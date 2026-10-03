"""Build concrete per-VM maps and physical handler functions before emission."""
from dataclasses import dataclass
import random
from .handler_layout import PhysicalFunction, lower_function, validate_layout, collect_fuseable_pairs_for_vm
from ..vm_obfuscation import ALL_SPLIT_OPS, DEFER_OPS, collect_used_orig_ops_for_vm, collect_used_ops_for_vm
from ..vm_variants import make_instr_layout


@dataclass
class RuntimeLayout:
    functions: PhysicalFunction
    vm_maps: list
    used_ops: list[set[int]]
    instruction_layout: dict
    constant_tags: dict
    constant_kinds: dict
    graph_sites: set[int]
    vm_count: int


def prepare_layout(backend_adapter, lowered_ir, context) -> RuntimeLayout:
    proto = lowered_ir.program
    protection_plan = lowered_ir.protection_plan
    protected_semantic_ir = lowered_ir.semantic_ir
    block_variant_rate = lowered_ir.policy["block_variant_rate"]
    # 2b. 멀티VM: proto를 N개 VM에 분산 + VM마다 독립 맵 생성
    #     (vop 공간은 공유 used_vops로 VM 간 disjoint 유지)
    protection_targets = backend_adapter.serialization_targets(lowered_ir)
    vm_assign = {key: target["vm_assignment"] for key, target in protection_targets.items()}
    n = protection_plan.functions[protected_semantic_ir.root.id]["vm_count"]

    used_vops: set[int] = set()
    vm_maps: list = []
    used_ops_list: list[set[int]] = []
    for k in range(n):
        vop_map, split_map, fuse_map, defer_map = backend_adapter.build_vm_map(
            proto, vm_assign, k, used_vops,
            protection_plan.functions[protected_semantic_ir.root.id]["alias_requirements"][k])
        vm_maps.append((vop_map, split_map, fuse_map, defer_map))
        used_ops = collect_used_ops_for_vm(proto, vm_assign, k, vop_map)
        if lowered_ir.policy.get("integrity_constants", False):
            for pseudo_op in range(47, 58):
                used_ops.update(vop_map[pseudo_op])
        if block_variant_rate > 0.0:
            for pseudo_op in (58, 59):
                used_ops.update(vop_map[pseudo_op])
        used_ops_list.append(used_ops)

    # instruction 워드 비트 레이아웃: serializer(packing)와 vm.lua(decode)가
    # 동일 레이아웃을 공유해야 하므로 serialize 전에 per-run 생성해 양쪽에 전달.
    instr_layout = make_instr_layout()
    constant_tag_names = ("nil", "bool", "int", "float", "str", "iexpr")
    constant_tag_values = random.sample(range(0x20, 0x100), 6)
    constant_tags = dict(zip(constant_tag_names, constant_tag_values))
    constant_kind_values = random.sample(range(0x1000, 0x100000), 6)
    constant_kinds = dict(zip(constant_tag_names, constant_kind_values))
    graph_sites: set[int] = set()
    def lower(proto):
        vm_id = vm_assign[id(proto)]
        function = lower_function(proto, vm_id, vm_maps[vm_id], protection_targets[id(proto)],
                                  graph_sites,
                                  integrity_enabled=bool(lowered_ir.policy.get("integrity_constants", False)),
                                  graph_execution_rate=lowered_ir.policy["graph_execution_rate"],
                                  cross_instruction_rate=lowered_ir.policy["cross_instruction_rate"],
                                  block_variant_rate=block_variant_rate,
                                  block_variant_count=int(lowered_ir.policy.get("block_variant_count", 3)),
                                  block_variant_max_instructions=int(lowered_ir.policy.get("block_variant_max_instructions", 6)))
        function.children = [lower(child) for child in proto.protos]
        return function
    functions = lower(proto)
    validate_layout(functions, vm_maps)
    return RuntimeLayout(functions, vm_maps, used_ops_list, instr_layout, constant_tags,
                         constant_kinds, graph_sites, n)


def iter_functions(function):
    yield function
    for child in function.children:
        yield from iter_functions(child)


from .handler_ir import OPERATIONS
_VOP_SPACE    = 128  # 7비트 op × 256 variant = 32768, 실용 범위는 128*256


def _make_vop_map(used_vops: set[int] | None, alias_requirements) -> dict[int, list[int]]:
    """Allocate disjoint backend opcode identifiers for planned alias counts.

    Semantic requirements own multiplicity. Randomness here only chooses the
    physical 15-bit encoding; instruction alias selection is already planned.
    """
    if used_vops is None:
        used_vops = set()
    vop_map: dict[int, list[int]] = {}

    counts = dict(alias_requirements["operations"])
    for orig, name in enumerate(OPERATIONS):
        n_aliases = counts.get(name, alias_requirements["auxiliary_count"])
        aliases = []
        for _ in range(n_aliases):
            while True:
                op_slot = random.randint(0, _VOP_SPACE - 1)
                variant = random.randint(0, 255)
                vop = op_slot | (variant << 7)
                if vop not in used_vops:
                    used_vops.add(vop)
                    aliases.append(vop)
                    break
        vop_map[orig] = aliases
    return vop_map


def _new_unique_vop(used: set[int]) -> int:
    while True:
        vop = random.randint(0, 0x7FFF)
        if vop not in used:
            used.add(vop)
            return vop


def _make_fuse_map(used_vops: set[int],
                   pairs: set[tuple[int, int]]) -> dict[tuple[int, int], int]:
    """fuse 가능한 각 (op1, op2) 쌍마다 고유 vop 1개 할당."""
    return {pair: _new_unique_vop(used_vops) for pair in sorted(pairs)}


def _make_split_map(used_vops: set[int],
                    split_ops: set[int]) -> dict[int, dict[str, tuple[int, ...]]]:
    """각 split 가능 op마다 2-part, 3-part 용 vop 튜플 할당.

    split_ops: split 핸들러를 만들 op 집합 (실제 바이트코드에 등장하는
    splittable op으로 한정 — 안 쓰는 op까지 CFF 핸들러를 만들면 체인 폭증).
    """
    split_map: dict[int, dict[str, tuple[int, ...]]] = {}
    for op in sorted(split_ops):
        split_map[op] = {
            "2": (_new_unique_vop(used_vops), _new_unique_vop(used_vops)),
            "3": (_new_unique_vop(used_vops), _new_unique_vop(used_vops),
                  _new_unique_vop(used_vops)),
        }
    return split_map


def _make_defer_map(used_vops: set[int],
                    defer_ops: set[int]) -> dict[int, int]:
    """Allocate one producer vop for each lazy cross-instruction operation."""
    return {op: _new_unique_vop(used_vops) for op in sorted(defer_ops)}



def build_handler_map(proto, vm_assign, vm_id, used_vops, alias_requirements, *, delayed):
    vop_map = _make_vop_map(used_vops, alias_requirements)
    used = collect_used_orig_ops_for_vm(proto, vm_assign, vm_id)
    split_map = _make_split_map(used_vops, ALL_SPLIT_OPS & used)
    fuse_map = _make_fuse_map(used_vops, collect_fuseable_pairs_for_vm(proto, vm_assign, vm_id))
    defer_map = _make_defer_map(used_vops, DEFER_OPS & used if delayed else set())
    return vop_map, split_map, fuse_map, defer_map
