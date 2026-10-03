"""Explicit physical handler layout, constructed before binary serialization."""
from __future__ import annotations
from dataclasses import dataclass, replace
from .handler_ir import HandlerFunction, HandlerInstruction
from ..vm_obfuscation import FUSE_OPS


@dataclass(frozen=True)
class PhysicalInstruction:
    instruction: HandlerInstruction
    vop: int
    avalanche: tuple[int, ...]
    graph_sites: tuple[tuple[int, int, int, int, int], ...]


@dataclass
class PhysicalFunction:
    source: HandlerFunction
    vm_id: int
    code: list[PhysicalInstruction]
    routes: list[list[int]]
    integrity_indices: set[int]
    stream_integrity: bool
    children: list[PhysicalFunction]


def lower_function(proto: HandlerFunction, vm_id: int, vm_map, targets: dict,
                   graph_sites: set[int], *, integrity_enabled=False,
                   graph_execution_rate=0.0, cross_instruction_rate=0.0,
                   block_variant_rate=0.0, block_variant_count=3,
                   block_variant_max_instructions=6) -> PhysicalFunction:
    vop_map, split_map, fuse_map, defer_map = vm_map
    emitted = []
    def emit(instruction, vop):
        emitted.append((instruction, vop))
    # --- split/fuse 결정 + jump offset 보정 ---
    iexpr_indices = set(targets["integrity_constants"]) if integrity_enabled else set()
    stream_enabled = bool(iexpr_indices) and proto.max_stack_size <= 253 and not targets["open_register_extent"]
    temp0 = proto.max_stack_size
    temp1 = proto.max_stack_size + 1
    protected     = _compute_protected(proto.code)
    block_layout, canonical, total, block_routes = _make_block_layout(
        proto.code, split_map, fuse_map, defer_map,
        cross_instruction_rate, protected, iexpr_indices, stream_enabled,
        block_variant_rate, block_variant_count,
        block_variant_max_instructions,
        targets["instruction_forms"] if targets is not None else None,
        targets["block_variants"] if targets is not None else None,
    )
    code          = proto.code
    add_slots = targets["avalanche_slots"] if graph_execution_rate > 0 else {}
    emitted_av: list[tuple[int, ...]] = []
    def planned_alias(op: int, index: int) -> int:
        if not vop_map:
            return op
        aliases = vop_map[op]
        return aliases[targets["alias_variants"].get(index, 0) % len(aliases)]

    # (family, site, selector_seed, state_key, diffusion_policy)
    emitted_sites: list[tuple[tuple[int, int, int, int, int], ...]] = []

    occurrence_cursor = {}
    def graph_descriptor(op: int, index: int) -> tuple[int, int, int, int, int] | None:
        if op not in _GRAPH_SITE_OPS:
            return None
        cursor = occurrence_cursor.get(index, 0)
        descriptors = targets["occurrence_descriptors"][index]
        if not descriptors:
            return None  # Linker-owned control slots are not planned graph sites.
        if cursor >= len(descriptors):
            raise ValueError("physical graph occurrences exceed concrete protection plan")
        site, selector_seed, state_key, policy = descriptors[cursor]
        occurrence_cursor[index] = cursor + 1
        if site in graph_sites:
            raise ValueError("duplicate planned graph occurrence")
        graph_sites.add(site)
        family = targets["graph_families"].get(index, 0) if graph_execution_rate > 0 else 0
        return family, site, selector_seed, state_key, policy

    # 명령어: u64 커스텀 포맷으로 emit (alias 중 랜덤 선택 + 롤링 acc 인코딩)
    def emit_unit(unit: tuple, physical: int) -> int:
        i = unit[1]
        raw = _adjust_jump_at(code[i], i, physical, canonical, total)
        orig_op = raw.op
        emit_raw = (
            _as_pseudo_loadiexpr(raw)
            if orig_op == 1 and _loadk_bx(raw) in iexpr_indices
            else raw
        )
        emit_op = emit_raw.op
        if unit[0] == "iexpr_stream":
            for pseudo_raw in _as_iexpr_stream(raw, temp0, temp1):
                pseudo_op = pseudo_raw.op
                emit(pseudo_raw, planned_alias(pseudo_op, i))
                emitted_av.append(())
                emitted_sites.append(())
                physical += 1
        elif unit[0] == "normal":
            emit(emit_raw, planned_alias(emit_op, i))
            emitted_av.append(add_slots.get(i, ()))
            desc = graph_descriptor(emit_op, i)
            emitted_sites.append((desc,) if desc is not None else ())
            physical += 1
        elif unit[0] == "split":
            # 같은 raw 명령어를 각 part vop으로 반복 방출
            vops = split_map[orig_op][str(unit[2])]  # type: ignore[index]
            for vop in vops:
                emit(emit_raw, vop)
                emitted_av.append(add_slots.get(i, ()))
                desc = graph_descriptor(orig_op, i)
                emitted_sites.append((desc,) if desc is not None else ())
                physical += 1
        elif unit[0] == "defer":
            emit(emit_raw, defer_map[orig_op])  # type: ignore[index]
            emitted_av.append(add_slots.get(i, ()))
            desc = graph_descriptor(orig_op, i)
            emitted_sites.append((desc,) if desc is not None else ())
            physical += 1
        else:  # fuse: fused vop 슬롯(instr1) + operand 슬롯(instr2)
            op2 = code[unit[2]].op
            fuse_vop = fuse_map[(orig_op, op2)]  # type: ignore[index]
            emit(raw, fuse_vop)
            emitted_av.append(add_slots.get(i, ()))
            descriptors = []
            desc = graph_descriptor(orig_op, i)
            if desc is not None:
                descriptors.append(desc)
            desc = graph_descriptor(op2, unit[2])
            if desc is not None:
                descriptors.append(desc)
            emitted_sites.append(tuple(descriptors))
            # operand 슬롯: dispatch 안 되지만 acc 동기화 위해 정상 슬롯으로 방출
            emit(code[unit[2]], planned_alias(op2, unit[2]))
            emitted_av.append(add_slots.get(unit[2], ()))
            emitted_sites.append(())
            physical += 2
        return physical

    physical = 0
    for chunk_index, entry in enumerate(block_layout):
        if entry["selected"]:
            route_raw = _make_abc(PSEUDO_BLOCK_ROUTE, entry["route_index"])
            emit(route_raw, planned_alias(PSEUDO_BLOCK_ROUTE, entry["start"]))
            emitted_av.append(())
            emitted_sites.append(())
            physical += 1
        for plan in entry["plans"]:
            for unit in plan:
                physical = emit_unit(unit, physical)
            if entry["selected"]:
                successor = (
                    block_layout[chunk_index + 1]["entry"]
                    if chunk_index + 1 < len(block_layout) else total
                )
                goto_raw = _make_abx(PSEUDO_BLOCK_GOTO, 0, successor)
                emit(goto_raw, planned_alias(PSEUDO_BLOCK_GOTO, entry["start"]))
                emitted_av.append(())
                emitted_sites.append(())
                physical += 1

    if physical != total:
        raise RuntimeError(
            f"block layout size mismatch: emitted={physical}, expected={total}"
        )

    return PhysicalFunction(proto, vm_id, [
        PhysicalInstruction(instruction, vop, avalanche, sites)
        for (instruction, vop), avalanche, sites in zip(emitted, emitted_av, emitted_sites)
    ], block_routes, iexpr_indices, stream_enabled, [])


def validate_layout(function: PhysicalFunction, vm_maps: list) -> None:
    if not 0 <= function.vm_id < len(vm_maps):
        raise ValueError(f"invalid physical VM assignment: {function.source.id}")
    aliases, splits, fuses, defers = vm_maps[function.vm_id]
    allowed = {vop for values in (aliases or {}).values() for vop in values}
    allowed.update(vop for forms in (splits or {}).values() for values in forms.values() for vop in values)
    allowed.update((fuses or {}).values())
    allowed.update((defers or {}).values())
    size = len(function.code)
    for index, item in enumerate(function.code):
        if aliases and item.vop not in allowed:
            raise ValueError(f"missing handler target: {function.source.id}:{index}")
        instruction = item.instruction
        if instruction.operation == "BLOCK_ROUTE":
            if not 0 <= instruction.a < len(function.routes):
                raise ValueError("invalid block route index")
        if instruction.operation == "BLOCK_GOTO":
            if not 0 <= instruction.bx <= size:
                raise ValueError("invalid block goto target")
        if instruction.operation in {"JUMP", "FOR_LOOP", "FOR_PREP", "ITER_LOOP"}:
            if not 0 <= index + 1 + instruction.sbx <= size:
                raise ValueError(f"invalid physical jump: {function.source.id}:{index}")
        if any(not 0 <= slot <= 254 for slot in item.avalanche):
            raise ValueError("invalid avalanche scratch slot")
        for family, site, seed, state_key, policy in item.graph_sites:
            if not (all(type(value) is int for value in (family, site, seed, state_key, policy))
                    and 0 <= family <= 8 and 0 < site <= 0xFFFFFFFF
                    and 0 < seed <= 0xFFFFFFFF and 0 < state_key <= 0xFFFF
                    and 0 <= policy <= 3):
                raise ValueError("invalid graph descriptor")
    for route in function.routes:
        if not 1 <= len(route) <= 255:
            raise ValueError("invalid block route length")
        if any(type(target) is not int or not 1 <= target <= size for target in route):
            raise ValueError("invalid block route target")
    for child in function.children:
        validate_layout(child, vm_maps)


PSEUDO_LOADIEXPR = 47


PSEUDO_GET_SCRIPT_HASH = 48


PSEUDO_GET_VMCOUNT = 49


PSEUDO_GET_LAYOUT = 50


PSEUDO_GET_SEED = 51


PSEUDO_GET_VMID = 52


PSEUDO_GET_CODELEN = 53


PSEUDO_IXOR = 54


PSEUDO_IADD = 55


PSEUDO_IMUL = 56


PSEUDO_LOAD_IENC = 57


PSEUDO_BLOCK_ROUTE = 58


PSEUDO_BLOCK_GOTO = 59


_SBXOPS: set[int] = {30, 39, 40, 42}


_TESTOPS: set[int] = {31, 32, 33, 34, 35}


def _successors(code: list[HandlerInstruction], index: int) -> set[int]:
    raw = code[index]
    op = raw.op
    n = len(code)
    nxt = index + 1
    if op in {37, 38}:
        return set()
    if op in _SBXOPS:
        sbx = raw.bx - 131071
        target = nxt + sbx
        if op in {30, 40}:
            return {target} if 0 <= target < n else set()
        result = {target} if 0 <= target < n else set()
        if op in {39, 42} and nxt < n:
            result.add(nxt)
        return result
    if op in _TESTOPS:
        return {i for i in (nxt, index + 2) if i < n}
    if op == 3 and raw.c != 0:
        return {index + 2} if index + 2 < n else set()
    return {nxt} if nxt < n else set()


def _compute_protected(code: list[HandlerInstruction]) -> set[int]:
    """독립적으로 dispatch 진입해야 하는(=fuse의 operand 슬롯이 되면 안 되는)
    명령어 인덱스 집합.

    - JMP/FORLOOP/FORPREP/TFORLOOP의 점프 목적지
    - test 명령(skip)의 착지 위치 i+2
    - LOADBOOL(op==3, C!=0)의 skip 착지 위치 i+2
    """
    n = len(code)
    protected: set[int] = set()
    for i, raw in enumerate(code):
        op = raw.op
        if op in _SBXOPS:
            sbx = raw.bx - 131071
            tgt = i + 1 + sbx
            if 0 <= tgt < n:
                protected.add(tgt)
        elif op in _TESTOPS:
            if i + 2 < n:
                protected.add(i + 2)
        elif op == 3:  # LOADBOOL
            C = raw.c
            if C != 0 and i + 2 < n:
                protected.add(i + 2)
    return protected


def collect_fuseable_pairs(proto: HandlerFunction) -> set[tuple[int, int]]:
    """proto 트리에서 fuse 가능한 인접 (op1, op2) 쌍 집합을 반환."""
    pairs: set[tuple[int, int]] = set()
    _collect_pairs(proto, pairs)
    return pairs


def collect_fuseable_pairs_for_vm(proto: HandlerFunction, vm_assign: dict[int, int],
                                  vm_id: int) -> set[tuple[int, int]]:
    """vm_id로 배정된 proto들만의 fuse 가능 쌍."""
    pairs: set[tuple[int, int]] = set()
    for p in iter_protos(proto):
        if vm_assign.get(id(p), 0) == vm_id:
            _collect_pairs_single(p, pairs)
    return pairs


def _collect_pairs_single(proto: HandlerFunction, pairs: set[tuple[int, int]]) -> None:
    """단일 proto의 fuse 가능 쌍만 수집(재귀 안 함)."""
    code = proto.code
    protected = _compute_protected(code)
    for i in range(len(code) - 1):
        op1 = code[i].op
        op2 = code[i + 1].op
        if op1 in FUSE_OPS and op2 in FUSE_OPS and (i + 1) not in protected:
            pairs.add((op1, op2))


def _collect_pairs(proto: HandlerFunction, pairs: set[tuple[int, int]]) -> None:
    _collect_pairs_single(proto, pairs)
    for sub in proto.protos:
        _collect_pairs(sub, pairs)


def _lower_units(code: list[HandlerInstruction],
                split_map: dict[int, dict[str, tuple[int, ...]]] | None,
                fuse_map: dict[tuple[int, int], int] | None,
                defer_map: dict[int, int] | None,
                cross_instruction_rate: float,
                protected: set[int],
                start: int = 0,
                end: int | None = None,
                instruction_forms: dict | None = None,
                variant: int = 0) -> list[tuple]:
    n = len(code) if end is None else end
    plan: list[tuple] = []
    i = start
    while i < n:
        op = code[i].op
        if instruction_forms is not None:
            forms = instruction_forms.get(i, (("normal", 1),))
            kind, argument = forms[min(variant, len(forms) - 1)]
            choice = ("normal", i)
            if kind == "split" and split_map and op in split_map:
                choice = ("split", i, argument)
            elif (kind == "fuse" and fuse_map and i + 1 < n and i + 1 not in protected
                  and code[i + 1].source_id == argument
                  and (op, code[i + 1].op) in fuse_map):
                choice = ("fuse", i, i + 1)
            elif kind == "defer" and defer_map and op in defer_map:
                choice = ("defer", i)
            plan.append(choice)
            i += 2 if choice[0] == "fuse" else 1
            continue
        raise ValueError("handler layout requires planned instruction forms")
    return plan


def _cfg_blocks(code: list[HandlerInstruction]) -> list[tuple[int, int]]:
    """Return half-open basic-block ranges in original instruction space."""
    if not code:
        return []
    leaders = {0}
    for i in range(len(code)):
        succ = _successors(code, i)
        if succ != ({i + 1} if i + 1 < len(code) else set()):
            leaders.update(succ)
            if i + 1 < len(code):
                leaders.add(i + 1)
    ordered = sorted(i for i in leaders if 0 <= i < len(code))
    return [
        (start, ordered[index + 1] if index + 1 < len(ordered) else len(code))
        for index, start in enumerate(ordered)
    ]


def _block_chunks(code: list[HandlerInstruction], max_instructions: int) -> list[tuple[int, int, bool]]:
    """Split CFG blocks into small straight-line candidate runs.

    The bool marks chunks that may be cloned. LOADKX/EXTRAARG remains adjacent,
    while control-transfer and skip instructions are emitted only once.
    """
    chunks: list[tuple[int, int, bool]] = []
    limit = max(2, max_instructions)
    for block_start, block_end in _cfg_blocks(code):
        i = block_start
        while i < block_end:
            op = code[i].op
            if op == 2 and i + 1 < block_end:
                chunks.append((i, i + 2, False))
                i += 2
                continue
            if op not in _BLOCK_VARIANT_SAFE_OPS:
                chunks.append((i, i + 1, False))
                i += 1
                continue
            run_end = i + 1
            while (run_end < block_end
                   and (code[run_end].op) in _BLOCK_VARIANT_SAFE_OPS):
                run_end += 1
            while i < run_end:
                remaining = run_end - i
                size = min(limit, remaining)
                if remaining - size == 1 and size > 2:
                    size -= 1
                chunks.append((i, i + size, size >= 2))
                i += size
    return chunks


def _adjust_jump_at(raw: HandlerInstruction, original_index: int, physical_index: int,
                    canonical: list[int], total: int) -> int:
    if (raw.op) not in _SBXOPS:
        return raw
    old_sbx = raw.bx - 131071
    target = original_index + 1 + old_sbx
    new_target = canonical[target] if 0 <= target < len(canonical) else total
    new_sbx = new_target - physical_index - 1
    new_bx = new_sbx + 131071
    return raw.with_bx(new_bx)


def _plan_slots(unit: tuple) -> int:
    if unit[0] == "iexpr_stream":
        return _STREAM_IEXPR_SLOTS
    if unit[0] == "split":
        return unit[2]
    if unit[0] == "fuse":
        return 2
    return 1


_GRAPH_SITE_OPS = {
    # Integer arithmetic occurrence families.
    13, 14, 15, 20, 21, 22, 23, 24, 25, 26,
    # Control packets whose operands are rebound to live VM state at runtime.
    30, 39, 40, 41, 42, 45,
}


def iter_protos(proto: HandlerFunction):
    """proto 트리를 pre-order로 순회(직렬화 순서와 동일)."""
    yield proto
    for sub in proto.protos:
        yield from iter_protos(sub)


def _loadk_bx(raw: HandlerInstruction) -> int:
    return raw.bx


def _load_a(raw: HandlerInstruction) -> int:
    return raw.a


def _make_abc(op: int, a: int, b: int = 0, c: int = 0) -> HandlerInstruction:
    return HandlerInstruction(op, a, b, c)


def _make_abx(op: int, a: int, bx: int) -> HandlerInstruction:
    return HandlerInstruction(op, a).with_bx(bx)


def _as_pseudo_loadiexpr(raw: HandlerInstruction) -> HandlerInstruction:
    return replace(raw, op=PSEUDO_LOADIEXPR)


def _as_iexpr_stream(raw: HandlerInstruction, temp0: int, temp1: int) -> list[HandlerInstruction]:
    a = _load_a(raw)
    bx = _loadk_bx(raw)
    return [
        _make_abc(PSEUDO_GET_SCRIPT_HASH, temp0),
        _make_abc(PSEUDO_GET_VMCOUNT, temp1),
        _make_abc(PSEUDO_IXOR, temp0, temp0, temp1),
        _make_abc(PSEUDO_GET_LAYOUT, temp1),
        _make_abc(PSEUDO_IADD, temp0, temp0, temp1),
        _make_abc(PSEUDO_GET_SEED, temp1),
        _make_abc(PSEUDO_IXOR, temp0, temp0, temp1),
        _make_abc(PSEUDO_GET_VMID, temp1),
        _make_abc(PSEUDO_IADD, temp0, temp0, temp1),
        _make_abc(PSEUDO_GET_CODELEN, temp1),
        _make_abc(PSEUDO_IMUL, temp0, temp0, temp1),
        _make_abx(PSEUDO_LOAD_IENC, temp1, bx),
        _make_abc(PSEUDO_IXOR, a, temp1, temp0),
    ]


def _mark_integrity_stream_units(plan: list[tuple], code: list[HandlerInstruction],
                                 iexpr_indices: set[int],
                                 stream_enabled: bool) -> list[tuple]:
    if not stream_enabled or not iexpr_indices:
        return plan

    def is_selected_loadk(index: int) -> bool:
        raw = code[index]
        return (raw.op) == 1 and _loadk_bx(raw) in iexpr_indices

    marked: list[tuple] = []
    for unit in plan:
        kind = unit[0]
        if kind == "normal" and is_selected_loadk(unit[1]):
            marked.append(("iexpr_stream", unit[1]))
            continue
        if kind == "split" and is_selected_loadk(unit[1]):
            marked.append(("iexpr_stream", unit[1]))
            continue
        if kind == "fuse" and (is_selected_loadk(unit[1]) or is_selected_loadk(unit[2])):
            for index in (unit[1], unit[2]):
                marked.append(("iexpr_stream", index) if is_selected_loadk(index) else ("normal", index))
            continue
        marked.append(unit)
    return marked


def _make_block_layout(
    code: list[HandlerInstruction],
    split_map: dict[int, dict[str, tuple[int, ...]]] | None,
    fuse_map: dict[tuple[int, int], int] | None,
    defer_map: dict[int, int] | None,
    cross_instruction_rate: float,
    protected: set[int],
    iexpr_indices: set[int],
    stream_enabled: bool,
    block_variant_rate: float,
    block_variant_count: int,
    block_variant_max_instructions: int,
    instruction_forms: dict | None = None,
    block_variants: dict | None = None,
) -> tuple[list[dict], list[int], int, list[list[int]]]:
    chunks = _block_chunks(code, block_variant_max_instructions)
    block_layout: list[dict] = []
    route_count = 0
    for start, end, eligible in chunks:
        selected = (
            eligible
            and route_count < 256
            and bool((block_variants or {}).get(start, False)) and block_variant_rate > 0
        )
        variant_total = block_variant_count if selected else 1
        plans = []
        for variant in range(variant_total):
            plan = _lower_units(
                code, split_map, fuse_map, defer_map,
                cross_instruction_rate, protected, start, end, instruction_forms, variant,
            )
            plans.append(_mark_integrity_stream_units(
                plan, code, iexpr_indices, stream_enabled
            ))
        block_layout.append({
            "start": start,
            "end": end,
            "selected": selected,
            "route_index": route_count if selected else None,
            "plans": plans,
        })
        if selected:
            route_count += 1

    canonical = [0] * len(code)
    position = 0
    for entry in block_layout:
        entry["entry"] = position
        if entry["selected"]:
            position += 1
        variant_starts = []
        for variant_index, plan in enumerate(entry["plans"]):
            variant_starts.append(position)
            cursor = position
            for unit in plan:
                if variant_index == 0:
                    canonical[unit[1]] = cursor
                    if unit[0] == "fuse":
                        canonical[unit[2]] = cursor + 1
                cursor += _plan_slots(unit)
            position = cursor
            if entry["selected"]:
                position += 1
        entry["variant_starts"] = variant_starts
        if entry["selected"]:
            canonical[entry["start"]] = entry["entry"]

    if position > 0x3FFFF and any(entry["selected"] for entry in block_layout):
        return _make_block_layout(
            code, split_map, fuse_map, defer_map,
            cross_instruction_rate, protected, iexpr_indices, stream_enabled,
            0.0, block_variant_count, block_variant_max_instructions, instruction_forms, block_variants,
        )

    routes: list[list[int]] = [[] for _ in range(route_count)]
    for entry in block_layout:
        if entry["selected"]:
            routes[entry["route_index"]] = [
                pos + 1 for pos in entry["variant_starts"]
            ]
    return block_layout, canonical, position, routes

_STREAM_IEXPR_SLOTS = 13
_BLOCK_VARIANT_SAFE_OPS = set(range(0, 30)) - {2, 3}
