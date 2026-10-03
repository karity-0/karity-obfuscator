"""Backend-neutral protection planning and capability resolution."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import random
from typing import Any

from .semantic_ir import SemanticIR


class RequirementLevel(str, Enum):
    OPTIONAL = "optional"
    REQUIRED = "required"


@dataclass(frozen=True)
class ProtectionRequest:
    feature: str
    level: RequirementLevel = RequirementLevel.OPTIONAL
    parameters: dict[str, Any] = field(default_factory=dict)
    source_options: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProtectionPlan:
    values: dict[str, dict[str, Any]]
    instructions: dict[str, dict[str, Any]]
    blocks: dict[str, dict[str, Any]]
    functions: dict[str, dict[str, Any]]
    requests: tuple[ProtectionRequest, ...]
    generation: str = ""

    def dump(self) -> str:
        lines = ["protection-plan v1", f"generation={self.generation or 'unspecified'}"]
        for request in self.requests:
            params = ",".join(
                f"{key}={request.parameters[key]!r}" for key in sorted(request.parameters)
            ) or "-"
            options = ",".join(request.source_options) or "-"
            lines.append(
                f"request {request.feature} level={request.level.value} "
                f"options={options} params={params}"
            )
        for label, collection in (
            ("function", self.functions), ("block", self.blocks),
            ("instruction", self.instructions), ("value", self.values),
        ):
            for item_id in sorted(collection):
                values = ",".join(
                    f"{key}={collection[item_id][key]!r}"
                    for key in sorted(collection[item_id])
                )
                lines.append(f"{label} {item_id} {values}")
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ProtectedIR:
    semantic_ir: SemanticIR
    plan: ProtectionPlan


def protect(ir: SemanticIR, plan: ProtectionPlan) -> ProtectedIR:
    """Bind a validated plan to immutable semantic IR."""
    if plan.generation and plan.generation != ir.generation:
        raise ValueError("protection plan belongs to a different IR generation")
    function_ids: set[str] = set()
    block_ids: set[str] = set()
    instruction_ids: set[str] = set()
    value_ids: set[str] = set()
    for function in ir.functions():
        function_ids.add(function.id)
        value_ids.update(value.id for value in function.values)
        for block in function.blocks:
            block_ids.add(block.id)
            instruction_ids.update(item.id for item in block.instructions)
    for label, planned, valid in (
        ("function", plan.functions, function_ids),
        ("block", plan.blocks, block_ids),
        ("instruction", plan.instructions, instruction_ids),
        ("value", plan.values, value_ids),
    ):
        unknown = sorted(set(planned) - valid)
        if unknown:
            raise ValueError(
                f"protection plan references unknown {label}: {', '.join(unknown)}"
            )
    from .ir.operations import OPERATIONS as semantic_operations
    for function_id, state in plan.functions.items():
        requirements = state.get('alias_requirements')
        if requirements is None:
            continue
        if function_id != ir.root.id or len(requirements) != state.get('vm_count'):
            raise ValueError('invalid alias requirement VM placement')
        for requirement in requirements:
            entries = requirement['operations']
            if (len(entries) != len(semantic_operations)
                    or {name for name, _ in entries} != set(semantic_operations)
                    or any(type(count) is not int or count not in (2, 3) for _, count in entries)
                    or type(requirement['auxiliary_count']) is not int
                    or requirement['auxiliary_count'] not in (2, 3)):
                raise ValueError('invalid semantic alias multiplicity')
        runtime_variants = state.get("runtime_variants")
        if runtime_variants is not None:
            if function_id != ir.root.id or len(runtime_variants) != state.get("vm_count"):
                raise ValueError("invalid runtime variant VM placement")
            for variant, aliases in zip(runtime_variants, requirements):
                counts = dict(aliases["operations"])
                modes = dict(variant.get("semantic_alias_modes", ()))
                routes = dict(variant.get("helper_route_cycles", ()))
                if (variant.get("dispatcher") not in {
                        "ifelseif", "tailcall", "bsearch", "split4", "split6",
                        "bsplit4", "bsplit6", "table"
                    } or set(modes) != set(counts)
                    or any(len(modes[name]) != counts[name]
                           or any(type(value) is not bool for value in modes[name])
                           for name in counts)
                    or not all(type(value) is int and 0 <= value < 8
                               for value in variant.get("decoy_body_variants", ()))
                    or not 1 <= variant.get("helper_variant_count", 0) <= 4
                    or variant.get("helper_fetch_variant") not in (0, 1, 2)
                    or set(routes) != set(_HELPER_NAMES)
                    or any(not cycle or any(
                        type(value) is not int
                        or not 0 <= value < variant["helper_variant_count"]
                        for value in cycle
                    ) for cycle in routes.values())):
                    raise ValueError("invalid planned runtime variant")
    blob_form = plan.functions.get(ir.root.id, {}).get("blob_form")
    if blob_form is not None and blob_form not in {"string", "table", "numeric"}:
        raise ValueError("invalid planned blob representation")
    representation_routes = plan.functions.get(ir.root.id, {}).get(
        "representation_routes"
    )
    if representation_routes is not None:
        routes = dict(representation_routes)
        expected = {
            "arithmetic": set(_ARITHMETIC_ROUTE_KINDS),
            "semantic": set(_SEMANTIC_ROUTE_KINDS),
        }
        if (set(routes) != set(expected)
                or any(set(dict(routes[group])) != names
                       for group, names in expected.items())
                or any(type(route) is not bool
                       for entries in routes.values() for _, route in entries)):
            raise ValueError("invalid planned representation routes")
    occurrence_ids = set()
    for instruction_id, state in plan.instructions.items():
        for kind, argument in state.get("instruction_forms", ()):
            if kind not in {"normal", "split", "fuse", "defer", "operand"}:
                raise ValueError(f"invalid planned instruction form: {instruction_id}")
            if kind == "split" and argument not in (2, 3):
                raise ValueError(f"invalid split arity: {instruction_id}")
            if kind in {"fuse", "operand"} and argument not in instruction_ids:
                raise ValueError(f"invalid instruction relation: {instruction_id}")
        for descriptor in state.get("occurrence_descriptors", ()):
            if len(descriptor) != 4:
                raise ValueError("invalid planned occurrence descriptor")
            site, seed, state_key, policy = descriptor
            if (site in occurrence_ids or not 0x10000 <= site <= 0x7FFFFFFF
                    or not 0x10000 <= seed <= 0xFFFFFFFF or not 4000 <= state_key <= 0xFFFF
                    or not 0 <= policy <= 3):
                raise ValueError("invalid or duplicate planned occurrence descriptor")
            occurrence_ids.add(site)
        if not 0 <= state.get("avalanche_arity", 0) <= 3:
            raise ValueError(f"invalid avalanche arity: {instruction_id}")
    return ProtectedIR(ir, plan)


@dataclass(frozen=True)
class BackendCapabilities:
    name: str
    features: frozenset[str]
    supported_options: frozenset[str]
    fallbacks: tuple[tuple[str, str], ...] = ()

    def supports(self, feature: str) -> bool:
        return feature in self.features


@dataclass(frozen=True)
class CapabilityResolution:
    backend: str
    active: tuple[ProtectionRequest, ...]
    disabled: tuple[ProtectionRequest, ...]
    fallbacks: tuple[tuple[ProtectionRequest, str], ...] = ()

    def is_active(self, feature: str) -> bool:
        return any(request.feature == feature for request in self.active)

    def dump(self) -> str:
        lines = [f"capability-resolution backend={self.backend}"]
        lines.extend(f"native {request.feature}" for request in self.active
                     if not any(target == request.feature for _, target in self.fallbacks))
        lines.extend(f"fallback {request.feature} -> {target}" for request, target in self.fallbacks)
        lines.extend(f"disabled {request.feature}" for request in self.disabled)
        return "\n".join(lines) + "\n"


class UnsupportedProtectionError(ValueError):
    pass


_OPTION_FEATURES = {
    "dispatcher_type": "dispatcher_cff",
    "dispatcher_target_hiding": "dispatcher_target_hiding",
    "semantic_state_threading": "state_transition",
    "argument_virtualization": "argument_representation",
    "upvalue_virtualization": "upvalue_representation",
    "table_virtualization": "table_representation",
    "branch_virtualization": "branch_representation",
    "blob_form": "blob_representation",
    "vm_count": "multi_vm",
    "fake_handlers": "decoy_handlers",
    "mutate_handlers": "handler_mutation",
    "junk_instructions": "junk_instructions",
    "junk_rate": "junk_instructions",
    "integrity_constants": "integrity_constants",
    "integrity_constant_rate": "integrity_constants",
    "graph_execution_rate": "graph_execution",
    "cross_instruction_rate": "delayed_materialization",
    "runtime_polymorphism_rate": "runtime_polymorphism",
    "runtime_trace": "runtime_trace",
    "block_variant_rate": "block_variants",
    "block_variant_count": "block_variants",
    "block_variant_max_instructions": "block_variants",
    "helper_variant_count": "helper_variants",
    "helper_diversity_rate": "helper_variants",
    "semantic_diversity_rate": "semantic_variants",
}

_PARAMETER_OPTIONS = frozenset((
    "junk_rate", "integrity_constant_rate", "block_variant_count",
    "block_variant_max_instructions", "helper_variant_count",
))

_DISPATCH_KINDS = ("split4", "split6", "bsplit4", "bsplit6", "tailcall", "table")
_HELPER_NAMES = ("rget", "rset", "_flow", "_sem")
_ARITHMETIC_ROUTE_KINDS = (
    "ADD", "SUB", "MUL", "BIT_AND", "BIT_OR", "BIT_XOR",
    "SHIFT_LEFT", "SHIFT_RIGHT", "NEGATE", "BIT_NOT",
)
_SEMANTIC_ROUTE_KINDS = (
    "VALUE", "TABLE_GET", "TABLE_SET", "EQUAL", "LESS_THAN", "LESS_EQUAL",
    "TRUTH", "MOD", "POW", "DIV", "FLOOR_DIV", "LOGICAL_NOT", "LENGTH",
    "CONCAT", "NEW_TABLE", "SET_LIST", "CLOSURE", "VARARG",
)


def _enabled(name: str, value: Any) -> bool:
    if name == "dispatcher_type":
        return value is not None
    if name == "blob_form":
        return value is not None
    if name == "vm_count":
        return int(value or 1) > 1
    if name.endswith("_rate"):
        return float(value or 0.0) > 0.0
    if name in {"block_variant_count", "block_variant_max_instructions", "helper_variant_count"}:
        return False
    return bool(value)


def protection_requests(options: dict[str, Any]) -> tuple[ProtectionRequest, ...]:
    """Resolve user intent without requiring a compiled program."""
    levels = options.get("requirements", {})
    if not isinstance(levels, dict):
        raise ValueError("vm_options.requirements must be an object")
    for feature, level in levels.items():
        if feature not in protection_features():
            raise ValueError(f"unknown protection requirement: {feature}")
        if level not in ("optional", "required"):
            raise ValueError(f"requirement {feature} must be optional or required")
    grouped: dict[str, dict[str, Any]] = {"handler_aliases": {}}
    sources: dict[str, list[str]] = {"handler_aliases": []}
    for option, feature in _OPTION_FEATURES.items():
        if option in _PARAMETER_OPTIONS:
            continue
        if option not in options or not _enabled(option, options[option]):
            continue
        grouped.setdefault(feature, {})[option] = options[option]
        sources.setdefault(feature, []).append(option)
    for option in _PARAMETER_OPTIONS:
        feature = _OPTION_FEATURES[option]
        if feature in grouped and option in options:
            grouped[feature][option] = options[option]
            sources[feature].append(option)
    for feature, level in levels.items():
        if level == "required" and feature not in grouped:
            raise ValueError(f"required protection '{feature}' must be enabled in vm_options")
    return tuple(
        ProtectionRequest(feature, RequirementLevel(levels.get(feature, "optional")),
                          grouped[feature], tuple(sorted(sources[feature])))
        for feature in sorted(grouped)
    )


def protection_features() -> tuple[str, ...]:
    return tuple(sorted(set(_OPTION_FEATURES.values()) | {"handler_aliases"}))


class ProtectionPlanner:
    """Translate user controls into desired semantic protection state."""

    def __init__(self, options: dict[str, Any]):
        self.options = dict(options)
        self._random_state = random.getstate()

    def build(self, ir: SemanticIR) -> ProtectionPlan:
        requests = protection_requests(self.options)
        grouped = {request.feature: request.parameters for request in requests}

        values: dict[str, dict[str, Any]] = {}
        instructions: dict[str, dict[str, Any]] = {}
        blocks: dict[str, dict[str, Any]] = {}
        functions: dict[str, dict[str, Any]] = {}
        for function in ir.functions():
            function_state: dict[str, Any] = {}
            for request in requests:
                if request.feature in {
                    "dispatcher_cff", "dispatcher_target_hiding", "multi_vm",
                    "state_transition", "runtime_polymorphism", "helper_variants",
                }:
                    function_state[request.feature] = dict(request.parameters)
            if function_state:
                functions[function.id] = function_state
            for value in function.values:
                state: dict[str, Any] = {}
                if value.kind == "constant" and "integrity_constants" in grouped:
                    state["integrity_encoding_candidate"] = grouped["integrity_constants"]
                if value.kind == "register" and "state_transition" in grouped:
                    state["state_threaded"] = True
                if state:
                    values[value.id] = state
            for block in function.blocks:
                if "block_variants" in grouped:
                    blocks[block.id] = {"variant_candidate": grouped["block_variants"]}
                for instruction in block.instructions:
                    state = {}
                    if "delayed_materialization" in grouped and instruction.operation in {
                        "ADD", "SUB", "NEGATE",
                    }:
                        state["delayed_materialization_candidate"] = grouped[
                            "delayed_materialization"
                        ]
                    if "graph_execution" in grouped:
                        state["graph_candidate"] = grouped["graph_execution"]
                    if "handler_mutation" in grouped:
                        state["mutation_candidate"] = True
                    if "semantic_variants" in grouped:
                        state["semantic_variant_candidate"] = grouped["semantic_variants"]
                    if state:
                        instructions[instruction.id] = state
        self._select_targets(ir, values, instructions, functions)
        junk_rng = random.Random()
        junk_rng.setstate(self._random_state)
        junk_enabled = bool(self.options.get("junk_instructions", False))
        junk_rate = float(self.options.get("junk_rate", 0.15))
        for function in ir.functions():
            for block in function.blocks:
                for instruction in block.instructions:
                    if "junk_before_applied" in instruction.metadata:
                        registers = instruction.metadata["junk_before_applied"]
                    elif instruction.metadata.get("protection_origin") == "junk":
                        registers = ()
                    elif junk_enabled and function.max_stack_size and junk_rng.random() < junk_rate:
                        registers = (junk_rng.randrange(function.max_stack_size),)
                    else:
                        registers = ()
                    instructions[instruction.id]["junk_before"] = tuple(registers)

        return ProtectionPlan(values, instructions, blocks, functions, requests, ir.generation)

    def _select_targets(self, ir, values, instructions, functions):
        """Resolve semantic targets once, independently of emission randomness."""
        rng = random.Random()
        rng.setstate(self._random_state)
        ordered = tuple(ir.functions())
        count = max(1, min(int(self.options.get("vm_count", 1)), len(ordered)))
        placements = list(range(count)) + [rng.randrange(count) for _ in range(len(ordered) - count)]
        rng.shuffle(placements)
        integrity_rate = float(self.options.get("integrity_constant_rate", 0.25))
        graph_rate = float(self.options.get("graph_execution_rate", 0.0))
        graph_operations = {
            "ADD", "SUB", "MUL", "BIT_AND", "BIT_OR", "BIT_XOR",
            "SHIFT_LEFT", "SHIFT_RIGHT", "NEGATE", "BIT_NOT", "JUMP",
            "FOR_LOOP", "FOR_PREP", "ITER_CALL", "ITER_LOOP", "VARARG",
        }
        split_operations = {
            "MOVE", "LOAD_CONST", "ADD", "SUB", "MUL", "MOD", "POW", "DIV",
            "FLOOR_DIV", "BIT_AND", "BIT_OR", "BIT_XOR", "SHIFT_LEFT", "SHIFT_RIGHT",
            "NEGATE", "BIT_NOT", "LOGICAL_NOT", "LENGTH",
        }
        fuse_operations = split_operations | {"GET_UPVALUE"}
        for function, placement in zip(ordered, placements):
            open_register_extent = any(
                operand.kind == "register_range" and operand.count is None
                for block in function.blocks for instruction in block.instructions
                for operand in instruction.operands
            )
            functions.setdefault(function.id, {}).update(
                vm_assignment=placement, vm_count=count,
                open_register_extent=open_register_extent,
            )
            for value in function.values:
                literal = value.literal
                if (value.kind == "constant" and self.options.get("integrity_constants", False)
                        and isinstance(literal, int) and not isinstance(literal, bool)
                        and -(2**52) <= literal < 2**52):
                    values.setdefault(value.id, {})["integrity_encoded"] = rng.random() < integrity_rate
            for block in function.blocks:
                for offset, instruction in enumerate(block.instructions):
                    state = instructions.setdefault(instruction.id, {})
                    forms = []
                    for variant in range(int(self.options.get("block_variant_count", 3))):
                        if offset:
                            previous = instructions[block.instructions[offset - 1].id]["instruction_forms"][variant]
                            if previous == ("fuse", instruction.id):
                                forms.append(("operand", block.instructions[offset - 1].id))
                                continue
                        choices = [("normal", 1)]
                        if instruction.operation in split_operations:
                            choices.extend((("split", 2), ("split", 3)))
                        if (instruction.operation in fuse_operations and offset + 1 < len(block.instructions)
                                and block.instructions[offset + 1].operation in fuse_operations):
                            choices.append(("fuse", block.instructions[offset + 1].id))
                        if (instruction.operation in {"ADD", "SUB", "NEGATE"}
                                and rng.random() < float(self.options.get("cross_instruction_rate", 0.0))):
                            forms.append(("defer", 1))
                        else:
                            forms.append(rng.choice(choices))
                    state["instruction_forms"] = tuple(forms)
                    state["alias_variant"] = rng.getrandbits(32)
                    state["block_variant_selected"] = rng.random() < float(self.options.get("block_variant_rate", 0.0))
                    arithmetic = instruction.operation in split_operations - {"MOVE", "LOAD_CONST", "LOGICAL_NOT", "LENGTH"}
                    avalanche_rate = 1.0 if arithmetic else 0.25
                    state["avalanche_arity"] = (
                        rng.randint(1, 3) if instruction.operation not in {"RETURN", "TAIL_CALL"}
                        and not open_register_extent
                        and rng.random() < graph_rate * avalanche_rate else 0
                    )
                    if instruction.operation in graph_operations:
                        selected = rng.random() < graph_rate
                        instructions.setdefault(instruction.id, {})["graph_family"] = rng.randint(1, 8) if selected else 0

        # Alias multiplicity is a protection decision. Backends only allocate
        # their own opcode identifiers for these semantic requirements.
        from .ir.operations import OPERATIONS as semantic_operations
        functions[ir.root.id]['alias_requirements'] = tuple(
            {'operations': tuple((name, rng.randint(2, 3))
                                 for name in sorted(semantic_operations)),
             'auxiliary_count': rng.randint(2, 3)}
            for _ in range(count)
        )

        # Runtime protection topology is part of the requested protection,
        # rather than an emitter-side coin toss. Names and opcode numbers are
        # deliberately absent: backends still own physical encodings.
        root_state = functions[ir.root.id]
        alias_requirements = root_state["alias_requirements"]
        semantic_rate = max(0.0, min(
            1.0, float(self.options.get("semantic_diversity_rate", 0.35))
        ))
        helper_count = max(1, min(
            4, int(self.options.get("helper_variant_count", 3))
        ))
        helper_rate = max(0.0, min(
            1.0, float(self.options.get("helper_diversity_rate", 0.35))
        ))
        dispatcher = self.options.get("dispatcher_type") or "ifelseif"
        blob_form = self.options.get("blob_form") or "string"
        root_state["blob_form"] = (
            rng.choice(("string", "table", "numeric"))
            if blob_form == "random" else blob_form
        )
        root_state["representation_routes"] = (
            ("arithmetic", tuple(
                (name, bool(rng.getrandbits(1)))
                for name in _ARITHMETIC_ROUTE_KINDS
            )),
            ("semantic", tuple(
                (name, bool(rng.getrandbits(1)))
                for name in _SEMANTIC_ROUTE_KINDS
            )),
        )

        used_operations = [set() for _ in range(count)]
        forced_indirect_aliases: list[dict[str, set[int]]] = [
            {} for _ in range(count)
        ]
        for function, placement in zip(ordered, placements):
            used_operations[placement].update(
                instruction.operation
                for block in function.blocks for instruction in block.instructions
            )
            alias_counts = dict(alias_requirements[placement]["operations"])
            for block in function.blocks:
                for instruction in block.instructions:
                    # The direct SET_LIST specialization cannot consume the
                    # following extension word. Keep the alias selected by an
                    # extended batch on the complete semantic implementation.
                    if instruction.operation == "SET_LIST" and any(
                        operand.role == "batch" and operand.value > 511
                        for operand in instruction.operands
                    ):
                        alias = (instructions[instruction.id]["alias_variant"]
                                 % alias_counts["SET_LIST"])
                        forced_indirect_aliases[placement].setdefault(
                            "SET_LIST", set()
                        ).add(alias)

        runtime_variants = []
        for vm_id in range(count):
            counts = dict(alias_requirements[vm_id]["operations"])
            semantic_alias_modes = []
            for name in sorted(semantic_operations):
                aliases = counts[name]
                semantic_alias_modes.append((
                    name,
                    tuple(False if index == 0 or index in forced_indirect_aliases[
                              vm_id
                          ].get(name, ()) else rng.random() < semantic_rate
                          for index in range(aliases)),
                ))

            real_handler_count = sum(
                counts[name] for name in used_operations[vm_id] if name in counts
            )
            if self.options.get("fake_handlers", False) and real_handler_count:
                decoy_count = rng.randint(
                    real_handler_count // 2, real_handler_count * 2 + 1
                )
                decoy_body_variants = tuple(rng.randrange(8) for _ in range(decoy_count))
            else:
                decoy_body_variants = ()

            helper_route_cycles = []
            for helper in _HELPER_NAMES:
                routes = []
                for _ in range(16):
                    routes.append(
                        rng.randrange(1, helper_count)
                        if helper_count > 1 and rng.random() < helper_rate else 0
                    )
                helper_route_cycles.append((helper, tuple(routes)))

            runtime_variants.append({
                "dispatcher": rng.choice(_DISPATCH_KINDS) if dispatcher == "mixed" else dispatcher,
                "decoy_body_variants": decoy_body_variants,
                "mutate_handlers": bool(self.options.get("mutate_handlers", False)),
                "semantic_alias_modes": tuple(semantic_alias_modes),
                "helper_variant_count": helper_count,
                "helper_fetch_variant": rng.randrange(3),
                "helper_route_cycles": tuple(helper_route_cycles),
            })
        root_state["runtime_variants"] = tuple(runtime_variants)

        # Reserve concrete occurrence identities after target selection so each
        # physical variant/split consumes its own planned descriptor.
        sites = set()
        for function in ordered:
            for block in function.blocks:
                for instruction in block.instructions:
                    if instruction.operation not in graph_operations:
                        continue
                    descriptors = []
                    for _ in range(max(1, int(self.options.get("block_variant_count", 3))) * 3):
                        site = rng.randint(0x10000, 0x7FFFFFFF)
                        while site in sites:
                            site = rng.randint(0x10000, 0x7FFFFFFF)
                        sites.add(site)
                        descriptors.append((site, rng.randint(0x10000, 0xFFFFFFFF),
                                            rng.randint(4000, 0xFFFF), rng.randrange(4)))
                    instructions[instruction.id]["occurrence_descriptors"] = tuple(descriptors)



def resolve_capabilities(
    plan: ProtectionPlan | tuple[ProtectionRequest, ...],
    capabilities: BackendCapabilities,
) -> CapabilityResolution:
    active: list[ProtectionRequest] = []
    disabled: list[ProtectionRequest] = []
    fallbacks = []
    declarations = dict(capabilities.fallbacks)
    requests = plan.requests if isinstance(plan, ProtectionPlan) else plan
    for request in requests:
        if capabilities.supports(request.feature):
            active.append(request)
        elif request.feature in declarations and capabilities.supports(declarations[request.feature]):
            target = declarations[request.feature]
            fallbacks.append((request, target))
            active.append(ProtectionRequest(target, request.level, dict(request.parameters), request.source_options))
        elif request.level is RequirementLevel.REQUIRED:
            raise UnsupportedProtectionError(
                f"backend={capabilities.name} does not support required "
                f"protection '{request.feature}'"
            )
        else:
            disabled.append(request)
    return CapabilityResolution(capabilities.name, tuple(active), tuple(disabled), tuple(fallbacks))


def option_feature(option: str) -> str | None:
    return _OPTION_FEATURES.get(option)
