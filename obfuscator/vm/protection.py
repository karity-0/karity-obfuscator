"""Backend-neutral protection planning and capability resolution."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
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

    def dump(self) -> str:
        lines = ["protection-plan v1"]
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
    return ProtectedIR(ir, plan)


@dataclass(frozen=True)
class BackendCapabilities:
    name: str
    features: frozenset[str]
    supported_options: frozenset[str]

    def supports(self, feature: str) -> bool:
        return feature in self.features


@dataclass(frozen=True)
class CapabilityResolution:
    backend: str
    active: tuple[ProtectionRequest, ...]
    disabled: tuple[ProtectionRequest, ...]

    def is_active(self, feature: str) -> bool:
        return any(request.feature == feature for request in self.active)

    def dump(self) -> str:
        lines = [f"capability-resolution backend={self.backend}"]
        lines.extend(f"supported {request.feature}" for request in self.active)
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


class ProtectionPlanner:
    """Translate user controls into desired semantic protection state."""

    def __init__(self, options: dict[str, Any]):
        self.options = dict(options)

    def build(self, ir: SemanticIR) -> ProtectionPlan:
        grouped: dict[str, dict[str, Any]] = {}
        sources: dict[str, list[str]] = {}
        for option, feature in _OPTION_FEATURES.items():
            if option in _PARAMETER_OPTIONS:
                continue
            if option not in self.options or not _enabled(option, self.options[option]):
                continue
            grouped.setdefault(feature, {})[option] = self.options[option]
            sources.setdefault(feature, []).append(option)
        for option in _PARAMETER_OPTIONS:
            feature = _OPTION_FEATURES[option]
            if feature in grouped and option in self.options:
                grouped[feature][option] = self.options[option]
                sources[feature].append(option)
        requests = tuple(
            ProtectionRequest(
                feature,
                parameters=grouped[feature],
                source_options=tuple(sorted(sources[feature])),
            )
            for feature in sorted(grouped)
        )

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
        return ProtectionPlan(values, instructions, blocks, functions, requests)


def resolve_capabilities(
    plan: ProtectionPlan,
    capabilities: BackendCapabilities,
) -> CapabilityResolution:
    active: list[ProtectionRequest] = []
    disabled: list[ProtectionRequest] = []
    for request in plan.requests:
        if capabilities.supports(request.feature):
            active.append(request)
        elif request.level is RequirementLevel.REQUIRED:
            raise UnsupportedProtectionError(
                f"backend={capabilities.name} does not support required "
                f"protection '{request.feature}'"
            )
        else:
            disabled.append(request)
    return CapabilityResolution(capabilities.name, tuple(active), tuple(disabled))


def option_feature(option: str) -> str | None:
    return _OPTION_FEATURES.get(option)
