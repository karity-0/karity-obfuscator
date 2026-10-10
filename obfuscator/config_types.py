"""Static configuration contracts. Runtime validation remains in registry.py.

Fields are optional where omission selects an existing default. Extensible
backend and protection-feature names stay strings rather than closed enums.
"""
from __future__ import annotations

from typing import Literal, TypedDict

type BlobForm = Literal["string", "table", "numeric", "emoji", "chinese", "random"]
type RequirementLevel = Literal["optional", "required"]
type SelectionMode = Literal["all", "marked"]
type SelectablePass = Literal["string_obf", "number_obf", "boolean_obf", "table_obf", "function_obf", "vm"]


class ProtectionOptions(TypedDict, total=False):
    requirements: dict[str, RequirementLevel]
    dispatcher_type: str
    blob_form: BlobForm
    vm_count: int
    fake_handlers: bool
    mutate_handlers: bool
    junk_instructions: bool
    junk_rate: float
    integrity_constants: bool
    integrity_constant_rate: float
    dispatcher_target_hiding: bool
    semantic_state_threading: bool
    argument_virtualization: bool
    upvalue_virtualization: bool
    table_virtualization: bool
    branch_virtualization: bool
    runtime_trace: bool
    block_variant_count: int
    block_variant_max_instructions: int
    helper_variant_count: int
    helper_diversity_rate: float


class VMOptions(ProtectionOptions, total=False):
    backend: str | None
    graph_execution_rate: float
    cross_instruction_rate: float
    runtime_polymorphism_rate: float
    block_variant_rate: float
    semantic_diversity_rate: float


class BackendPolicy(ProtectionOptions):
    """Lowering always supplies these rates, even when a backend disables them."""
    graph_execution_rate: float
    cross_instruction_rate: float
    runtime_polymorphism_rate: float
    block_variant_rate: float
    semantic_diversity_rate: float


class RenameOptions(TypedDict, total=False):
    seed: int
    readable: bool


class FunctionOptions(TypedDict, total=False):
    cff: bool
    junk: bool
    inline: bool
    wrapper: bool
    boundary_mode: Literal["mixed", "split", "cff"]
    nested: bool
    nested_max_depth: int
    loop_split: bool
    loop_unroll: bool
    loop_unroll_max_iterations: int
    loop_unroll_rate: float
    loop_max_generated_blocks: int
    loop_max_expansion_ratio: float
    loop_max_depth: int


class TargetOptions(TypedDict, total=False):
    lua_version: Literal["5.1", "5.3"]
    environment: Literal["standalone", "cheatengine"]
    compatibility: Literal["portable", "runtime_specific", "binary_specific"]
    disabled_capabilities: list[str]
    runtime_abi: str | None
    host_images: list[str]


class FakeSignatureOptions(TypedDict, total=False):
    sources: list[Literal["well_known", "generated"]]
    generator_patterns: list[str]
    custom_pattern: str


class SignatureConfig(TypedDict, total=False):
    mode: Literal["default", "none", "fake", "generated", "custom"]
    custom: str
    custom_pattern: str
    fake: FakeSignatureOptions


class DebugDumps(TypedDict, total=False):
    ir: str
    protected_ir: str
    protection_plan: str
    backend_ir: str


class ObfuscatorConfig(TypedDict, total=False):
    passes: list[str]
    vm_output_passes: list[str]
    packer_output_passes: list[str]
    vm_options: VMOptions
    rename_obf_options: RenameOptions
    function_obf_options: FunctionOptions
    signature: SignatureConfig
    target: TargetOptions
    debug_dumps: DebugDumps
    lua_executable: str | None
    luac_executable: str | None
    lua_library: str | None
    selection_modes: dict[SelectablePass, SelectionMode]
    selection_profiles: dict[str, ObfuscatorConfig]
    profile: str
    profiles: dict[str, ObfuscatorConfig]
    _profile: str
    _selection_profiles: dict[str, ObfuscatorConfig]
