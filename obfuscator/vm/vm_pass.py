"""Orchestrate frontend, protection, lowering and backend emission stages."""
from __future__ import annotations

# Load processing dependencies only when the corresponding feature is used.
__lazy_modules__ = {
    "obfuscator.vm.backends.runtime_emitter",
    "obfuscator.vm.ir.optimize",
    "obfuscator.vm.ir.protect",
    "obfuscator.vm.semantic_ir",
}

from functools import partial
from typing import Callable, cast

from pathlib import Path
import subprocess  # Public toolchain test hook shares the standard module.
import time

from ..config_types import DebugDumps, VMOptions
from ..passes.base import PostPass
from ..toolchain import LuaToolchain
from .backend import normalize_vm_backend
from .backends import BackendContext, get_backend
from .backends.base import LoweredIR
from .semantic_ir import SemanticIR
from .backends.runtime_emitter import _compile, _obfuscate_vm_output
from .ir.protect import apply_protection
from .ir.optimize import optimize_semantic_ir
from .protection import ProtectedIR, ProtectionPlan, ProtectionPlanner, protect, resolve_capabilities
from .targets.profile import TargetProfile
from .targets.pass_requirements import (
    validate_pass_target, validate_vm_output_pass_target,
)


_DEFAULT_VM_OPTIONS: VMOptions = {
    "requirements": {},
    # 디스패치 모양: "ifelseif" | "tailcall"(테이블+꼬리호출) | "bsearch"(op 이진탐색)
    #             | "mixed"(VM마다 랜덤)
    "dispatcher_type": "ifelseif",
    "dispatcher_target_hiding": False,
    "semantic_state_threading": False,
    "argument_virtualization": False,
    "upvalue_virtualization": False,
    "table_virtualization": False,
    "branch_virtualization": False,
    # 블롭 저장 형태: string, table, numeric, emoji, chinese 또는 random.
    "blob_form": "random",
    "vm_count": 1,    # 멀티VM: 함수(proto)를 N개 독립 VM에 분산(1=단일, >1=출력 ~N×)
    "fake_handlers": True,
    "mutate_handlers": True,
    "junk_instructions": True,
    "junk_rate": 0.15,
    "integrity_constants": False,
    "integrity_constant_rate": 0.25,
    "graph_execution_rate": 0.1,
    "cross_instruction_rate": 0.2,
    "runtime_polymorphism_rate": 0.2,
    "runtime_trace": False,
    "block_variant_rate": 0.08,
    "block_variant_count": 3,
    "block_variant_max_instructions": 6,
    "helper_variant_count": 3,
    "helper_diversity_rate": 0.35,
    "semantic_diversity_rate": 0.35,
}


class VMBuildPipeline(PostPass):
    def __init__(
        self,
        vm_output_passes: list[str] | None = None,
        vm_options: VMOptions | None = None,
        output_prefix: str = "",
        toolchain: LuaToolchain | None = None,
        debug_dumps: DebugDumps | None = None,
        target: TargetProfile | None = None,
    ):
        self.vm_output_passes = vm_output_passes or []
        self.vm_options: VMOptions = {**_DEFAULT_VM_OPTIONS, **(vm_options or {})}
        self.backend = normalize_vm_backend(self.vm_options.pop("backend", target.backend if target else None))
        self.output_prefix = output_prefix
        self.toolchain = toolchain or LuaToolchain(lua_version=target.lua_version if target else "5.3")
        self.target_profile = target or TargetProfile(backend=self.backend)
        validate_pass_target("vm", self.target_profile)
        for name in self.vm_output_passes:
            validate_vm_output_pass_target(name, self.target_profile)
        if self.target_profile.backend != self.backend:
            raise ValueError("target profile backend mismatch")
        self.target = self.target_profile.adapter()
        self.debug_dumps = cast(DebugDumps, dict(debug_dumps or {}))
        self.isolate_runtime_globals = False
        self.last_profile: list[dict] = []
        self.last_source_ir: SemanticIR | None = None
        self.last_optimized_ir: SemanticIR | None = None
        self.last_protected_ir: ProtectedIR | None = None
        self.last_semantic_ir: SemanticIR | None = None
        self.last_protection_plan: ProtectionPlan | None = None
        self.last_lowered_ir: LoweredIR | None = None

    def run(self, script: str) -> str:
        self.last_profile = []
        self.last_source_ir = None
        self.last_optimized_ir = None
        self.last_protected_ir = None
        self.last_semantic_ir = None
        self.last_protection_plan = None
        self.last_lowered_ir = None
        backend = get_backend(self.backend)
        started = time.perf_counter()
        constant_provider = self.target_profile.constant_provider()
        if constant_provider is not None:
            self.last_profile.append({"phase": "resolve_host_images",
                                      "elapsed": round(time.perf_counter() - started, 6),
                                      "images": len(constant_provider.images)})
        output_transform: Callable[[str, list[str]], tuple[str, list[dict]]] = _obfuscate_vm_output
        if getattr(self.target, "compact_output_globals", False):
            output_transform = partial(_obfuscate_vm_output, compact_globals=True)
        if self.isolate_runtime_globals:
            original_transform = output_transform
            def isolated_transform(source, passes):
                from ..passes.rename_ts import qualify_runtime_globals
                transformed, details = original_transform(source, passes)
                started = time.perf_counter()
                isolated = qualify_runtime_globals(transformed)
                self.last_profile.append({"phase": "isolate_runtime_globals",
                                          "elapsed": round(time.perf_counter() - started, 6)})
                return isolated, details
            output_transform = isolated_transform
        self.target.isolate_runtime_globals = self.isolate_runtime_globals
        context = BackendContext(
            self.vm_options, self.toolchain, tuple(self.vm_output_passes),
            self.output_prefix, self.last_profile, output_transform, self.target,
            constant_provider=constant_provider,
        )
        started = time.perf_counter()
        bytecode = self.target.compile(script, self.toolchain)
        self.last_profile.append({"phase": "compile_luac", "elapsed": round(time.perf_counter() - started, 6)})
        started = time.perf_counter()
        source_ir = self.target.build_ir(bytecode)
        self.last_source_ir = source_ir
        self.last_profile.append({
            "phase": "build_semantic_ir", "elapsed": round(time.perf_counter() - started, 6),
            "functions": sum(1 for _ in source_ir.functions()),
            "instructions": sum(len(block.instructions) for function in source_ir.functions() for block in function.blocks),
        })
        planner = ProtectionPlanner(self.vm_options)
        optimize_started = time.perf_counter()
        optimized_ir = optimize_semantic_ir(source_ir)
        self.last_optimized_ir = optimized_ir
        self.last_profile.append({
            "phase": "optimize_semantic_ir", "elapsed": round(time.perf_counter() - optimize_started, 6),
            "folded": sum("constant_folded_from" in instruction.metadata
                          for function in optimized_ir.functions() for block in function.blocks
                          for instruction in block.instructions),
        })
        resolution_started = time.perf_counter()
        initial_plan = planner.build(optimized_ir)
        resolution = resolve_capabilities(initial_plan, backend.capabilities)
        self.last_profile.append({
            "phase": "resolve_backend_capabilities", "elapsed": round(time.perf_counter() - resolution_started, 6),
            "backend": backend.name,
            "supported": [request.feature for request in resolution.active],
            "disabled": [request.feature for request in resolution.disabled],
        })
        started = time.perf_counter()
        semantic_ir = apply_protection(optimized_ir, initial_plan, resolution)
        self.last_profile.append({"phase": "apply_semantic_protection", "elapsed": round(time.perf_counter() - started, 6)})
        started = time.perf_counter()
        plan = planner.build(semantic_ir)
        lowered = backend.optimize(backend.lower(protect(semantic_ir, plan), context), context)
        self.last_semantic_ir = semantic_ir
        self.last_protected_ir = lowered.protected_ir
        self.last_protection_plan = plan
        self.last_lowered_ir = lowered
        self.last_profile.append({
            "phase": "backend_lowering", "elapsed": round(time.perf_counter() - started, 6),
            "backend": backend.name, "kind": lowered.kind,
        })
        started = time.perf_counter()
        output = backend.emit(lowered, context)
        self.last_profile.append({
            "phase": "backend_emit", "elapsed": round(time.perf_counter() - started, 6),
            "backend": backend.name,
        })
        dumps = {
            "ir": source_ir.dump, "optimized_ir": optimized_ir.dump, "protected_ir": semantic_ir.dump,
            "protection_plan": lambda: plan.dump() + lowered.resolution.dump(),
            "backend_ir": lowered.dump,
        }
        for name, path in cast(dict[str, str], self.debug_dumps).items():
            if name in dumps and path:
                Path(path).write_text(dumps[name](), encoding="utf-8")
        return output


class VMPass(PostPass):
    """Select and run one VM implementation without coupling it to profiles."""

    def __init__(
        self,
        vm_output_passes: list[str] | None = None,
        vm_options: VMOptions | None = None,
        output_prefix: str = "",
        toolchain: LuaToolchain | None = None,
        debug_dumps: DebugDumps | None = None,
        target: TargetProfile | None = None,
    ):
        options = cast(VMOptions, dict(vm_options or {}))
        self.backend = normalize_vm_backend(options.pop("backend", target.backend if target else None))
        self.vm_options: VMOptions = {"backend": self.backend, **options}
        self.vm_output_passes = vm_output_passes or []
        self.output_prefix = output_prefix
        self.toolchain = toolchain or LuaToolchain(lua_version=target.lua_version if target else "5.3")
        self.target_profile = target or TargetProfile(backend=self.backend)
        if self.target_profile.backend != self.backend:
            raise ValueError("target profile backend mismatch")
        self.target = self.target_profile.adapter()
        self.last_profile: list[dict] = []
        self.last_source_ir: SemanticIR | None = None
        self.last_optimized_ir: SemanticIR | None = None
        self.last_protected_ir: ProtectedIR | None = None
        self.last_semantic_ir: SemanticIR | None = None
        self.last_protection_plan: ProtectionPlan | None = None
        self.last_lowered_ir: LoweredIR | None = None

        self._backend = VMBuildPipeline(
            vm_output_passes=self.vm_output_passes,
            vm_options={"backend": self.backend, **options},
            output_prefix=output_prefix,
            toolchain=self.toolchain,
            debug_dumps=debug_dumps,
            target=self.target_profile,
        )

    def run(self, script: str) -> str:
        self.last_source_ir = None
        self.last_optimized_ir = None
        self.last_protected_ir = None
        self.last_semantic_ir = None
        self.last_protection_plan = None
        self.last_lowered_ir = None
        self.last_profile = []
        output = self._backend.run(script)
        self.last_profile = getattr(self._backend, "last_profile", [])
        self.last_source_ir = self._backend.last_source_ir
        self.last_optimized_ir = self._backend.last_optimized_ir
        self.last_protected_ir = self._backend.last_protected_ir
        self.last_semantic_ir = self._backend.last_semantic_ir
        self.last_protection_plan = self._backend.last_protection_plan
        self.last_lowered_ir = self._backend.last_lowered_ir
        return output
