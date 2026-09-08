"""Structural regression for Semantic IR, protection plans and lowerers."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.parser import Proto, Upvalue
from obfuscator.vm.backends import BackendContext, get_backend
from obfuscator.vm.protection import (
    ProtectionPlan, ProtectionPlanner, ProtectionRequest, RequirementLevel,
    UnsupportedProtectionError, resolve_capabilities,
)
from obfuscator.vm.semantic_ir import build_semantic_ir, validate_semantic_ir
from obfuscator.vm.mov.lower import lower as lower_mov


def abc(op: int, a: int = 0, b: int = 0, c: int = 0) -> int:
    return op | (a << 6) | (c << 14) | (b << 23)


def abx(op: int, a: int, bx: int) -> int:
    return op | (a << 6) | (bx << 14)


def proto(code: list[int], children=()) -> Proto:
    return Proto(
        source="@ir-regression.lua", line_defined=0, last_line_defined=0,
        num_params=0, is_vararg=1, max_stack_size=4, code=code,
        constants=[7, 11], upvalues=[Upvalue(1, 0, "captured")],
        protos=list(children), lineinfo=[], locvars=[],
    )


def main() -> int:
    child = proto([abc(38, 0, 1, 0)])
    source = proto([
        abx(1, 0, 0),             # R0 = K0
        abx(1, 1, 1),             # R1 = K1
        abc(13, 2, 0, 1),         # R2 = R0 + R1
        abc(31, 0, 2, 257),       # if R2 == K1, skip next
        abc(0, 3, 2, 0),          # R3 = R2
        abc(38, 2, 2, 0),         # return R2
    ], [child])

    ir = build_semantic_ir(source)
    validate_semantic_ir(ir)
    assert [function.id for function in ir.functions()] == ["f0", "f0.0"]
    assert len(ir.root.blocks) == 3
    instructions = [
        instruction
        for block in ir.root.blocks
        for instruction in block.instructions
    ]
    assert [item.operation for item in instructions] == [
        "LOAD_CONST", "LOAD_CONST", "ADD", "EQUAL", "MOVE", "RETURN",
    ]
    assert instructions[2].inputs == ("f0:r0", "f0:r1")
    assert instructions[2].outputs == ("f0:r2",)
    assert instructions[3].constants == ("f0:k1",)
    assert len(instructions[3].targets) == 2
    first_dump = ir.dump()
    assert first_dump == build_semantic_ir(source).dump()
    assert "MOV_" not in first_dump and "classic_" not in first_dump

    options = {
        "dispatcher_type": "mixed",
        "vm_count": 2,
        "fake_handlers": True,
        "junk_instructions": True,
        "integrity_constants": True,
        "graph_execution_rate": 0.5,
        "cross_instruction_rate": 0.75,
        "runtime_polymorphism_rate": 0.25,
        "semantic_state_threading": True,
    }
    plan = ProtectionPlanner(options).build(ir)
    assert plan.instructions["f0:i2"]["delayed_materialization_candidate"]
    assert plan.values["f0:k0"]["integrity_encoding_candidate"]
    assert plan.values["f0:r0"]["state_threaded"] is True
    assert plan.dump() == ProtectionPlanner(options).build(ir).dump()

    lowered = {}
    for name in ("classic", "karity", "mov"):
        backend = get_backend(name)
        item = backend.optimize(
            backend.lower(ir, plan, BackendContext(options)),
            BackendContext(options),
        )
        lowered[name] = item
        assert item.semantic_ir is ir
        assert item.source_proto is source
        assert item.backend == name
    assert lowered["karity"].policy["graph_execution_rate"] == 0.5
    assert lowered["classic"].policy["graph_execution_rate"] == 0.0
    assert lowered["mov"].kind == "mov-micro-ir"
    assert lowered["mov"].resolution.is_active("multi_vm")
    assert not lowered["mov"].resolution.is_active("graph_execution")
    assert "fallback-disable graph_execution" in lowered["mov"].dump()
    get_backend("mov").attach_programs(lowered["mov"], [lower_mov(source.code)])
    mov_dump = lowered["mov"].dump()
    assert "micro-program 0" in mov_dump
    assert any(f" {name} " in mov_dump for name in ("MOVE", "LOOKUP", "SELECT", "HOST"))

    required = ProtectionPlan({}, {}, {}, {}, (
        ProtectionRequest("graph_execution", RequirementLevel.REQUIRED),
    ))
    try:
        resolve_capabilities(required, get_backend("mov").capabilities)
    except UnsupportedProtectionError:
        pass
    else:
        raise AssertionError("MOV accepted a required unsupported protection")

    print(
        "vm-ir-regression-ok functions=2 blocks=3 "
        "plans=deterministic backends=classic,karity,mov"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
