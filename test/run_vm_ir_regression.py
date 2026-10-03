"""Structural regression for Semantic IR, protection plans and lowerers."""
from dataclasses import replace
import random
import tempfile
import subprocess
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.parser import Proto, Upvalue
from obfuscator.vm.backends import BackendContext, get_backend
from obfuscator.vm.protection import (
    ProtectionPlan, ProtectionPlanner, ProtectionRequest, RequirementLevel,
    UnsupportedProtectionError, resolve_capabilities, protect,
)
from obfuscator.vm.semantic_ir import build_semantic_ir, validate_semantic_ir, IRValidationError
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


def check_typed_frontend():
    # Every executable 5.3 operation has ordered typed operands.
    for op in range(46):
        code = [abc(op, 0, 1, 1)]
        if op in (5, 6, 9): code = [abc(op, 0, 0, 1)]
        if op in (1, 44): code = [abx(op, 0, 0)]
        if op == 2: code = [abx(op, 0, 0), 46]
        if op in (30, 39, 40, 42): code = [abx(op, 0, 131071)]
        code.append(abc(38, 0, 1))
        if op in (3, 31, 32, 33, 34, 35): code.append(abc(38, 0, 1))
        sample = proto(code, [proto([abc(38, 0, 1)])])
        sample.max_stack_size = 8
        typed = build_semantic_ir(sample)
        assert typed.root.blocks[0].instructions[0].operands, op
    jump_ir = build_semantic_ir(proto([abx(30, 0, 131071), abc(38, 0, 1)]))
    assert jump_ir.root.blocks[0].instructions[0].targets == ("f0:b1",)
    combined = build_semantic_ir(proto([
        abx(2, 0, 0), 46 | (1 << 6),
        abc(43, 0, 1, 0), 46 | (3 << 6),
        abc(36, 0, 0, 0), abc(45, 0, 0), abc(38, 0, 0),
    ]))
    assert combined.dump() == (ROOT / "test/fixtures/ir/typed_extensions.ir").read_text(encoding="utf-8")
    instructions = [i for b in combined.root.blocks for i in b.instructions]
    assert [i.operation for i in instructions] == ["LOAD_CONST", "SET_LIST", "CALL", "VARARG", "RETURN"]
    assert instructions[0].constants == ("f0:k1",)
    assert instructions[1].operands[-1].value == 3
    assert instructions[2].operands[1].count is None
    assert instructions[2].operands[2].count is None
    assert instructions[3].operands[0].count is None
    assert instructions[4].operands[0].count is None
    assert combined.root.values[4].literal == 7
    open_plan = ProtectionPlanner({"graph_execution_rate": 1.0}).build(combined)
    assert open_plan.functions[combined.root.id]["open_register_extent"]
    assert all(state["avalanche_arity"] == 0 for state in open_plan.instructions.values())
    # The validator and dump need no frontend provenance or Proto.
    blocks = tuple(replace(b, instructions=tuple(replace(i, metadata={}) for i in b.instructions)) for b in combined.root.blocks)
    detached = replace(combined, root=replace(combined.root, blocks=blocks))
    validate_semantic_ir(detached)
    assert detached.dump() == combined.dump()
    from obfuscator.vm.backends.handler_ir import validate_handler_ir
    for backend in ("classic", "karity", "mov"):
        lowered = get_backend(backend).lower(protect(detached, ProtectionPlanner({}).build(detached)), BackendContext({}))
        validate_handler_ir(lowered.program)
    for code in ([abx(2, 0, 0)], [46], [abc(0, 0, 7), abc(38, 0, 1)],
                 [abx(30, 0, 131072), abx(2, 0, 0), 46, abc(38, 0, 1)]):
        try:
            build_semantic_ir(proto(code))
        except IRValidationError:
            pass
        else:
            raise AssertionError(f"accepted malformed bytecode: {code}")
    plan = ProtectionPlanner({}).build(combined)
    changed = replace(combined, root=replace(combined.root, values=tuple(
        replace(v, literal=99) if v.kind == "constant" else v for v in combined.root.values)))
    try:
        protect(changed, plan)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted a plan from a different IR generation")


def check_semantic_contracts():
    from obfuscator.vm.ir.liveness import analyze_liveness
    sample=build_semantic_ir(proto([abc(0,0,1),abc(38,0,2)]))
    block=sample.root.blocks[0]
    original=block.instructions[0]
    malformed=[
        replace(original,operation="UNKNOWN"),
        replace(original,operands=original.operands[:1]),
        replace(original,operands=original.operands+(original.operands[0],)),
        replace(original,operands=(replace(original.operands[0],kind="constant"),original.operands[1])),
    ]
    for instruction in malformed:
        invalid=replace(sample,root=replace(sample.root,blocks=(
            replace(block,instructions=(instruction,*block.instructions[1:])),*sample.root.blocks[1:])))
        try:
            validate_semantic_ir(invalid)
        except IRValidationError:
            pass
        else:
            raise AssertionError('invalid operation contract was accepted')
    info=analyze_liveness(sample.root)
    assert info.before[original.id]==frozenset(('f0:r1',))
    assert 'f0:r0' in info.after[original.id]
    conditional=build_semantic_ir(proto([abc(35,0,1,0),abx(30,0,131071),abc(38,0,2)]))
    first=conditional.root.blocks[0].instructions[0]
    assert {'f0:r0','f0:r1'}<=analyze_liveness(conditional.root).before[first.id]
    loop=build_semantic_ir(proto([abc(0,1,2),abc(34,0,0,0),abx(30,0,131068),abc(38,1,2)]))
    life=analyze_liveness(loop.root)
    first=loop.root.blocks[0].instructions[0]
    assert life.before[first.id]==frozenset(('f0:r0','f0:r2'))
    assert {'f0:r0','f0:r1','f0:r2'}<=life.after[first.id]
    child=proto([abc(5,0,0),abc(38,0,2)])
    closure=build_semantic_ir(proto([abx(44,1,0),abx(1,0,0),abc(38,1,2)], [child]))
    block=closure.root.blocks[0]
    instruction=block.instructions[0]
    bad_capture=replace(instruction,operands=tuple(
        replace(value,value=1) if value.role=='capture' else value for value in instruction.operands))
    invalid=replace(closure,root=replace(closure.root,blocks=(
        replace(block,instructions=(bad_capture,*block.instructions[1:])),*closure.root.blocks[1:])))
    try:
        validate_semantic_ir(invalid)
    except IRValidationError as error:
        assert 'closure capture mismatch' in str(error)
    else:
        raise AssertionError('inconsistent closure capture was accepted')
    life=analyze_liveness(closure.root)
    returned=next(i for b in closure.root.blocks for i in b.instructions if i.operation=='RETURN')
    assert 'f0:r0' in life.before[returned.id]
    assert not life.captured_after[returned.id]
    closed=build_semantic_ir(proto([abx(44,1,0),abx(1,0,0),abx(30,1,131071),abc(38,1,2)],[child]))
    life=analyze_liveness(closed.root)
    jump=next(i for b in closed.root.blocks for i in b.instructions if i.operation=='JUMP')
    assert 'f0:r0' in life.before[jump.id] and 'f0:r0' not in life.after[jump.id]
    open_ir=build_semantic_ir(proto([abc(45,0,0),abc(38,0,0)]))
    life=analyze_liveness(open_ir.root)
    assert len(life.open_extents)==2
    assert any('f0:runtime_top' in values for values in life.before.values())


def check_common_optimization():
    import math
    from obfuscator.vm.ir.normalize import normalize_semantic_ir
    from obfuscator.vm.ir import IRBlock
    from obfuscator.vm.ir.optimize import optimize_semantic_ir
    from obfuscator.vm.protection import ProtectedIR
    sample=proto([abx(1,0,0),abc(13,1,0,257),abc(38,1,2)])
    sample.constants=[(1<<63)-1,1]
    original=build_semantic_ir(sample)
    instructions=original.root.blocks[0].instructions
    split=replace(original,root=replace(original.root,blocks=tuple(
        IRBlock(f"f0:b{index}",(replace(instruction,targets=((f"f0:b{index+1}",) if index+1<len(instructions) else ())),),
                ((f"f0:b{index+1}",) if index+1<len(instructions) else ()))
        for index,instruction in enumerate(instructions))))
    normalized=normalize_semantic_ir(split)
    assert len(normalized.root.blocks)==1
    assert normalize_semantic_ir(normalized).dump()==normalized.dump()
    assert [i.id for i in normalized.root.blocks[0].instructions]==[i.id for i in instructions]
    optimized=optimize_semantic_ir(original)
    assert optimized.root.values[-1].literal==-(1<<63)
    assert optimized.root.blocks[0].instructions[1].operation=='LOAD_CONST'
    assert optimize_semantic_ir(optimized).dump()==optimized.dump()
    original_ids=[i.id for b in original.root.blocks for i in b.instructions]
    assert original_ids==[i.id for b in optimized.root.blocks for i in b.instructions]
    sample.constants=[0.,1]
    sample.code=[abx(1,0,0),abc(25,1,0),abc(38,1,2)]
    negative_zero=optimize_semantic_ir(build_semantic_ir(sample)).root.values[-1].literal
    assert type(negative_zero) is float and math.copysign(1,negative_zero)==-1
    sample.constants=[True,1]
    sample.code=[abx(1,0,0),abc(13,1,0,257),abc(38,1,2)]
    assert optimize_semantic_ir(build_semantic_ir(sample)).root.blocks[0].instructions[1].operation=='ADD'
    plan=ProtectionPlanner({}).build(original)
    for name in ('classic','karity','mov'):
        try:
            get_backend(name).lower(ProtectedIR(optimized,plan),BackendContext({}))
        except ValueError as error:
            assert 'generation' in str(error)
        else:
            raise AssertionError('mixed protected generations were accepted')
    from obfuscator.vm.vm_pass import VMPass
    from run_vm_output_emitter_regression import run_source
    source="""local x=0x7fffffffffffffff; local y=x+1
local z=0.0;local n=-z
local a=1;local function change() a=9 end;change();local b=a+2
local t=setmetatable({}, {__add=function() a=20;return 3 end})
local c=t+1;local d=a+2
local function zeros()
    local positive=0.0;local negative=-positive
    return function() return positive end,function() return negative end
end
local positive,negative=zeros()
print(y,1/n,b,c,d,1/positive(),1/negative())
"""
    expected=run_source(source)
    assert expected[0]==0,expected
    for name in ('classic','karity','mov'):
        random.seed(9921)
        vm=VMPass(vm_options={'backend':name,'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False,'upvalue_virtualization':True,'vm_count':2})
        actual=run_source(vm.run(source))
        assert actual[:2]==expected[:2],(name,expected,actual)
        assert vm.last_optimized_ir is not None
        assert vm.last_protection_plan.generation==vm.last_semantic_ir.generation
        assert any('constant_folded_from' in i.metadata for f in vm.last_optimized_ir.functions() for b in f.blocks for i in b.instructions)


def check_extended_setlist():
    from obfuscator.parser import Lua53Parser
    from obfuscator.vm import VMPass
    from lua_runtime import lua_executable
    parse = Lua53Parser.parse
    def extended(parser):
        function = parse(parser)
        for index, raw in enumerate(function.code):
            if raw & 63 == 43:
                function.code[index] = raw & ~(511 << 14)
                function.code.insert(index + 1, 46 | (512 << 6))
                break
        else:
            raise AssertionError("fixture compiler did not emit SETLIST")
        return function
    with tempfile.TemporaryDirectory() as directory:
        for backend in ("classic", "karity", "mov"):
            random.seed(719)
            with patch.object(Lua53Parser, "parse", extended):
                output = VMPass(vm_options={
                    "backend": backend, "junk_instructions": False,
                    "fake_handlers": False, "mutate_handlers": False,
                    "integrity_constants": False,
                }).run('local t={42}; assert(t[25551]==42); print("extended-ok")')
            path = Path(directory) / (backend + ".lua")
            path.write_text(output, encoding="utf-8")
            result = subprocess.run([lua_executable(), str(path)], capture_output=True, timeout=120)
            assert result.returncode == 0, (backend, result.stderr)
            assert result.stdout.strip() == b"extended-ok"


def check_runtime_composition():
    from obfuscator.vm.backends.runtime_emitter import _load_vm
    from obfuscator.vm.backends.classic import ClassicBackend
    class RenamedClassic(ClassicBackend):
        name = 'custom_direct_backend'
    # Executor selection follows the backend contract, not a recognized name.
    assert _load_vm(RenamedClassic(), None) == _load_vm(ClassicBackend(), None)
    assert 'local exec, _EX, _NX' not in _load_vm(RenamedClassic(), None)
    from obfuscator.vm.targets.lua51 import Lua51Target
    from obfuscator.vm.targets.lua53 import Lua53Target
    from obfuscator.vm.backends.karity import KarityBackend
    from obfuscator.vm.backends.mov import MovBackend
    from obfuscator.vm.mov.layout import make_kits
    from types import SimpleNamespace
    lowered=SimpleNamespace(backend_data={'kits':make_kits(1)})
    with patch.object(Lua53Target,'runtime_template',side_effect=AssertionError('5.3 template read')):
        for backend in (ClassicBackend(),KarityBackend(),MovBackend()):
            source=_load_vm(backend,lowered,target=Lua51Target())
            if backend.name == 'mov':
                assert '_mov_f64_words' in source
            assert 'local function _ixor(a,b)' in source
            assert 'Lua 5.1 target runtime template' in source
    for target in (Lua51Target(),Lua53Target()):
        try:
            target.runtime_template('../vm.lua')
        except ValueError:
            pass
        else:
            raise AssertionError('invalid runtime template accepted')


def check_alias_planning():
    from obfuscator.vm.backends.handler_ir import OPERATIONS
    ir = build_semantic_ir(proto([abx(1, 0, 0), abc(38, 0, 2)],
                                 [proto([abc(38, 0, 1)])]))
    random.seed(224)
    planner = ProtectionPlanner({"vm_count": 2})
    plan = planner.build(ir)
    requirements = plan.functions[ir.root.id]['alias_requirements']
    runtime_variants = plan.functions[ir.root.id]['runtime_variants']
    assert planner.build(ir).dump() == plan.dump()
    assert len(requirements) == 2
    assert len(runtime_variants) == 2
    assert plan.functions[ir.root.id]['blob_form'] in {'string', 'table', 'numeric'}
    representation_routes = dict(plan.functions[ir.root.id]['representation_routes'])
    assert set(representation_routes) == {'arithmetic', 'semantic'}
    assert all(
        type(route) is bool
        for entries in representation_routes.values() for _, route in entries
    )
    for variant, requirement in zip(runtime_variants, requirements):
        assert variant['dispatcher'] == 'ifelseif'
        assert not variant['decoy_body_variants']
        assert len(dict(variant['semantic_alias_modes'])) == len(requirement['operations'])
        assert all(
            len(dict(variant['semantic_alias_modes'])[name]) == count
            for name, count in requirement['operations']
        )
        assert set(dict(variant['helper_route_cycles'])) == {
            'rget', 'rset', '_flow', '_sem'
        }
    for seed in (2, 400):
        random.seed(seed)
        for name in ('classic', 'karity'):
            lowered = get_backend(name).lower(protect(ir, plan), BackendContext({}))
            assert lowered.resolution.is_active('handler_aliases')
            for vm_id, maps in enumerate(lowered.backend_data['layout'].vm_maps):
                expected = dict(requirements[vm_id]['operations'])
                for op, operation in enumerate(OPERATIONS):
                    assert len(maps[0][op]) == expected.get(operation, requirements[vm_id]['auxiliary_count'])
    mov = get_backend('mov').lower(protect(ir, plan), BackendContext({}))
    assert any(request.feature == 'handler_aliases' for request in mov.resolution.disabled)
    required = ProtectionPlanner({'requirements': {'handler_aliases': 'required'}}).build(ir)
    try:
        get_backend('mov').lower(protect(ir, required), BackendContext({}))
    except UnsupportedProtectionError:
        pass
    else:
        raise AssertionError('MOV accepted required handler aliases')
    invalid = dict(plan.functions)
    invalid[ir.root.id] = dict(invalid[ir.root.id], alias_requirements=(
        dict(requirements[0], auxiliary_count=0), *requirements[1:]))
    try:
        protect(ir, replace(plan, functions=invalid))
    except ValueError as error:
        assert 'alias multiplicity' in str(error)
    else:
        raise AssertionError('invalid alias count accepted')
    bad_runtime = dict(runtime_variants[0])
    bad_runtime['helper_fetch_variant'] = 99
    invalid[ir.root.id] = dict(
        plan.functions[ir.root.id],
        runtime_variants=(bad_runtime, *runtime_variants[1:]),
    )
    try:
        protect(ir, replace(plan, functions=invalid))
    except ValueError as error:
        assert 'runtime variant' in str(error)
    else:
        raise AssertionError('invalid runtime variant accepted')
    bad_routes = tuple(
        (group, entries + (("UNKNOWN", False),) if group == "semantic" else entries)
        for group, entries in plan.functions[ir.root.id]['representation_routes']
    )
    invalid[ir.root.id] = dict(
        plan.functions[ir.root.id], representation_routes=bad_routes
    )
    try:
        protect(ir, replace(plan, functions=invalid))
    except ValueError as error:
        assert 'representation routes' in str(error)
    else:
        raise AssertionError('invalid representation route accepted')


def check_backend_layouts():
    from obfuscator.vm.mov.ir import Instruction, Op, Host
    from obfuscator.vm.mov.validate import validate_program
    from obfuscator.vm.backends.handler_layout import validate_layout
    ir = build_semantic_ir(proto([abx(1, 0, 0), abc(38, 0, 2)]))
    for name in ("classic", "karity", "mov"):
        random.seed(9421)
        backend = get_backend(name)
        context = BackendContext({})
        plan = ProtectionPlanner({}).build(ir)
        lowered = backend.optimize(backend.lower(protect(ir, plan), context), context)
        assert lowered.dump() == (ROOT / "test/fixtures/ir" / f"{name}_layout.ir").read_text(encoding="utf-8")
        layout = lowered.backend_data["layout"]
        # Backend ownership must preserve the physical byte format and RNG
        # consumption, including MOV's linked tape after the common prefix.
        from obfuscator.vm.backends.handler_codec import serialize
        state = random.getstate()
        expected = serialize(layout.functions, layout=layout.instruction_layout,
                             constant_tags=layout.constant_tags, vm_count=layout.vm_count,
                             integrity_options={'enabled': False})
        if name == 'mov':
            from obfuscator.vm.mov.serializer import serialize as serialize_mov
            expected += serialize_mov(lowered.backend_data['programs'],
                                      lowered.backend_data['kits'], {},
                                      linked=lowered.backend_data['linked'])
        expected_state = random.getstate()
        random.setstate(state)
        assert backend.serialize_program(lowered, context) == expected
        assert random.getstate() == expected_state
        if name != "mov":
            from copy import deepcopy
            def reject_dispatch(change, message):
                bad = deepcopy(lowered)
                change(bad.backend_data['layout'])
                try:
                    backend.optimize(bad, context)
                except ValueError as error:
                    assert message in str(error), str(error)
                else:
                    raise AssertionError('invalid backend dispatcher accepted')
            def collide(layout):
                values = next(iter(layout.vm_maps[0][0].values()))
                values[1] = values[0]
            def overflow(layout):
                next(iter(layout.vm_maps[0][0].values())).append(32768)
            def prune(layout):
                aliases = {v for values in layout.vm_maps[0][0].values() for v in values}
                target = next(item.vop for item in layout.functions.code if item.vop in aliases)
                layout.used_ops[0].remove(target)
            # Directly use the backend-specific validator where common target
            # validation could fail first for an alias changed by corruption.
            bad = deepcopy(lowered)
            collide(bad.backend_data['layout'])
            try:
                backend.validate_lowered(bad)
            except ValueError as error:
                assert 'colliding' in str(error)
            else:
                raise AssertionError('colliding dispatcher accepted')
            reject_dispatch(overflow, '15-bit')
            reject_dispatch(prune, 'pruned handler')
            if name == 'classic':
                reject_dispatch(lambda layout: layout.vm_maps[0][3].update({0: 32767}),
                                'deferred handlers')
            original = layout.functions.code[0]
            layout.functions.code[0] = replace(original, vop=0xFFFFFF)
            try:
                validate_layout(layout.functions, layout.vm_maps)
            except ValueError:
                pass
            else:
                raise AssertionError("missing handler target accepted")
            layout.functions.code[0] = original
        else:
            program = lowered.backend_data["programs"][0]
            assert lowered.backend_data["linked"]
            for invalid in (Instruction(Op.SELECT, 30, 99999, 1),
                            Instruction(Op.LOOKUP, 99999, 1, 1),
                            Instruction(Op.HOST, Host.PREPARE, 1)):
                bad = replace(program, code=[invalid, *program.code[1:]])
                try:
                    validate_program(bad)
                except ValueError:
                    pass
                else:
                    raise AssertionError("invalid microcode accepted")


def check_karity_state_model():
    from copy import deepcopy
    from obfuscator.vm.backends.karity_state import _boundary_kind, validate_state
    from obfuscator.vm.backends.handler_ir import HandlerInstruction, OPERATION_IDS

    boundary_cases = {
        "CALL": "call-or-yield",
        "TAIL_CALL": "tail-call-or-yield",
        "RETURN": "host-return",
        "GET_TABLE": "table-metamethod-read",
        "SET_TABLE": "table-metamethod-write",
        "ADD": "arithmetic-metamethod",
        "CLOSURE": "upvalue-capture",
        "ITER_CALL": "iterator-call-or-yield",
        "MOVE": None,
    }
    for operation, expected_boundary in boundary_cases.items():
        instruction = HandlerInstruction(OPERATION_IDS[operation])
        assert _boundary_kind(instruction) == expected_boundary, operation

    # A forced deferred ADD is consumed by MOVE, so the projection must retain
    # both the pending producer and the later rget materialization boundary.
    ir = build_semantic_ir(proto([
        abc(13, 0, 1, 2), abc(0, 3, 0), abc(38, 3, 2),
    ]))
    options = {"cross_instruction_rate": 1.0, "graph_execution_rate": 0.0}
    random.seed(9531)
    backend = get_backend("karity")
    context = BackendContext(options)
    lowered = backend.optimize(
        backend.lower(protect(ir, ProtectionPlanner(options).build(ir)), context),
        context,
    )
    state = lowered.backend_data["karity_state"]
    transitions = state.functions[0].transitions
    pending = next(item for item in transitions if item.pending_write is not None)
    assert pending.operation == "ADD"
    assert pending.pending_guard == ("all-inputs-integer-kind", "runtime-poly-lazy")
    assert any(
        pending.pending_write in item.materialized for item in transitions
    )
    materializer = next(
        item for item in transitions if pending.pending_write in item.materialized
    )
    pending_input = materializer.native_inputs[materializer.reads.index(pending.pending_write)]
    assert pending_input.producers == (pending.pc,)
    assert pending_input.epochs == (pending.pc + 1,)
    assert all(
        item.operation != "RETURN" or item.native_boundary
        for item in transitions
    )
    validate_state(lowered)
    state_dump = lowered.dump()
    assert f"karity-transition function=f0 pc={materializer.pc} " in state_dump
    assert "materialized=(0,)" in state_dump
    assert "boundary=host-return" in state_dump

    repeated_read_ir = build_semantic_ir(proto([
        abc(13, 0, 1, 2), abc(13, 0, 0, 0), abc(38, 0, 2),
    ]))
    random.seed(9531)
    repeated_read_context = BackendContext(options)
    repeated_read_lowered = backend.optimize(
        backend.lower(
            protect(repeated_read_ir, ProtectionPlanner(options).build(repeated_read_ir)),
            repeated_read_context,
        ),
        repeated_read_context,
    )
    repeated_read_transitions = (
        repeated_read_lowered.backend_data["karity_state"].functions[0].transitions
    )
    repeated_read = next(
        item for item in repeated_read_transitions
        if item.operation == "ADD" and item.reads == (0, 0)
    )
    prior_producer = next(
        item for item in reversed(repeated_read_transitions[:repeated_read.pc])
        if item.pending_write == 0
    )
    assert len(repeated_read.native_inputs) == 2
    assert repeated_read.resolved_pending == (0,)
    if repeated_read.graph_descriptors:
        assert repeated_read.materialized == (0,)
        assert repeated_read.maybe_materialized == ()
    else:
        assert repeated_read.materialized == ()
        assert repeated_read.maybe_materialized == (0,)
    assert all(value.producers == (prior_producer.pc,)
               for value in repeated_read.native_inputs)
    validate_state(repeated_read_lowered)

    # Closure creation captures a register box, not its transient native value.
    # Keep the pending producer/epoch attached to that capture until a later
    # rget or upvalue close actually materializes it.
    child = proto([abc(5, 0, 0), abc(38, 0, 2)])
    closure_ir = build_semantic_ir(proto([
        abc(13, 0, 1, 2), abx(44, 3, 0), abc(38, 3, 2),
    ], [child]))
    random.seed(9531)
    closure_context = BackendContext(options)
    closure_lowered = backend.optimize(
        backend.lower(
            protect(closure_ir, ProtectionPlanner(options).build(closure_ir)),
            closure_context,
        ),
        closure_context,
    )
    closure_transitions = closure_lowered.backend_data["karity_state"].functions[0].transitions
    closure = next(item for item in closure_transitions if item.operation == "CLOSURE")
    closure_pending = next(item for item in closure_transitions if item.pending_write is not None)
    assert closure.captures == (0,)
    assert closure.boundary_kind == "upvalue-capture"
    assert closure.capture_states[0].representation.value == "maybe-pending"
    assert closure.capture_states[0].producers == (closure_pending.pc,)
    validate_state(closure_lowered)

    close_ir = build_semantic_ir(proto([
        abc(13, 0, 1, 2), abx(44, 3, 0),
        abx(30, 1, 131071), abc(38, 3, 2),
    ], [child]))
    random.seed(9531)
    close_context = BackendContext(options)
    close_lowered = backend.optimize(
        backend.lower(
            protect(close_ir, ProtectionPlanner(options).build(close_ir)),
            close_context,
        ),
        close_context,
    )
    close_transitions = close_lowered.backend_data["karity_state"].functions[0].transitions
    close_pending = next(item for item in close_transitions if item.pending_write == 0)
    close_boundary = next(
        item for item in close_transitions
        if item.operation == "JUMP" and item.close_from == 0
    )
    assert close_boundary.boundary_kind == "upvalue-close"
    assert close_boundary.open_boxes == (0, 3)
    assert close_boundary.closed_registers == (0, 3)
    assert 0 in close_boundary.close_materialized
    assert close_boundary.close_states[0].producers == (close_pending.pc,)
    validate_state(close_lowered)

    # A conditional can join an untouched encoded value with a value that may
    # still be deferred. Preserve both predecessor epochs and resolve the
    # path-dependent pending value at the first rget after the join.
    branch_proto = proto([
        abc(34, 0, 0, 0), abx(30, 0, 131073),
        abc(13, 1, 2, 3), abx(30, 0, 131071),
        abc(0, 4, 1), abc(38, 4, 2),
    ])
    branch_proto.max_stack_size = 5
    branch_ir = build_semantic_ir(branch_proto)
    random.seed(9531)
    branch_context = BackendContext(options)
    branch_lowered = backend.optimize(
        backend.lower(
            protect(branch_ir, ProtectionPlanner(options).build(branch_ir)),
            branch_context,
        ),
        branch_context,
    )
    branch_transitions = branch_lowered.backend_data["karity_state"].functions[0].transitions
    branch_pending = next(item for item in branch_transitions if item.pending_write == 1)
    branch_materializer = next(
        item for item in branch_transitions if 1 in item.materialized
    )
    joined_input = branch_materializer.native_inputs[
        branch_materializer.reads.index(1)
    ]
    assert joined_input.producers == (branch_pending.pc,)
    assert joined_input.epochs == (0, branch_pending.pc + 1)
    validate_state(branch_lowered)

    def changed_transition(source, pc, update):
        bad = deepcopy(source)
        state = bad.backend_data["karity_state"]
        functions = list(state.functions)
        function = functions[0]
        functions[0] = replace(
            function,
            transitions=tuple(
                update(item) if item.pc == pc else item
                for item in function.transitions
            ),
        )
        bad.backend_data["karity_state"] = replace(state, functions=tuple(functions))
        return bad

    bad = changed_transition(
        lowered, pending.pc, lambda item: replace(item, pending_write=None)
    )
    try:
        validate_state(bad)
    except ValueError as error:
        assert "pending producer does not write" in str(error)
    else:
        raise AssertionError("Karity accepted a stale pending-state projection")
    try:
        backend.emit(bad, context)
    except ValueError as error:
        assert "pending producer does not write" in str(error)
    else:
        raise AssertionError("Karity emitted a stale pending-state projection")

    missing_materialization = changed_transition(
        lowered,
        materializer.pc,
        lambda item: replace(
            item,
            materialized=tuple(
                register for register in item.materialized
                if register != pending.pending_write
            ),
        ),
    )
    try:
        validate_state(missing_materialization)
    except ValueError as error:
        assert "pending input escaped materialization" in str(error)
    else:
        raise AssertionError("Karity accepted an unresolved pending read")

    wrong_producer = next(
        item for item in transitions
        if item.pc != pending.pc and item.pending_write != pending.pending_write
    )
    native_index = materializer.reads.index(pending.pending_write)
    wrong_producer_state = replace(
        materializer.native_inputs[native_index],
        producer=wrong_producer.pc,
        producers=(wrong_producer.pc,),
    )
    wrong_producer_lowered = changed_transition(
        lowered,
        materializer.pc,
        lambda item: replace(
            item,
            native_inputs=tuple(
                wrong_producer_state if index == native_index else value
                for index, value in enumerate(item.native_inputs)
            ),
        ),
    )
    try:
        validate_state(wrong_producer_lowered)
    except ValueError as error:
        assert "pending producer does not write" in str(error)
    else:
        raise AssertionError("Karity accepted a pending value from the wrong producer")


def check_dispatch_sequences():
    from copy import deepcopy
    ir=build_semantic_ir(proto([abc(13,0,1,2),abc(14,0,1,2),abc(38,0,2)]))
    for name in ('classic','karity'):
        random.seed(9424)
        backend=get_backend(name)
        context=BackendContext({'block_variant_rate':0.0})
        lowered=backend.lower(protect(ir,ProtectionPlanner(context.options).build(ir)),context)
        layout=lowered.backend_data['layout']
        aliases,splits,fuses,defers=layout.vm_maps[0]
        first=replace(layout.functions.code[0],instruction=lowered.program.code[0],graph_sites=(),avalanche=())
        second=replace(first,instruction=lowered.program.code[1],vop=aliases[14][0])
        layout.graph_sites.clear()
        layout.used_ops[0].update(aliases[13]+aliases[14])
        def check(code, message=None, routes=()):
            bad=deepcopy(lowered)
            bad.backend_data['layout'].functions.code=code
            bad.backend_data['layout'].functions.routes=list(routes)
            bad.backend_data['layout'].used_ops[0].update(item.vop for item in code if item.vop in {
                vop for values in aliases.values() for vop in values})
            try:
                backend.optimize(bad,context)
            except ValueError as error:
                assert message and message in str(error),str(error)
            else:
                assert message is None, 'corrupt dispatcher sequence accepted'
        check([replace(first,vop=aliases[13][0])])
        check([replace(first,vop=aliases[14][0])],'operation differs')
        for values in splits[13].values():
            group=[replace(first,vop=vop) for vop in values]
            check(group)
            check(group[1:],'split handler sequence')
            check(list(reversed(group)),'split handler sequence')
            changed=list(group)
            changed[-1]=replace(changed[-1],instruction=replace(first.instruction,a=1))
            check(changed,'split handler sequence')
        pair=(13,14)
        assert pair in fuses
        fused=replace(first,vop=fuses[pair])
        check([fused,second])
        check([fused],'fused operand slot')
        check([fused,replace(second,vop=aliases[13][0])],'fused operand slot')
        from obfuscator.vm.backends.handler_ir import HandlerInstruction
        for composite in ([fused,second], [replace(first,vop=vop) for vop in splits[13]['3']]):
            for op in (30,39,40,42,59):
                for target in (1,2,len(composite)+1):
                    instruction=HandlerInstruction(op).with_bx(target if op==59 else 131071+target-1)
                    jump=replace(first,instruction=instruction,vop=aliases[op][0])
                    check([jump,*composite], 'composite handler interior' if target==2 else None)
            for op in (3,31,32,33,34,35):
                skip=replace(first,instruction=HandlerInstruction(op,c=1),vop=aliases[op][0])
                check([skip,*composite],'composite handler interior')
            check(composite,routes=[[1]])
            check(composite,'composite handler interior',routes=[[2]])
        if name=='karity':
            check([replace(first,vop=defers[13])])
            check([replace(first,vop=defers[14])],'operation differs')


def check_graph_layout_validation():
    from copy import deepcopy
    ir = build_semantic_ir(proto([abx(1, 0, 0), abc(13, 1, 0, 0), abc(38, 1, 2)]))
    for name in ('classic', 'karity'):
        random.seed(9422)
        backend = get_backend(name)
        context = BackendContext({'graph_execution_rate': 1.0})
        plan = ProtectionPlanner(context.options).build(ir)
        lowered = backend.optimize(backend.lower(protect(ir, plan), context), context)
        layout = lowered.backend_data['layout']
        index = next(i for i, item in enumerate(layout.functions.code) if item.graph_sites)
        if name == 'karity':
            graph_state = lowered.backend_data['karity_state'].functions[0]
            graph_transition = next(
                item for item in graph_state.transitions if item.graph_dependencies
            )
            assert graph_transition.graph_sites
            assert len(graph_transition.graph_dependencies) == len(graph_transition.graph_sites)
            for dependency in graph_transition.graph_dependencies:
                assert dependency.registers == graph_transition.reads
                assert all(epochs for _, epochs in dependency.epochs)
            bad_state = deepcopy(lowered)
            state = bad_state.backend_data['karity_state']
            functions = list(state.functions)
            function_state = functions[0]
            transitions = list(function_state.transitions)
            dependency = graph_transition.graph_dependencies[0]
            stale_dependency = replace(dependency, epochs=())
            transitions[graph_transition.pc] = replace(
                graph_transition,
                graph_dependencies=(stale_dependency,
                                    *graph_transition.graph_dependencies[1:]),
            )
            functions[0] = replace(function_state, transitions=tuple(transitions))
            bad_state.backend_data['karity_state'] = replace(
                state, functions=tuple(functions)
            )
            try:
                from obfuscator.vm.backends.karity_state import validate_state
                validate_state(bad_state)
            except ValueError as error:
                assert 'stale representation epoch' in str(error), str(error)
            else:
                raise AssertionError('Karity accepted a stale graph representation epoch')
        def reject(change, message):
            bad = deepcopy(lowered)
            change(bad.backend_data['layout'])
            try:
                backend.optimize(bad, context)
            except ValueError as error:
                assert message in str(error), str(error)
            else:
                raise AssertionError('invalid graph layout accepted')
        def descriptor_change(layout, field, value):
            item = layout.functions.code[index]
            descriptor = list(item.graph_sites[0])
            descriptor[field] = value
            layout.functions.code[index] = replace(item, graph_sites=(tuple(descriptor), *item.graph_sites[1:]))
        for field, value in ((1, 1 << 32), (2, 1 << 32), (3, 1 << 16), (3, 1.5)):
            reject(lambda layout: descriptor_change(layout, field, value), 'invalid graph descriptor')
        reject(lambda layout: descriptor_change(layout, 2, 1), 'differs from protection plan')
        family = layout.functions.code[index].graph_sites[0][0]
        reject(lambda layout: descriptor_change(layout, 0, (family + 1) % 9),
               'family differs from backend policy')
        def duplicate(layout):
            item = layout.functions.code[index]
            layout.functions.code[index] = replace(item, graph_sites=(*item.graph_sites, item.graph_sites[0]))
        reject(duplicate, 'duplicate physical graph site')
        reject(lambda layout: layout.graph_sites.clear(), 'inventory mismatch')
        reject(lambda layout: layout.graph_sites.add(1), 'inventory mismatch')


def check_block_route_validation():
    from copy import deepcopy
    from obfuscator.vm.backends.handler_layout import validate_layout
    ir = build_semantic_ir(proto([abx(1, 0, 0), abc(13, 1, 0, 0), abc(38, 1, 2)]))
    context = BackendContext({'block_variant_rate': 1.0})
    random.seed(9423)
    backend = get_backend('karity')
    lowered = backend.optimize(backend.lower(protect(ir, ProtectionPlanner(context.options).build(ir)), context), context)
    layout = lowered.backend_data['layout']
    assert layout.functions.routes
    def reject(change, message):
        bad = deepcopy(layout.functions)
        change(bad)
        try:
            validate_layout(bad, layout.vm_maps)
        except ValueError as error:
            assert message in str(error), str(error)
        else:
            raise AssertionError('invalid block control flow accepted')
    def change_instruction(function, operation, transform):
        index = next(i for i, item in enumerate(function.code) if item.instruction.operation == operation)
        item = function.code[index]
        function.code[index] = replace(item, instruction=transform(item.instruction))
    reject(lambda f: change_instruction(f, 'BLOCK_ROUTE', lambda i: replace(i, a=len(f.routes))), 'route index')
    reject(lambda f: change_instruction(f, 'BLOCK_GOTO', lambda i: i.with_bx(len(f.code) + 1)), 'goto target')
    reject(lambda f: f.routes.__setitem__(0, []), 'route length')
    reject(lambda f: f.routes.__setitem__(0, [1] * 256), 'route length')
    reject(lambda f: f.routes[0].__setitem__(0, len(f.code) + 1), 'route target')
    reject(lambda f: f.routes[0].__setitem__(0, 1.5), 'route target')
    # The one-past-end zero-based PC is a legal exit for BLOCK_GOTO.
    boundary = deepcopy(layout.functions)
    change_instruction(boundary, 'BLOCK_GOTO', lambda i: i.with_bx(len(boundary.code)))
    validate_layout(boundary, layout.vm_maps)


def check_semantic_protection():
    from obfuscator.vm import VMPass
    from run_vm_output_emitter_regression import run_source
    generator = random.Random(8802)
    sources = ["local t=setmetatable({}, {__len=function() return 'length' end}); print(#t)"]
    for _ in range(3):
        offset, factor, limit = generator.randint(1, 9), generator.randint(2, 5), generator.randint(4, 8)
        sources.append(f"""local function pack(...) return select('#',...), ... end
local s=0; local fs={{}}
for i=1,{limit} do
  local x=i+{offset}; fs[i]=function(y) if y%2==0 then return x*y else return x-y end end
  if i%3==0 then s=s+fs[i]({factor}) else s=s-i end
end
print(s,pack(nil,fs[1](2),nil))""")
    for case, source in enumerate(sources):
        expected = run_source(source)
        assert expected[0] == 0
        for name in ("classic", "karity", "mov"):
            random.seed(8810 + case)
            pipeline = VMPass(vm_options={"backend": name, "junk_rate": 1.0,
                "vm_count": 1 + case % 3, "graph_execution_rate": 0.2})
            result = run_source(pipeline.run(source))
            assert result == expected, (name, case, result, expected)
            source_ids = {i.id for f in pipeline.last_source_ir.functions() for b in f.blocks for i in b.instructions}
            final_ids = {i.id for f in pipeline.last_semantic_ir.functions() for b in f.blocks for i in b.instructions}
            assert source_ids < final_ids
            assert any(':junk' in value for value in final_ids - source_ids)
            assert pipeline.last_semantic_ir.generation == pipeline.last_protection_plan.generation


def main() -> int:
    check_semantic_contracts()
    check_common_optimization()
    check_semantic_protection()
    check_runtime_composition()
    check_alias_planning()
    check_backend_layouts()
    check_karity_state_model()
    check_dispatch_sequences()
    check_graph_layout_validation()
    check_block_route_validation()
    check_typed_frontend()
    check_extended_setlist()
    from obfuscator.vm.vm_pass import VMPass
    with tempfile.TemporaryDirectory() as directory:
        paths = {name: str(Path(directory) / (name + ".txt")) for name in
                 ("ir", "protected_ir", "protection_plan", "backend_ir")}
        from obfuscator.registry import validate_config
        validate_config({"passes": ["vm"], "debug_dumps": paths})
        random.seed(617)
        pipeline = VMPass(vm_options={"backend": "classic", "junk_rate": 1.0}, debug_dumps=paths)
        pipeline.run("local x=3; for i=1,3 do x=x+i end; print(x)")
        assert pipeline.last_source_ir is not pipeline.last_semantic_ir
        assert pipeline.last_protected_ir.semantic_ir is pipeline.last_semantic_ir
        assert pipeline.last_lowered_ir.semantic_ir is pipeline.last_semantic_ir
        assert pipeline.last_protection_plan.generation == pipeline.last_semantic_ir.generation
        assert Path(paths["ir"]).read_text(encoding="utf-8") == pipeline.last_source_ir.dump()
        assert Path(paths["protected_ir"]).read_text(encoding="utf-8") == pipeline.last_semantic_ir.dump()
        assert pipeline.last_semantic_ir.generation in Path(paths["backend_ir"]).read_text(encoding="utf-8")
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
    planning_rng_state = random.getstate()
    planner = ProtectionPlanner(options)
    plan = planner.build(ir)
    assert planner.build(ir).dump() == plan.dump()

    # The plan owns a snapshot of the build seed. Random choices made by a
    # later emitter must not perturb protection policy, even if they happen
    # after planner construction but before it is asked to build.
    random.setstate(planning_rng_state)
    emitter_isolated_planner = ProtectionPlanner(options)
    for _ in range(512):
        random.getrandbits(64)
    emitter_rng_state = random.getstate()
    assert emitter_isolated_planner.build(ir).dump() == plan.dump()
    assert random.getstate() == emitter_rng_state

    assignments = {state["vm_assignment"] for state in plan.functions.values()}
    assert assignments == {0, 1}
    for block in ir.root.blocks:
        for index, instruction in enumerate(block.instructions):
            for variant, form in enumerate(plan.instructions[instruction.id]["instruction_forms"]):
                if form[0] == "fuse":
                    follower = block.instructions[index + 1]
                    assert form[1] == follower.id
                    assert plan.instructions[follower.id]["instruction_forms"][variant] == ("operand", instruction.id)

    assert plan.instructions["f0:i2"]["delayed_materialization_candidate"]
    assert plan.values["f0:k0"]["integrity_encoding_candidate"]
    assert plan.values["f0:r0"]["state_threaded"] is True
    assert plan.dump() == planner.build(ir).dump()

    lowered = {}
    for name in ("classic", "karity", "mov"):
        backend = get_backend(name)
        item = backend.optimize(
            backend.lower(protect(ir, plan), BackendContext(options)),
            BackendContext(options),
        )
        lowered[name] = item
        assert item.semantic_ir is ir
        assert item.program.id == ir.root.id
        assert item.program.code[2].operation == "ADD"
        assert item.backend == name
        assert "handler-function f0" in item.dump()
        from obfuscator.vm.backends.handler_codec import serialize
        try:
            serialize(item.program)
        except ValueError as error:
            assert "concrete protection targets" in str(error)
        else:
            raise AssertionError("typed codec accepted an unplanned program")
    assert lowered["karity"].policy["graph_execution_rate"] == 0.5
    assert lowered["classic"].policy["graph_execution_rate"] == 0.0
    assert lowered["mov"].kind == "mov-micro-ir"
    assert lowered["mov"].resolution.is_active("multi_vm")
    assert not lowered["mov"].resolution.is_active("graph_execution")
    assert "fallback-disable graph_execution" in lowered["mov"].dump()
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
