"""Karity's explicit encoded-register and deferred-value lowering contract.

The runtime owns the concrete private banks.  This module mirrors the part of
that contract visible in physical handler IR: an ordinary ``rset`` leaves an
encoded register, a deferred arithmetic handler leaves a pending producer, and
the next read resolves that pending representation.  Deferred arithmetic may
resolve an operand through ``_pending_snapshot`` without native decoding, or
take a runtime-dependent ``rget`` fallback.  The model records those two
boundaries separately.  It is intentionally backend-local; semantic IR and
ProtectionPlan remain free of runtime-bank fields and source tokens.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable

from .handler_layout import PhysicalFunction
from .runtime_layout import iter_functions


class Representation(str, Enum):
    NATIVE = "native"
    ENCODED = "encoded"
    PENDING = "pending"
    MAYBE_PENDING = "maybe-pending"


@dataclass(frozen=True)
class RegisterState:
    representation: Representation
    epoch: int
    producer: int | None = None
    dependencies: tuple[int, ...] = ()
    producers: tuple[int, ...] = ()
    epochs: tuple[int, ...] = ()


@dataclass(frozen=True)
class GraphDependency:
    family: int
    site: int
    seed: int
    state_key: int
    policy: int
    registers: tuple[int, ...]
    epochs: tuple[tuple[int, tuple[int, ...]], ...]


@dataclass(frozen=True)
class KarityTransition:
    pc: int
    source_id: str
    operation: str
    reads: tuple[int, ...]
    writes: tuple[int, ...]
    captures: tuple[int, ...]
    boxes_created: tuple[int, ...]
    close_from: int | None
    pending_write: int | None
    pending_guard: tuple[str, ...]
    encoded_fast_path: bool
    resolved_pending: tuple[int, ...]
    materialized: tuple[int, ...]
    maybe_materialized: tuple[int, ...]
    native_inputs: tuple[RegisterState, ...]
    capture_states: tuple[RegisterState, ...]
    native_boundary: bool
    boundary_kind: str | None
    graph_sites: tuple[int, ...]
    graph_descriptors: tuple[tuple[int, int, int, int, int], ...]
    open_boxes: tuple[int, ...] = ()
    closed_registers: tuple[int, ...] = ()
    close_states: tuple[RegisterState, ...] = ()
    close_materialized: tuple[int, ...] = ()
    graph_dependencies: tuple[GraphDependency, ...] = ()
    reachable: bool = False


@dataclass(frozen=True)
class KarityFunctionState:
    function: str
    register_count: int
    transitions: tuple[KarityTransition, ...]


@dataclass(frozen=True)
class KarityState:
    functions: tuple[KarityFunctionState, ...]
    representation_routes: tuple[tuple[str, tuple[tuple[str, bool], ...]], ...]
    rotation_policy: tuple[tuple[str, object], ...]

    def occurrence_inventory(self) -> tuple[frozenset[int], frozenset[int]]:
        """Physical graph sites and their runtime families, including dead routes."""
        descriptors = (
            descriptor
            for function in self.functions
            for transition in function.transitions
            for descriptor in transition.graph_descriptors
        )
        pairs = tuple((family, site) for family, site, *_ in descriptors)
        return (frozenset(site for _, site in pairs),
                frozenset(family for family, _ in pairs))

    def dump(self) -> str:
        lines = [
            f"karity-routes {group} "
            + ",".join(f"{name}:{int(graph)}" for name, graph in routes)
            for group, routes in self.representation_routes
        ]
        policy = dict(self.rotation_policy)
        lines.append(
            f"karity-rotation boundaries={','.join(policy['boundaries'])} "
            f"initial-ticks={policy['initial_ticks']} period={policy['period']}"
        )
        for function in self.functions:
            transitions = function.transitions
            lines.append(
                f"karity-state {function.function} transitions={len(transitions)} "
                f"pending={sum(item.pending_write is not None for item in transitions)} "
                f"materializations={sum(len(item.materialized) for item in transitions)} "
                f"conditional-materializations={sum(len(item.maybe_materialized) for item in transitions)} "
                f"pending-resolutions={sum(len(item.resolved_pending) for item in transitions)} "
                f"encoded-fast-paths={sum(item.encoded_fast_path for item in transitions)} "
                f"native-values={sum(len(item.native_inputs) for item in transitions)} "
                f"native-boundaries={sum(item.native_boundary for item in transitions)} "
                f"graph-sites={sum(len(item.graph_sites) for item in transitions)}"
            )
            for transition in transitions:
                if not (transition.pending_write is not None or transition.materialized
                        or transition.native_boundary or transition.captures
                        or transition.closed_registers or transition.graph_dependencies):
                    continue
                native = tuple(
                    (register, value.representation.value, value.epochs,
                     value.producers or (() if value.producer is None else (value.producer,)))
                    for register, value in zip(transition.reads, transition.native_inputs)
                )
                captures = tuple(
                    (register, value.representation.value, value.epochs,
                     value.producers or (() if value.producer is None else (value.producer,)))
                    for register, value in zip(transition.captures, transition.capture_states)
                )
                graph_epochs = tuple(
                    (dependency.site, dependency.epochs)
                    for dependency in transition.graph_dependencies
                )
                lines.append(
                    f"karity-transition function={function.function} pc={transition.pc} "
                    f"source={transition.source_id} op={transition.operation} "
                    f"reads={transition.reads} writes={transition.writes} "
                    f"pending={transition.pending_write} guard={transition.pending_guard} "
                    f"encoded-fast-path={transition.encoded_fast_path} "
                    f"resolved-pending={transition.resolved_pending} "
                    f"materialized={transition.materialized} "
                    f"maybe-materialized={transition.maybe_materialized} "
                    f"native={native} captures={captures} "
                    f"close={transition.closed_registers} "
                    f"close-materialized={transition.close_materialized} "
                    f"boundary={transition.boundary_kind or '-'} "
                    f"graph-epochs={graph_epochs}"
                )
        return "\n".join(lines) + ("\n" if lines else "")


_DEFERRED_OPERATIONS = frozenset(("ADD", "SUB", "NEGATE"))
_LINEAR_OPERATIONS = _DEFERRED_OPERATIONS
_TERMINALS = frozenset(("RETURN", "TAIL_CALL"))
_CONDITIONALS = frozenset((
    "EQUAL", "LESS_THAN", "LESS_EQUAL", "TEST", "TEST_SET",
))
_BINARY_WRITES = frozenset((
    "ADD", "SUB", "MUL", "MOD", "POW", "DIV", "FLOOR_DIV",
    "BIT_AND", "BIT_OR", "BIT_XOR", "SHIFT_LEFT", "SHIFT_RIGHT",
))
_UNARY_WRITES = frozenset(("NEGATE", "BIT_NOT", "LOGICAL_NOT", "LENGTH"))
_BOUNDARY_KINDS = {
    # Calls may invoke a native function or suspend the surrounding coroutine
    # (notably through coroutine.yield); Lua 5.1 has no standalone YIELD opcode.
    "CALL": "call-or-yield",
    "TAIL_CALL": "tail-call-or-yield",
    "RETURN": "host-return",
    "GET_TABLE": "table-metamethod-read",
    "SET_TABLE": "table-metamethod-write",
    "GET_UPVALUE_TABLE": "upvalue-table-read",
    "SET_UPVALUE_TABLE": "upvalue-table-write",
    "GET_UPVALUE": "upvalue-read",
    "SET_UPVALUE": "upvalue-write",
    "SET_LIST": "table-list-write",
    "SELF": "table-metamethod-read",
    "ITER_CALL": "iterator-call-or-yield",
    "CLOSURE": "upvalue-capture",
    "GLOBAL_GET": "environment-read",
    "GLOBAL_SET": "environment-write",
    "ADD": "arithmetic-metamethod",
    "SUB": "arithmetic-metamethod",
    "MUL": "arithmetic-metamethod",
    "MOD": "arithmetic-metamethod",
    "POW": "arithmetic-metamethod",
    "DIV": "arithmetic-metamethod",
    "FLOOR_DIV": "arithmetic-metamethod",
    "BIT_AND": "arithmetic-metamethod",
    "BIT_OR": "arithmetic-metamethod",
    "BIT_XOR": "arithmetic-metamethod",
    "SHIFT_LEFT": "arithmetic-metamethod",
    "SHIFT_RIGHT": "arithmetic-metamethod",
    "NEGATE": "arithmetic-metamethod",
    "BIT_NOT": "arithmetic-metamethod",
    "LENGTH": "length-metamethod",
    "CONCAT": "concat-metamethod",
    "EQUAL": "comparison-metamethod",
    "LESS_THAN": "comparison-metamethod",
    "LESS_EQUAL": "comparison-metamethod",
}


def _boundary_kind(instruction) -> str | None:
    if instruction.operation == "JUMP" and instruction.a > 0:
        return "upvalue-close"
    return _BOUNDARY_KINDS.get(instruction.operation)


def _close_from(instruction) -> int | None:
    if instruction.operation == "JUMP" and instruction.a > 0:
        return instruction.a - 1
    if instruction.operation in {"TAIL_CALL", "RETURN"}:
        return 0
    return None


def _register(value: int) -> tuple[int, ...]:
    return (value,) if 0 <= value < 256 else ()


def _register_range(start: int, count: int, maximum: int) -> tuple[int, ...]:
    if count == 0:
        end = maximum - 1
    else:
        end = start + count - 1
    return tuple(index for index in range(start, end + 1) if 0 <= index < maximum)


def _operation_accesses(instruction, maximum: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return logical register reads/writes for the typed handler ABI."""
    operation, a, b, c = instruction.operation, instruction.a, instruction.b, instruction.c
    if operation == "MOVE": return _register(b), _register(a)
    if operation in {"LOAD_CONST", "LOAD_CONST_EXTENDED", "LOAD_BOOL", "NEW_TABLE", "CLOSURE", "GLOBAL_GET", "PACK_VARARG"}:
        return (), _register(a)
    if operation == "LOAD_NIL":
        return (), _register_range(a, b - a + 1, maximum)
    if operation == "GET_UPVALUE": return (), _register(a)
    if operation in {"GET_UPVALUE_TABLE", "GET_TABLE"}:
        return _register(b) + _register(c), _register(a)
    if operation == "SET_UPVALUE_TABLE":
        return _register(a) + _register(b) + _register(c), ()
    if operation in {"SET_UPVALUE", "GLOBAL_SET"}: return _register(a), ()
    if operation == "SET_TABLE": return _register(a) + _register(b) + _register(c), ()
    if operation == "SELF": return _register(b) + _register(c), _register(a) + _register(a + 1)
    if operation in _BINARY_WRITES:
        return _register(b) + _register(c), _register(a)
    if operation in _UNARY_WRITES: return _register(b), _register(a)
    if operation == "CONCAT":
        return _register_range(b, c - b + 1, maximum), _register(a)
    if operation in {"EQUAL", "LESS_THAN", "LESS_EQUAL"}:
        return _register(b) + _register(c), ()
    if operation == "TEST": return _register(a), ()
    if operation == "TEST_SET": return _register(b), _register(a)
    if operation in {"CALL", "TAIL_CALL"}:
        reads = _register_range(a, b, maximum)
        writes = () if operation == "TAIL_CALL" else _register_range(a, max(0, c - 1), maximum)
        return reads, writes
    if operation == "RETURN": return _register_range(a, b - 1, maximum), ()
    if operation in {"FOR_LOOP", "FOR_PREP"}:
        slots = _register_range(a, 4, maximum)
        return slots, slots
    if operation == "ITER_CALL":
        return _register_range(a, 3, maximum), _register_range(a + 3, c, maximum)
    if operation == "ITER_LOOP": return _register_range(a, 3, maximum), _register(a + 2)
    if operation == "SET_LIST":
        return _register(a) + _register_range(a + 1, b, maximum), ()
    if operation == "VARARG": return (), _register_range(a, b - 1, maximum)
    return (), ()


def _forms(function: PhysicalFunction, vm_map) -> tuple[dict[int, tuple[int, int]], set[int], set[int]]:
    _, splits, fuses, defers = vm_map
    split_parts = {
        vop: (part, len(values))
        for forms in splits.values() for values in forms.values()
        for part, vop in enumerate(values)
    }
    fused = {index for index, item in enumerate(function.code) if item.vop in fuses}
    internal = {index + 1 for index in fused if index + 1 < len(function.code)}
    deferred = set(defers.values())
    return split_parts, internal, deferred


def _successors(function: PhysicalFunction, index: int, internal: set[int]) -> tuple[int, ...]:
    instruction = function.code[index].instruction
    operation = instruction.operation
    size = len(function.code)
    next_pc = index + (2 if index + 1 in internal else 1)
    def valid(values: Iterable[int]) -> tuple[int, ...]:
        return tuple(sorted({value for value in values if 0 <= value < size and value not in internal}))
    if operation in _TERMINALS:
        return ()
    if operation in {"JUMP", "FOR_LOOP", "FOR_PREP", "ITER_LOOP"}:
        target = index + 1 + instruction.sbx
        if operation == "JUMP": return valid((target,))
        return valid((target, next_pc))
    if operation == "BLOCK_GOTO": return valid((instruction.bx,))
    if operation == "BLOCK_ROUTE":
        route = function.routes[instruction.a] if instruction.a < len(function.routes) else ()
        return valid(target - 1 for target in route)
    if operation in _CONDITIONALS:
        return valid((next_pc, index + 2))
    if operation == "LOAD_BOOL" and instruction.c:
        return valid((index + 2,))
    return valid((next_pc,))


def _merge(left: tuple[RegisterState, ...], right: tuple[RegisterState, ...]) -> tuple[RegisterState, ...]:
    result = []
    for first, second in zip(left, right):
        if first == second:
            result.append(first)
        elif ({first.representation, second.representation}
              & {Representation.PENDING, Representation.MAYBE_PENDING}):
            # A path-sensitive pending record is resolved by the generated
            # rget guard.  Preserve both producer epochs for validation.
            result.append(RegisterState(
                Representation.MAYBE_PENDING, max(first.epoch, second.epoch),
                dependencies=tuple(sorted(set(first.dependencies + second.dependencies))),
                producers=tuple(sorted(set(
                    first.producers + second.producers
                    + (() if first.producer is None else (first.producer,))
                    + (() if second.producer is None else (second.producer,))
                ))),
                epochs=tuple(sorted(set(
                    (first.epochs or (first.epoch,))
                    + (second.epochs or (second.epoch,))
                ))),
            ))
        else:
            result.append(RegisterState(
                Representation.ENCODED, max(first.epoch, second.epoch),
                epochs=tuple(sorted(set(
                    (first.epochs or (first.epoch,))
                    + (second.epochs or (second.epoch,))
                ))),
            ))
    return tuple(result)


def _capture_registers(function: PhysicalFunction, instruction) -> tuple[int, ...]:
    if instruction.operation != "CLOSURE":
        return ()
    child = instruction.bx
    if child >= len(function.source.protos):
        raise ValueError("Karity closure references a missing child function")
    maximum = function.source.max_stack_size
    return tuple(sorted({
        upvalue.idx for upvalue in function.source.protos[child].upvalues
        if upvalue.instack and 0 <= upvalue.idx < maximum
    }))


def _transfer(transition: KarityTransition, state: tuple[RegisterState, ...],
              open_boxes: frozenset[int]) -> tuple[
    tuple[RegisterState, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...],
    tuple[RegisterState, ...], tuple[RegisterState, ...], tuple[GraphDependency, ...],
    tuple[int, ...], tuple[RegisterState, ...], tuple[int, ...], frozenset[int]
]:
    values = list(state)
    closed_registers = tuple(sorted(
        register for register in open_boxes
        if transition.close_from is not None and register >= transition.close_from
    ))
    close_states = tuple(values[register] for register in closed_registers)
    close_materialized = tuple(
        register for register in closed_registers
        if values[register].representation in {Representation.PENDING, Representation.MAYBE_PENDING}
    )
    for register in close_materialized:
        current = values[register]
        values[register] = RegisterState(
            Representation.ENCODED, current.epoch,
            epochs=current.epochs or (current.epoch,),
        )
    native_inputs = tuple(
        RegisterState(Representation.NATIVE, values[register].epoch,
                      values[register].producer, values[register].dependencies,
                      values[register].producers,
                      values[register].epochs or (values[register].epoch,))
        for register in transition.reads
    )
    capture_states = tuple(values[register] for register in transition.captures)
    graph_dependencies = tuple(
        GraphDependency(
            family, site, seed, state_key, policy,
            transition.reads,
            tuple((register, values[register].epochs or (values[register].epoch,))
                  for register in transition.reads),
        )
        for family, site, seed, state_key, policy in transition.graph_descriptors
    )
    read_registers = tuple(dict.fromkeys(transition.reads))
    resolved_pending = tuple(
        register for register in read_registers
        if values[register].representation in {Representation.PENDING, Representation.MAYBE_PENDING}
    )
    # Deferred snapshots and direct linear arithmetic both finish pending
    # producers into encoded storage first. Their integer fast paths may then
    # avoid rget; only the native fallback decodes those operands.
    maybe_materialized = resolved_pending if transition.encoded_fast_path else ()
    materialized = resolved_pending if not transition.encoded_fast_path else ()
    for register in resolved_pending:
        current = values[register]
        values[register] = RegisterState(
            Representation.ENCODED, current.epoch,
            epochs=current.epochs or (current.epoch,),
        )
    for register in transition.writes:
        if register == transition.pending_write:
            values[register] = RegisterState(
                Representation.MAYBE_PENDING, transition.pc + 1,
                producer=transition.pc, dependencies=transition.reads,
                producers=(transition.pc,), epochs=(transition.pc + 1,),
            )
        else:
            values[register] = RegisterState(
                Representation.ENCODED, transition.pc + 1,
                epochs=(transition.pc + 1,),
            )
    boxes_after = (open_boxes | frozenset(transition.boxes_created)) - frozenset(closed_registers)
    return (
        tuple(values), resolved_pending, materialized, maybe_materialized, native_inputs,
        capture_states, graph_dependencies, closed_registers, close_states,
        close_materialized, boxes_after,
    )


def _function_state(function: PhysicalFunction, vm_map) -> KarityFunctionState:
    split_parts, internal, deferred = _forms(function, vm_map)
    aliases = vm_map[0]
    transitions: list[KarityTransition] = []
    for pc, item in enumerate(function.code):
        reads, writes = _operation_accesses(item.instruction, function.source.max_stack_size)
        captures = _capture_registers(function, item.instruction)
        split = split_parts.get(item.vop)
        if split is not None and split[0] != split[1] - 1:
            writes = ()
        # A deferred opcode with an active graph cannot take the lazy branch:
        # _defer1r/_defer2r fall through to native arithmetic and rset.
        ungraphed = not item.graph_sites or item.graph_sites[0][0] == 0
        pending_write = (
            writes[0] if (item.vop in deferred
                          and item.instruction.operation in _DEFERRED_OPERATIONS
                          and writes and ungraphed) else None
        )
        pending_guard = (
            ("all-inputs-integer-kind", "runtime-poly-lazy")
            if pending_write is not None else ()
        )
        direct_linear = (
            item.instruction.operation in _LINEAR_OPERATIONS
            and item.vop in aliases.get(item.instruction.op, ())
        )
        encoded_fast_path = (
            (pending_write is not None or direct_linear)
            and ungraphed
        )
        boxes_created = tuple(sorted(set(
            captures + (_register(item.instruction.a) if item.instruction.operation == "CLOSURE" else ())
        )))
        close_from = _close_from(item.instruction)
        boundary_kind = _boundary_kind(item.instruction)
        graph_descriptors = tuple(item.graph_sites)
        transitions.append(KarityTransition(
            pc=pc,
            source_id=item.instruction.source_id,
            operation=item.instruction.operation,
            reads=reads,
            writes=writes,
            captures=captures,
            boxes_created=boxes_created,
            close_from=close_from,
            pending_write=pending_write,
            pending_guard=pending_guard,
            encoded_fast_path=encoded_fast_path,
            resolved_pending=(),
            materialized=(),
            maybe_materialized=(),
            native_inputs=(),
            capture_states=(),
            native_boundary=boundary_kind is not None,
            boundary_kind=boundary_kind,
            graph_sites=tuple(site for _, site, _, _, _ in graph_descriptors),
            graph_descriptors=graph_descriptors,
        ))

    initial = tuple(RegisterState(Representation.ENCODED, 0, epochs=(0,))
                    for _ in range(function.source.max_stack_size))
    incoming: dict[int, tuple[RegisterState, ...]] = {0: initial} if transitions else {}
    incoming_boxes: dict[int, frozenset[int]] = {0: frozenset()} if transitions else {}
    worklist = [0] if transitions else []
    completed = list(transitions)
    while worklist:
        pc = worklist.pop()
        if pc in internal:
            continue
        (output, resolved_pending, materialized, maybe_materialized, native_inputs,
         capture_states, graph_dependencies, closed_registers, close_states,
         close_materialized, boxes_after) = _transfer(
            completed[pc], incoming[pc], incoming_boxes[pc]
        )
        completed[pc] = replace(
            completed[pc], resolved_pending=resolved_pending,
            materialized=materialized, maybe_materialized=maybe_materialized,
            native_inputs=native_inputs,
            capture_states=capture_states, graph_dependencies=graph_dependencies,
            open_boxes=tuple(sorted(incoming_boxes[pc])),
            closed_registers=closed_registers, close_states=close_states,
            close_materialized=close_materialized, reachable=True,
        )
        for successor in _successors(function, pc, internal):
            previous = incoming.get(successor)
            previous_boxes = incoming_boxes.get(successor)
            merged = output if previous is None else _merge(previous, output)
            merged_boxes = boxes_after if previous_boxes is None else previous_boxes | boxes_after
            if previous is None or previous != merged or previous_boxes != merged_boxes:
                incoming[successor] = merged
                incoming_boxes[successor] = merged_boxes
                worklist.append(successor)
    return KarityFunctionState(
        function.source.id, function.source.max_stack_size, tuple(completed)
    )


def lower_state(layout, representation_routes, rotation_policy) -> KarityState:
    if representation_routes is None:
        raise ValueError("Karity lowered state requires planned representation routes")
    if rotation_policy is None:
        raise ValueError("Karity lowered state requires planned runtime rotation policy")
    return KarityState(
        tuple(
            _function_state(function, layout.vm_maps[function.vm_id])
            for function in iter_functions(layout.functions)
        ),
        tuple((group, tuple((name, route) for name, route in routes))
              for group, routes in representation_routes),
        tuple(sorted(rotation_policy.items())),
    )


def _validate_producers(function: KarityFunctionState, register: int,
                        value: RegisterState) -> set[int]:
    producers = set(value.producers)
    if value.producer is not None:
        producers.add(value.producer)
    for producer in producers:
        if not 0 <= producer < len(function.transitions):
            raise ValueError("Karity pending producer is outside its function")
        if function.transitions[producer].pending_write != register:
            raise ValueError("Karity pending producer does not write its referenced register")
    return producers


def validate_state(lowered) -> None:
    actual = lowered.backend_data.get("karity_state")
    if not isinstance(actual, KarityState):
        raise ValueError("Karity lowered state is missing")
    seen_sites: set[int] = set()
    for function in actual.functions:
        for pc, transition in enumerate(function.transitions):
            if transition.pc != pc:
                raise ValueError("Karity transition program counters are inconsistent")
            if any(not 0 <= register < function.register_count
                   for register in (*transition.reads, *transition.writes, *transition.captures,
                                    *transition.boxes_created, *transition.open_boxes,
                                    *transition.closed_registers)):
                raise ValueError("Karity transition references an invalid register")
            if tuple(sorted(set(transition.boxes_created))) != transition.boxes_created:
                raise ValueError("Karity closure box creation set is invalid")
            if tuple(sorted(set(transition.open_boxes))) != transition.open_boxes:
                raise ValueError("Karity open-upvalue state is invalid")
            expected_closed = tuple(
                register for register in transition.open_boxes
                if transition.close_from is not None and register >= transition.close_from
            )
            if transition.closed_registers != expected_closed:
                raise ValueError("Karity upvalue-close boundary differs from open boxes")
            if len(transition.close_states) != len(transition.closed_registers):
                raise ValueError("Karity upvalue-close state is incomplete")
            expected_close_materialized = tuple(
                register for register, value in zip(
                    transition.closed_registers, transition.close_states
                )
                if value.representation in {Representation.PENDING, Representation.MAYBE_PENDING}
            )
            if transition.close_materialized != expected_close_materialized:
                raise ValueError("Karity upvalue close failed to materialize a pending value")
            if transition.pending_write is not None:
                if transition.operation not in _DEFERRED_OPERATIONS:
                    raise ValueError("Karity pending producer has an unsupported operation")
                if (transition.graph_descriptors
                        and transition.graph_descriptors[0][0] != 0):
                    raise ValueError("Karity graphed deferred handler cannot leave a pending value")
                if transition.pending_write not in transition.writes:
                    raise ValueError("Karity pending producer does not write its destination")
                if transition.pending_guard != ("all-inputs-integer-kind", "runtime-poly-lazy"):
                    raise ValueError("Karity pending producer is missing its runtime guard")
            if any(register not in transition.reads for register in transition.materialized):
                raise ValueError("Karity materialization is not backed by an rget use")
            if len(set(transition.materialized)) != len(transition.materialized):
                raise ValueError("Karity register materialization is duplicated")
            if any(register not in transition.reads for register in transition.resolved_pending):
                raise ValueError("Karity pending resolution is not backed by an operand read")
            if len(set(transition.resolved_pending)) != len(transition.resolved_pending):
                raise ValueError("Karity pending resolution is duplicated")
            if any(register not in transition.reads for register in transition.maybe_materialized):
                raise ValueError("Karity conditional materialization is not backed by an operand read")
            if len(set(transition.maybe_materialized)) != len(transition.maybe_materialized):
                raise ValueError("Karity conditional materialization is duplicated")
            if set(transition.materialized) & set(transition.maybe_materialized):
                raise ValueError("Karity materialization cannot be both definite and conditional")
            if any(register not in transition.resolved_pending
                   for register in (*transition.materialized, *transition.maybe_materialized)):
                raise ValueError("Karity materialization does not resolve a pending input")
            if (transition.maybe_materialized and not transition.encoded_fast_path):
                raise ValueError("Karity conditional materialization has no encoded fast path")
            if (transition.encoded_fast_path
                    and (transition.operation not in _LINEAR_OPERATIONS
                         or (transition.graph_descriptors
                             and transition.graph_descriptors[0][0] != 0))):
                raise ValueError("Karity encoded fast path has an invalid operation or graph route")
            if transition.reachable and len(transition.native_inputs) != len(transition.reads):
                raise ValueError("Karity reachable transition is missing native inputs")
            if (any(value.representation is not Representation.NATIVE
                    for value in transition.native_inputs)):
                raise ValueError("Karity native materialization contract is invalid")
            for register, value in zip(transition.reads, transition.native_inputs):
                producers = _validate_producers(function, register, value)
                if producers and register not in transition.resolved_pending:
                    raise ValueError("Karity pending input escaped resolution")
                if producers and register not in (*transition.materialized, *transition.maybe_materialized):
                    raise ValueError("Karity pending input escaped materialization")
            if transition.reachable and len(transition.capture_states) != len(transition.captures):
                raise ValueError("Karity closure capture state is incomplete")
            for register, value in zip(transition.captures, transition.capture_states):
                _validate_producers(function, register, value)
            for register, value in zip(transition.closed_registers, transition.close_states):
                producers = _validate_producers(function, register, value)
                if producers and register not in transition.close_materialized:
                    raise ValueError("Karity upvalue close left a pending producer unresolved")
            if (not transition.reachable
                    and (transition.native_inputs or transition.capture_states or transition.resolved_pending
                         or transition.materialized or transition.maybe_materialized
                         or transition.graph_dependencies or transition.open_boxes
                         or transition.closed_registers or transition.close_states
                         or transition.close_materialized)):
                raise ValueError("Karity unreachable transition contains dataflow state")
            if transition.close_from is not None and not 0 <= transition.close_from <= function.register_count:
                raise ValueError("Karity upvalue-close threshold is invalid")
            if ((transition.operation == "JUMP" and transition.close_from is not None)
                    != (transition.boundary_kind == "upvalue-close")):
                raise ValueError("Karity upvalue-close boundary classification is invalid")
            if transition.native_boundary != (transition.boundary_kind is not None):
                raise ValueError("Karity native boundary classification is invalid")
            if tuple(site for _, site, _, _, _ in transition.graph_descriptors) != transition.graph_sites:
                raise ValueError("Karity graph dependency descriptors are inconsistent")
            expected_graphs = len(transition.graph_descriptors) if transition.reachable else 0
            if len(transition.graph_dependencies) != expected_graphs:
                raise ValueError("Karity graph dependency state is incomplete")
            for dependency, descriptor in zip(
                    transition.graph_dependencies, transition.graph_descriptors):
                if (dependency.family, dependency.site, dependency.seed,
                        dependency.state_key, dependency.policy) != descriptor:
                    raise ValueError("Karity graph dependency differs from its physical descriptor")
                if dependency.registers != transition.reads:
                    raise ValueError("Karity graph dependency lost an operation input")
                expected_epochs = tuple(
                    (register, value.epochs)
                    for register, value in zip(transition.reads, transition.native_inputs)
                )
                if dependency.epochs != expected_epochs:
                    raise ValueError("Karity graph dependency has a stale representation epoch")
            for value in (*transition.native_inputs, *transition.capture_states,
                          *transition.close_states):
                if not value.epochs or value.epoch != max(value.epochs):
                    raise ValueError("Karity representation epoch summary is invalid")
                if tuple(sorted(set(value.epochs))) != value.epochs:
                    raise ValueError("Karity representation epoch alternatives are invalid")
                if any(not 0 <= register < function.register_count
                       for register in value.dependencies):
                    raise ValueError("Karity pending dependency register is invalid")
            if any(site in seen_sites for site in transition.graph_sites):
                raise ValueError("Karity graph dependency site is duplicated")
            seen_sites.update(transition.graph_sites)

    sites, families = actual.occurrence_inventory()
    if sites != lowered.backend_data["layout"].graph_sites:
        raise ValueError("Karity graph inventory differs from physical layout")
    if any(not 0 <= family <= 8 for family in families):
        raise ValueError("Karity graph family is outside the runtime bank")

    # Validate the projection's own transition contracts before checking that
    # it is a fresh snapshot.  Otherwise every malformed state fails only the
    # equality check below and the more useful invariants above are unreachable.
    root = lowered.protection_plan.functions[lowered.semantic_ir.root.id]
    expected = lower_state(
        lowered.backend_data["layout"], root["representation_routes"],
        root["runtime_rotation_policy"],
    )
    if actual != expected:
        raise ValueError("Karity lowered state differs from physical layout or protection plan")
