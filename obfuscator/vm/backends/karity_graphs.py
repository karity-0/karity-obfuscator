"""Karity-owned graph compilers, route emission and seeded DAG encoding."""
from __future__ import annotations

from obfuscator.names import NameAllocator
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import random as _random_module
import re


_GRAPH_ENCODING_RNG: ContextVar[_random_module.Random | None] = ContextVar(
    "karity_graph_encoding_rng", default=None,
)


class _GraphRandom:
    """Use an isolated stream only while rendering Karity graph encodings."""

    def __getattr__(self, name):
        return getattr(_GRAPH_ENCODING_RNG.get() or _random_module, name)


random = _GraphRandom()


@contextmanager
def karity_graph_encoding(plan):
    """Keep graph-DAG encoding independent of unrelated emitter RNG use.

    The protection plan fixes selected semantic sites and routes.  Its stable
    dump seeds only equivalent backend encodings, not new protection policy.
    """
    digest = hashlib.blake2b(
        plan.dump().encode("utf-8"), digest_size=16, person=b"karity-graphs",
    ).digest()
    token = _GRAPH_ENCODING_RNG.set(
        _random_module.Random(int.from_bytes(digest, "little"))
    )
    try:
        yield
    finally:
        _GRAPH_ENCODING_RNG.reset(token)




def _hex64() -> str:
    return f"0x{random.getrandbits(64):016X}"


def _exact_graph_source(source: str) -> str:
    return "--[[KARITY_EXACT_BEGIN]]" + source + "--[[KARITY_EXACT_END]]"


def _target_user_expression(source: str) -> str:
    """Keep a user-value expression in the target language's native semantics."""
    return ("(--<<TARGET_USER_EXPRESSION>>\n" + source +
            "\n--<<ENDTARGET_USER_EXPRESSION>>\n)")


def _target_user_statement(source: str) -> str:
    """Keep a complete user-value statement native while staging valid Lua."""
    return ("--<<TARGET_USER_STATEMENT>>\n" + source +
            "\n--<<ENDTARGET_USER_STATEMENT>>\n")


def _target_private_expression(source: str) -> str:
    """Mark one exact protection-state expression for target lowering."""
    return ("(--<<TARGET_PRIVATE_EXPRESSION>>\n" + source +
            "\n--<<ENDTARGET_PRIVATE_EXPRESSION>>\n)")


def _target_private_mod_expression(source: str, divisor: str) -> str:
    """Reduce one exact private word to a native positive-modulus result."""
    return ("(--<<TARGET_PRIVATE_MOD_EXPRESSION>>\n(" + source + ")%(" + divisor + ")" +
            "\n--<<ENDTARGET_PRIVATE_MOD_EXPRESSION>>\n)")


def _target_private_low_expression(source: str, modulus: int) -> str:
    """Extract power-of-two low bits as a native target number."""
    if modulus <= 0 or modulus & (modulus - 1):
        raise ValueError("private low expression modulus must be a power of two")
    return (f"(--<<TARGET_PRIVATE_LOW_EXPRESSION:{modulus}>>\n"
            f"(({source})&{modulus - 1})"
            "\n--<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>\n)")


def _opaque_zero(x: str, y: str) -> str:
    forms = [
        f"({x}&(~{x}))",
        f"({x}~{x})",
        f"({y}&(~{y}))",
        f"({y}~{y})",
        f"(({x}|(~{x}))+1)",
        f"(({y}|(~{y}))+1)",
        f"(({x}~{x})&{_hex64()})",
        f"(({y}&(~{y}))<<{random.randint(1, 31)})",
    ]
    return random.choice(forms)


def _integer_base_expr(kind: str, x: str, y: str) -> str:
    and_xy = f"({x}&{y})"
    xor_xy = f"({x}~{y})"
    or_xy = random.choice([
        f"({x}|{y})",
        f"(~((~{x})&(~{y})))",
        f"(({x}~{y})|({x}&{y}))",
    ])
    forms_by_kind = {
        "ADD": [
            f"({xor_xy}+({and_xy}<<1))",
            f"({or_xy}+{and_xy})",
            f"(({or_xy}<<1)-{xor_xy})",
            f"(({or_xy}+({and_xy}&{or_xy}))+{_opaque_zero(x, y)})",
        ],
        "SUB": [
            f"({x}+(~{y})+1)",
            f"(({x}~{y})-(((~{x})&{y})<<1))",
            f"(({x}+((~{y})|0))+1+{_opaque_zero(x, y)})",
        ],
        "MUL": [
            f"(({x}*{y})+{_opaque_zero(x, y)})",
            f"((({x}+{_opaque_zero(x, y)})*({y}+{_opaque_zero(x, y)})))",
        ],
        "BAND": [f"(~((~{x})|(~{y})))", f"({or_xy}-{xor_xy})"],
        "BOR": [f"(~((~{x})&(~{y})))", f"({xor_xy}+{and_xy})"],
        "BXOR": [f"({or_xy}-{and_xy})", f"(({x}|{y})&(~({x}&{y})))"],
        "SHL": [f"({x}<<({y}+{_opaque_zero(x, y)}))"],
        "SHR": [f"({x}>>({y}+{_opaque_zero(x, y)}))"],
        "UNM": [f"((~{x})+1)", f"(0-{x}+{_opaque_zero(x, y)})"],
        "BNOT": [f"(-{x}-1)", f"({x}~(-1))"],
    }
    forms = forms_by_kind[kind]
    return random.choice(forms)


def _wrap_identity(expr: str, x: str, y: str, allow_rot: bool = True) -> tuple[str, bool]:
    kinds = ["add", "sub", "xor", "zero_l", "zero_r"]
    if allow_rot and len(expr) < 360:
        kinds.append("rot")
    kind = random.choice(kinds)
    if kind == "add":
        k = _hex64()
        return f"(({expr}+{k})-{k})", False
    if kind == "sub":
        k = _hex64()
        return f"(({expr}-{k})+{k})", False
    if kind == "xor":
        k = _hex64()
        return f"(({expr}~{k})~{k})", False
    if kind == "rot":
        s = random.randint(1, 63)
        rs = 64 - s
        r = f"(({expr}<<{s})|({expr}>>{rs}))"
        return f"(({r}<<{rs})|({r}>>{s}))", True
    if kind == "zero_l":
        return f"({expr}+{_opaque_zero(x, y)})", False
    return f"({_opaque_zero(x, y)}+{expr})", False


def _make_integer_expr(kind: str, x: str = "x", y: str = "y") -> str:
    expr = _integer_base_expr(kind, x, y)
    used_rot = False
    for _ in range(random.randint(4, 8)):
        nxt, was_rot = _wrap_identity(expr, x, y, allow_rot=not used_rot)
        if len(nxt) > 3600:
            break
        expr = nxt
        used_rot = used_rot or was_rot
    return expr


def _random_topological_order(nodes: dict[int, dict], label: str) -> list[int]:
    """Compile-time scheduling for DAG graphs; no runtime node dispatcher remains."""
    indegree = {node_id: len(node["deps"]) for node_id, node in nodes.items()}
    children = {node_id: [] for node_id in nodes}
    for node_id, node in nodes.items():
        for dep in node["deps"]:
            if dep not in nodes:
                raise RuntimeError(
                    f"generated {label} graph node {node_id} references missing dependency {dep}"
                )
            children[dep].append(node_id)
    ready = [node_id for node_id, degree in indegree.items() if degree == 0]
    order: list[int] = []
    while ready:
        node_id = ready.pop(random.randrange(len(ready)))
        order.append(node_id)
        for child in children[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(order) != len(nodes):
        blocked = tuple(node_id for node_id, degree in indegree.items() if degree)
        raise RuntimeError(f"generated {label} graph contains a cycle; blocked nodes {blocked}")
    return order


def _compile_integer_graph_func(
    op_kind: str,
    preserve_native_numbers: bool = False,
    private_state_native: bool = False,
) -> str:
    """Compile an arithmetic DAG into one specialized straight-line handler."""
    name_allocator = NameAllocator(readable=True)
    a, b, state, slots, regs, active, boxes = [name_allocator.allocate("helper") for _ in range(7)]
    trace = name_allocator.allocate("helper")
    state_key = random.randint(700, 1200)
    nodes: dict[int, dict] = {}

    def add_node(kind: str, deps: list[int]) -> int:
        node_id = len(nodes)
        nodes[node_id] = {"kind": kind, "deps": tuple(dict.fromkeys(deps))}
        return node_id

    core = add_node("core", [])
    zeros: list[int] = []
    for _ in range(random.randint(8, 12)):
        deps = random.sample(zeros, min(len(zeros), random.randint(0, 2)))
        zeros.append(add_node("zero", deps))
    value = core
    for i in range(random.randint(max(12, len(zeros)), 18)):
        deps = [value, zeros[i % len(zeros)]]
        if random.random() < 0.45:
            deps.append(random.choice(zeros))
        value = add_node("identity", deps)
    sink = add_node("sink", [value, *random.sample(zeros, 2)])

    order = _random_topological_order(nodes, op_kind)
    names = {node_id: name_allocator.allocate("helper") for node_id in nodes}
    native_operation = (
        preserve_native_numbers and op_kind in {"ADD", "SUB", "MUL", "UNM"}
    )
    # Lua 5.1's Karity asset keeps user arithmetic as ordinary binary64
    # operations, but its graph bookkeeping and bitwise graph routes need an
    # exact private-word result.  Keep that decision at this code-generation
    # boundary: a target must never rediscover the graph's value domain by
    # translating the completed VM function.
    native_private_operation = private_state_native and not native_operation
    native_exact_state = native_operation or native_private_operation
    trace_seed = (
        f"{_hex64()}~({state}[611] or 0)"
        if native_exact_state
        else f"({a}~{b})~{_hex64()}~({state}[611] or 0)"
    )
    trace_initialization = (
        _target_private_expression(trace_seed) if native_exact_state else f"({trace_seed})"
    )
    lines = [
        f"function({a},{b},{state},{slots},{regs},{active},{boxes})",
        f"{state}={state} or {{}};{active}={active} or {{}};",
        "local " + ",".join(names.values()) + ";",
        f"local {trace}={trace_initialization};",
    ]
    for node_id in order:
        node = nodes[node_id]
        name = names[node_id]
        deps = [names[dep] for dep in node["deps"]]
        if node["kind"] == "core":
            if native_operation:
                operator = {"ADD": "+", "SUB": "-", "MUL": "*"}.get(op_kind)
                expression = f"(-{a})" if op_kind == "UNM" else f"({a}{operator}{b})"
                lines.append(
                    f"{name}={_target_user_expression(expression)};"
                    f"{trace}={_target_private_expression(f'{trace}~{node_id + 1}')};"
                )
            elif native_private_operation:
                # The result is exposed to the normal handler ABI, while the
                # opaque route expression itself remains an exact word.  The
                # explicit boundary avoids reintroducing the old generic
                # target helper for bitwise graph operations.
                expression = _target_private_expression(
                    _make_integer_expr(op_kind, a, b)
                )
                lines.append(
                    f"{name}=_source_value({expression});"
                    f"{trace}={_target_private_expression(f'{trace}~{node_id + 1}')};"
                )
            else:
                lines.append(
                    f"{name}={_make_integer_expr(op_kind, a, b)};"
                    f"{trace}=({trace}~({name}|(~{name})));"
                )
        elif node["kind"] == "zero":
            if native_exact_state:
                lines.append(
                    f"{name}=0;"
                    f"{trace}={_target_private_expression(f'{trace}~{node_id + 1}')};"
                    f"{state}[{state_key}]="
                    f"{_target_private_expression(f'({state}[{state_key}] or 0)~{trace}')};"
                )
            else:
                terms = deps or [a, b]
                joined = "~".join(f"(({term})~({term}))" for term in terms)
                lines.append(
                    f"{name}=({joined});{trace}=(({trace}~{name})~"
                    f"(({state}[{state_key}] or 0)&{name}));"
                    f"{state}[{state_key}]=(({state}[{state_key}] or 0)~{trace}~{name});"
                )
        elif node["kind"] == "identity":
            source = deps[0]
            zero_expr = "+".join(deps[1:])
            if native_exact_state:
                lines.append(
                    f"{name}={source};"
                    f"{trace}={_target_private_expression(f'{trace}~{node_id + 1}')};"
                )
            else:
                mode = random.randrange(3)
                if mode == 0:
                    mask = _hex64()
                    expr = f"((({source}~{mask})~{mask})+({zero_expr}))"
                elif mode == 1:
                    key = _hex64()
                    expr = f"((({source}+{key})-{key})+({zero_expr}))"
                else:
                    expr = f"(({source})+({zero_expr})+(({trace}~{trace})))"
                lines.append(
                    f"{name}={expr};{trace}=({trace}~({name}&{name})~({zero_expr}));"
                )
        else:
            if native_exact_state:
                lines.append(
                    f"{name}={deps[0]};"
                    f"{trace}={_target_private_expression(f'{trace}~{node_id + 1}')};"
                )
            else:
                lines.append(
                    f"{name}=({deps[0]})+({deps[1]})+({deps[2]});"
                    f"{trace}=({trace}~{name}~({name}<<1));"
                )

    index, slot, mixed = [name_allocator.allocate("helper") for _ in range(3)]
    out = names[sink]
    mixed_source = trace if native_operation else f"{out}~{trace}"
    mixed_expression = f"{mixed_source}~(({index}*{_hex64()})&-1)"
    state_expression = f"({state}[{state_key}] or 0)~{mixed}~{slot}"
    if native_exact_state:
        mixed_expression = _target_private_expression(mixed_expression)
        state_expression = _target_private_expression(state_expression)
    else:
        mixed_expression = f"({mixed_expression})"
        state_expression = f"({state_expression})"
    lines.extend([
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];",
        f"if not {boxes}[{slot}] then local {mixed}={mixed_expression};"
        f"{regs}({slot},{mixed});",
        f"{active}[{slot}]=true;{state}[{state_key}]={state_expression} "
        f"end end end;return {out} end",
    ])
    result = "".join(lines)
    if not native_exact_state:
        return ("--<<TARGET_PRIVATE_GRAPH>>\n" + result +
                "\n--<<ENDTARGET_PRIVATE_GRAPH>>\n")
    return result


def _compile_value_graph_func() -> str:
    """Compile a value diffusion DAG without runtime closures or memo tables."""
    name_allocator = NameAllocator(readable=True)
    value, state, slots, regs, active, boxes, tag = [name_allocator.allocate("helper") for _ in range(7)]
    nodes: dict[int, dict] = {0: {"kind": "source", "deps": ()}}
    zeros: list[int] = []
    for _ in range(random.randint(7, 11)):
        deps = random.sample(zeros, min(len(zeros), random.randint(0, 2)))
        node_id = len(nodes)
        nodes[node_id] = {"kind": "zero", "deps": tuple(deps)}
        zeros.append(node_id)
    current = 0
    for i in range(random.randint(10, 16)):
        deps = [current, zeros[i % len(zeros)]]
        if random.random() < 0.4:
            deps.append(random.choice(zeros))
        node_id = len(nodes)
        nodes[node_id] = {"kind": "identity", "deps": tuple(dict.fromkeys(deps))}
        current = node_id
    sink = len(nodes)
    nodes[sink] = {"kind": "sink", "deps": (current, *random.sample(zeros, 2))}

    names = {node_id: name_allocator.allocate("helper") for node_id in nodes}
    trace = name_allocator.allocate("helper")
    state_key = random.randint(1201, 1700)
    lines = [
        f"function({value},{state},{slots},{regs},{active},{boxes},{tag})",
        "local " + ",".join(names.values()) + ";",
        f"local {trace}={_target_private_expression(f'({state}[611] or 0)~{tag}~{_hex64()}')};",
    ]
    for node_id in _random_topological_order(nodes, "value"):
        node = nodes[node_id]
        name = names[node_id]
        deps = [names[dep] for dep in node["deps"]]
        if node["kind"] == "source":
            lines.append(f"{name}={value};")
        elif node["kind"] == "zero":
            source = "+".join(deps) if deps else f"({tag}~{tag})"
            lines.append(
                f"{name}={_target_private_expression(source)};"
                f"{name}={_target_private_expression(f'{name}~{name}')};"
                f"{trace}={_target_private_expression(f'{trace}~{name}~({tag}&0xFF)')};"
            )
        else:
            zero_expr = "+".join(deps[1:])
            lines.append(
                f"{name}={deps[0]};"
                f"{trace}={_target_private_expression(f'{trace}~({zero_expr})~({tag}&0xFF)')};"
            )
    out = names[sink]
    index, slot, mixed = [name_allocator.allocate("helper") for _ in range(3)]
    lines.extend([
        f"{state}[{state_key}]={_target_private_expression(f'({state}[{state_key}] or 0)~{trace}~{tag}')};",
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];",
        f"if not {boxes}[{slot}] then local {mixed}="
        f"{_target_private_expression(f'{trace}~{tag}~(({index}*{_hex64()})&-1)')};"
        f"{regs}({slot},{mixed});{active}[{slot}]=true;",
        f"{state}[{state_key}]={_target_private_expression(f'({state}[{state_key}] or 0)~{mixed}~{slot}')} "
        f"end end end;",
        f"return {out} end",
    ])
    return "".join(lines)


def _graph_edge(label: str, *, native_control: bool) -> str:
    return f"return {label}()" if native_control else f"goto {label}"


def _compiled_label_blocks(
    entry: str, blocks: list[tuple[str, str]], *, native_control: bool = False,
) -> str:
    """Lay graph blocks out randomly while preserving explicit build-time edges."""
    shuffled = list(blocks)
    random.shuffle(shuffled)
    if native_control:
        # Lua 5.1 has no goto. Each scoped block is an explicitly linked
        # tail-call node; declaration before assignment permits forward edges.
        names = ",".join(label for label, _ in shuffled)
        functions = ";".join(
            f"{label}=function() {body} end" for label, body in shuffled
        )
        return f"do local {names};{functions};return {entry}() end;"
    return f"goto {entry};" + "".join(
        f"::{label}::do {body} end;" for label, body in shuffled
    )


def _compile_call_route_func(*, native_control: bool = False) -> str:
    name_allocator = NameAllocator(readable=True)
    terminal, query = [name_allocator.allocate("helper") for _ in range(2)]
    count = random.randint(14, 22)
    labels = [name_allocator.allocate("helper") for _ in range(count)]
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            flow_expr = _target_private_expression(
                f"{query}[__VM_Q_TRACE__]~({query}[__VM_Q_FLOW__] or 0)"
            )
            ledger_expr = _target_private_expression(
                f"((d[1] or 0)~{query}[__VM_Q_TRACE__])&-1"
            )
            body = (
                f"{query}[__VM_Q_FLOW__]={flow_expr};"
                f"local d={query}[__VM_Q_LEDGER__];"
                f"if d then d[1]={ledger_expr} end;"
                f"return {terminal}({query})"
            )
        elif i == 0:
            salt = _hex64()
            trace_expr = _target_private_expression(
                f"({query}[__VM_Q_TRACE__]~{salt})&-1"
            )
            body = (
                f"{query}[__VM_Q_TRACE__]={trace_expr};"
                f"{_graph_edge(labels[1], native_control=native_control)}"
            )
        elif i == 1:
            salt = _hex64()
            trace_expr = _target_private_expression(
                f"(({query}[__VM_Q_TRACE__]+{salt})~{query}[__VM_Q_KIND__])&-1"
            )
            body = (
                f"{query}[__VM_Q_TRACE__]={trace_expr};"
                f"if {_target_user_expression(f'{query}[__VM_Q_BUDGET__]>0')} then "
                f"{query}[__VM_Q_BUDGET__]="
                f"{_target_user_expression(f'{query}[__VM_Q_BUDGET__]-1')};"
                f"{_graph_edge(labels[0], native_control=native_control)} end;"
                f"{_graph_edge(labels[2], native_control=native_control)}"
            )
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + random.randint(2, 5)))
            salt = _hex64()
            trace_expr = _target_private_expression(
                f"(({query}[__VM_Q_TRACE__]~{salt})+{i + 1})&-1"
            )
            branch_expr = _target_private_expression(
                f"(({query}[__VM_Q_TRACE__]~{query}[__VM_Q_KIND__]~{salt})&1)==0"
            )
            body = (
                f"{query}[__VM_Q_TRACE__]={trace_expr};"
                f"if {branch_expr} "
                f"then {_graph_edge(labels[primary], native_control=native_control)} end;"
                f"{_graph_edge(labels[alternate], native_control=native_control)}"
            )
        blocks.append((label, body))
    seed = _hex64()
    initial_trace = _target_private_expression(
        f"{query}[__VM_Q_KIND__]~{seed}"
    )
    budget_low = _target_private_low_expression(
        f"{query}[__VM_Q_KIND__]~{seed}", 4
    )
    initial_budget = _target_user_expression(f"{budget_low}+1")
    return (
        f"function({terminal},{query}){query}[__VM_Q_TRACE__]="
        f"({query}[__VM_Q_TRACE__] or {initial_trace});{query}[__VM_Q_BUDGET__]="
        f"({query}[__VM_Q_BUDGET__] or {initial_budget});"
        + _compiled_label_blocks(labels[0], blocks, native_control=native_control) + "end"
    )


def _compile_control_graph_func(*, native_control: bool = False) -> str:
    name_allocator = NameAllocator(readable=True)
    packet, state = [name_allocator.allocate("helper") for _ in range(2)]
    count = random.randint(12, 18)
    labels = [name_allocator.allocate("helper") for _ in range(count)]
    state_key = random.randint(1701, 2200)
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            body = f"return {packet}"
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 4))
            salt, loop_salt = _hex64(), _hex64()
            next_key = _target_private_expression(
                f"(o~{salt}~({state}[{state_key}] or 0))&-1"
            )
            loop_count = _target_private_low_expression(
                f"{packet}[__VM_CF_TRACE__]", 4
            )
            loop_mix = _target_private_expression(
                f"(n~((j*{loop_salt})&-1))&-1"
            )
            field_value = _target_private_expression(f"({packet}[f]~o)~n")
            next_trace = _target_private_expression(
                f"({packet}[__VM_CF_TRACE__]~n~{salt})&-1"
            )
            next_state = _target_private_expression(
                f"({state}[{state_key}] or 0)~n~{i + 1}"
            )
            branch_expr = _target_private_expression(
                f"((n~{packet}[__VM_CF_TRACE__])&1)==0"
            )
            loop_statement = _target_user_statement(
                f"for j=1,{loop_count}+1 do n={loop_mix} end"
            )
            body = (
                f"local o={packet}[__VM_CF_KEY__];local n={next_key};"
                f"{loop_statement};for _,f in ipairs("
                f"{packet}[__VM_CF_FIELDS__]) do {packet}[f]={field_value} end;"
                f"{packet}[__VM_CF_KEY__]=n;{packet}[__VM_CF_TRACE__]="
                f"{next_trace};{state}[{state_key}]={next_state};"
                f"if {branch_expr} "
                f"then {_graph_edge(labels[primary], native_control=native_control)} end;"
                f"{_graph_edge(labels[alternate], native_control=native_control)}"
            )
        blocks.append((label, body))
    seed = _hex64()
    initial_trace = _target_private_expression(
        f"{packet}[__VM_CF_KEY__]~{seed}"
    )
    return (
        f"function({packet},{state}){packet}[__VM_CF_TRACE__]=({packet}[__VM_CF_TRACE__] "
        f"or {initial_trace});"
        + _compiled_label_blocks(labels[0], blocks, native_control=native_control) + "end"
    )


def _compile_occurrence_graph_func(
    family_seed: int, *, native_control: bool = False,
    native_number_kind: bool = False,
) -> str:
    name_allocator = NameAllocator(readable=True)
    bank, pick, a, b, state, slots, regs, active, boxes, ledger, vm_state = [
        name_allocator.allocate("helper") for _ in range(11)
    ]
    site, selector, state_key, policy = [name_allocator.allocate("helper") for _ in range(4)]
    count = random.randint(7, 11)
    labels = [name_allocator.allocate("helper") for _ in range(count)]
    trace = name_allocator.allocate("helper")
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            key, out, result_value, mixed = [name_allocator.allocate("helper") for _ in range(4)]
            key_state = (
                f"{pick}~{trace}~{selector}~({state}[{state_key}] or 0)~{vm_state}"
            )
            mixed_state = _target_private_expression(
                f"({trace}~{site}~{selector}~{result_value}~{vm_state})&-1"
            )
            next_state = _target_private_expression(
                f"({state}[{state_key}] or 0)~{mixed}"
            )
            semantic_state = _target_private_expression(
                f"(({state}[611] or 0)~{mixed}~{site})&-1"
            )
            next_ledger = _target_private_expression(
                f"(({ledger}[1] or 0)~{mixed}~{selector})&-1"
            )
            key_modulo = _target_private_mod_expression(key_state, f"#{bank}")
            key_expression = _target_user_expression(f"{key_modulo}+1")
            bank_call = _target_user_expression(
                f"{bank}[{key}]({a},{b},{state},{slots},{regs},{active},{boxes})"
            )
            body = (
                f"local {key}={key_expression};local {out}={bank_call};"
                f"local {result_value}=0;if "
                f"{'_number_kind' if native_number_kind else 'math.type'}({out})=='integer' then "
                f"{result_value}={out} end;local {mixed}={mixed_state};"
                f"{state}[{state_key}]={next_state};if "
                f"{_target_user_expression(f'{policy}%2~=0')} then "
                f"{state}[611]={semantic_state} end;if "
                f"{_target_user_expression(f'math.floor({policy}/2)%2~=0')} then "
                f"{ledger}[1]={next_ledger} end;return {out}"
            )
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 3))
            salt = _hex64()
            next_trace = _target_private_expression(
                f"(({trace}~{salt})+{i + 1}+({state}[{state_key}] or 0))&-1"
            )
            next_state = _target_private_expression(
                f"({state}[{state_key}] or 0)~{trace}~{site}"
            )
            branch_expr = _target_private_expression(f"(({trace}~{site})&1)==0")
            body = (
                f"{trace}={next_trace};{state}[{state_key}]={next_state};"
                f"if {branch_expr} then "
                f"{_graph_edge(labels[primary], native_control=native_control)} end;"
                f"{_graph_edge(labels[alternate], native_control=native_control)}"
            )
        blocks.append((label, body))
    initial_trace = _target_private_expression(
        f"{site}~{selector}~{family_seed}~({state}[611] or 0)~"
        f"({state}[{state_key}] or 0)~{vm_state}"
    )
    return (
        f"function({bank},{pick},{a},{b},{state},{slots},{regs},{active},{boxes},"
        f"{ledger},{vm_state},{site},{selector},{state_key},{policy})"
        f"local {trace}={initial_trace};"
        + _compiled_label_blocks(labels[0], blocks, native_control=native_control) + "end"
    )


def _compile_loop_ir_func(kind: str, *, native_control: bool = False) -> str:
    name_allocator = NameAllocator(readable=True)
    packet, state = [name_allocator.allocate("helper") for _ in range(2)]
    trace = name_allocator.allocate("helper")
    state_key = random.randint(2801, 3300)
    labels: list[str] = []
    bodies: list[str] = []
    if kind == "FORLOOP":
        labels.extend([name_allocator.allocate("helper"), name_allocator.allocate("helper")])
        loop_state = _target_private_expression(
            f"({state}[{state_key}] or 0)~{trace}"
        )
        advance = _target_user_statement(
            f"{packet}[__VM_CF_VALUE__]={packet}[__VM_CF_VALUE__]+"
            f"{packet}[__VM_CF_STEP__]"
        )
        take = _target_user_expression("(d>0 and v<=l) or (d<=0 and v>=l)")
        bodies.extend([
            f"{advance};{state}[{state_key}]={loop_state};"
            f"{_graph_edge(labels[1], native_control=native_control)}",
            f"local v={packet}[__VM_CF_VALUE__];local d={packet}[__VM_CF_STEP__];"
            f"local l={packet}[__VM_CF_LIMIT__];{packet}[__VM_CF_TAKE__]="
            f"{take}",
        ])
    elif kind == "FORPREP":
        labels.append(name_allocator.allocate("helper"))
        bodies.append(_target_user_statement(
            f"{packet}[__VM_CF_VALUE__]={packet}[__VM_CF_VALUE__]-"
            f"{packet}[__VM_CF_STEP__]"
        ))
    else:
        labels.append(name_allocator.allocate("helper"))
        bodies.append(
            f"{packet}[__VM_CF_TAKE__]="
            f"{_target_user_expression(f'{packet}[__VM_CF_VALUE__]~=nil')}"
        )
    for _ in range(random.randint(7, 11)):
        next_label = name_allocator.allocate("helper")
        if bodies:
            bodies[-1] += ";" + _graph_edge(next_label, native_control=native_control)
        labels.append(next_label)
        salt = _hex64()
        next_trace = _target_private_expression(
            f"(({trace}~{salt})+{len(labels)})&-1"
        )
        next_state = _target_private_expression(
            f"({state}[{state_key}] or 0)~{trace}"
        )
        bodies.append(
            f"{trace}={next_trace};{state}[{state_key}]={next_state}"
        )
    bodies[-1] += f";return {packet}"
    blocks = list(zip(labels, bodies))
    seed = _hex64()
    initial_trace = _target_private_expression(f"{seed}~({state}[611] or 0)")
    return (
        f"function({packet},{state})local {trace}={initial_trace};"
        + _compiled_label_blocks(labels[0], blocks, native_control=native_control) + "end"
    )


def _semantic_source(
    kind: str, x: str, y: str, z: str, *, native_user_arithmetic: bool = False,
) -> str:
    if kind == "GET": return f"local r={_target_user_expression(f'{x}[{y}]')};"
    if kind == "SET": return _target_user_statement(f"{x}[{y}]={z}") + f"local r={z};"
    if kind == "EQ": return f"local r={_target_user_expression(f'{x}=={y}')};"
    if kind == "LT": return f"local r={_target_user_expression(f'{x}<{y}')};"
    if kind == "LE": return f"local r={_target_user_expression(f'{x}<={y}')};"
    if kind == "TRUTH": return f"local r=(not not {x});"
    if kind == "MOD": return f"local r={_target_user_expression(f'{x}%{y}')};"
    if kind == "POW":
        expression = f"{x}^{y}"
        if native_user_arithmetic:
            return f"local r={_target_user_expression(expression)};"
        return f"local r=({expression});"
    if kind == "DIV":
        expression = f"{x}/{y}"
        if native_user_arithmetic:
            return f"local r={_target_user_expression(expression)};"
        return f"local r=({expression});"
    if kind == "IDIV":
        if native_user_arithmetic:
            return f"local r={_target_user_expression(f'math.floor({x}/{y})')};"
        return f"local r=({x}//{y});"
    if kind == "NOT": return f"local r=(not {x});"
    if kind == "LEN": return f"local r=(#{x});"
    if kind == "CONCAT":
        return _target_user_statement(
            f"local r={x}[{z}];for i={z}-1,1,-1 do r={x}[i]..r end;"
        )
    if kind == "NEWTABLE": return "local r={};"
    if kind == "SETLIST":
        return _target_user_statement(
            f"for i=1,{z}[2] do {x}[{z}[1]+i]={y}[i] end;local r={x};"
        )
    if kind == "CLOSURE": return f"local r={x}({y});"
    if kind == "VARARG":
        return _target_user_statement(
            f"for i=1,{z}[1] do {x}({y}+i-1,{z}[2][i]) end;local r={z}[1];"
        )
    return f"local r={x};"


def _compile_semantic_ir_func(
    kind: str, *, native_user_arithmetic: bool = False,
    native_control: bool = False,
) -> str:
    name_allocator = NameAllocator(readable=True)
    x, y, z, state = [name_allocator.allocate("helper") for _ in range(4)]
    direct = _semantic_source(
        kind, x, y, z, native_user_arithmetic=native_user_arithmetic,
    )
    trace = name_allocator.allocate("helper")
    result = name_allocator.allocate("helper")
    state_key = random.randint(3301, 3900)
    labels = [name_allocator.allocate("helper") for _ in range(random.randint(7, 11))]
    blocks: list[tuple[str, str]] = []
    # The semantic source may read the result again (notably CONCAT), so bind
    # every standalone result reference to the compiler-owned local.
    first = re.sub(r"\br\b", result, direct).replace("local " + result, result)
    blocks.append((labels[0], first + _graph_edge(labels[1], native_control=native_control)))
    for i in range(1, len(labels) - 1):
        salt = _hex64()
        next_trace = _target_private_expression(
            f"(({trace}~{salt})+{i})&-1"
        )
        next_state = _target_private_expression(
            f"({state}[{state_key}] or 0)~{trace}"
        )
        blocks.append((labels[i],
            f"{trace}={next_trace};{state}[{state_key}]={next_state};"
            f"{_graph_edge(labels[i + 1], native_control=native_control)}"))
    blocks.append((labels[-1], f"return {result}"))
    seed = _hex64()
    initial_trace = _target_private_expression(f"{seed}~({state}[611] or 0)")
    heavy = (
        f"function({x},{y},{z},{state})local {result};local {trace}="
        f"{initial_trace};"
        + _compiled_label_blocks(labels[0], blocks, native_control=native_control) + "end"
    )
    direct_func = f"function({x},{y},{z},{state}){direct}return r end"
    return "{" + heavy + "," + direct_func + "}"


_ARITH_SPECS = {
    "ADD": ("__VM_SLOT_ADD__", "+", 2),
    "SUB": ("__VM_SLOT_SUB__", "-", 2),
    "MUL": ("__VM_SLOT_MUL__", "*", 2),
    "BAND": ("__VM_SLOT_BAND__", "&", 2),
    "BOR": ("__VM_SLOT_BOR__", "|", 2),
    "BXOR": ("__VM_SLOT_BXOR__", "~", 2),
    "SHL": ("__VM_SLOT_SHL__", "<<", 2),
    "SHR": ("__VM_SLOT_SHR__", ">>", 2),
    "UNM": ("__VM_SLOT_UNM__", "-", 1),
    "BNOT": ("__VM_SLOT_BNOT__", "~", 1),
}
_ARITH_ROUTE_NAMES = {
    "ADD": "ADD", "SUB": "SUB", "MUL": "MUL", "BAND": "BIT_AND",
    "BOR": "BIT_OR", "BXOR": "BIT_XOR", "SHL": "SHIFT_LEFT",
    "SHR": "SHIFT_RIGHT", "UNM": "NEGATE", "BNOT": "BIT_NOT",
}
_SEMANTIC_ROUTE_NAMES = {
    "VALUE": "VALUE", "GET": "TABLE_GET", "SET": "TABLE_SET",
    "EQ": "EQUAL", "LT": "LESS_THAN", "LE": "LESS_EQUAL",
    "TRUTH": "TRUTH", "MOD": "MOD", "POW": "POW", "DIV": "DIV",
    "IDIV": "FLOOR_DIV", "NOT": "LOGICAL_NOT", "LEN": "LENGTH",
    "CONCAT": "CONCAT", "NEWTABLE": "NEW_TABLE", "SETLIST": "SET_LIST",
    "CLOSURE": "CLOSURE", "VARARG": "VARARG",
}


def _apply_handler_graphs(
    vm_code: str,
    graph_family_count: int = 8,
    runtime_polymorphism_rate: float = 0.0,
    semantic_state_threading: bool = False,
    argument_virtualization: bool = False,
    upvalue_virtualization: bool = False,
    table_virtualization: bool = False,
    branch_virtualization: bool = False,
    representation_routes: tuple | None = None,
    preserve_native_numbers: bool = False,
    private_state_native: bool = False,
    native_graph_control: bool = False,
) -> str:
    name_allocator = NameAllocator(readable=True)
    if representation_routes is None:
        raise ValueError("Karity runtime requires planned representation routes")
    planned_routes = dict(representation_routes)
    if set(planned_routes) != {"arithmetic", "semantic"}:
        raise ValueError("Karity runtime has incomplete representation routes")
    planned_arithmetic = dict(planned_routes["arithmetic"])
    planned_semantic = dict(planned_routes["semantic"])
    if (set(planned_arithmetic) != set(_ARITH_ROUTE_NAMES.values())
            or set(planned_semantic) != set(_SEMANTIC_ROUTE_NAMES.values())
            or any(type(route) is not bool for route in
                   (*planned_arithmetic.values(), *planned_semantic.values()))):
        raise ValueError("Karity runtime has invalid representation routes")
    threshold = max(0, min(0x10000, round(runtime_polymorphism_rate * 0x10000)))
    vm_code = vm_code.replace("__VM_POLY_THRESHOLD__", str(threshold))
    vm_code = vm_code.replace(
        "__VM_SEMANTIC_STATE__", "true" if semantic_state_threading else "false"
    )
    vm_code = vm_code.replace(
        "__VM_ARGUMENT_VIRTUALIZATION__",
        "true" if argument_virtualization else "false",
    )
    vm_code = vm_code.replace(
        "__VM_UPVALUE_VIRTUALIZATION__",
        "true" if upvalue_virtualization else "false",
    )
    vm_code = vm_code.replace(
        "__VM_TABLE_VIRTUALIZATION__",
        "true" if table_virtualization else "false",
    )
    vm_code = vm_code.replace(
        "__VM_BRANCH_VIRTUALIZATION__",
        "true" if branch_virtualization else "false",
    )
    for token in ("__VM_ARG_MASK__", "__VM_ARG_KEY__", "__VM_ARG_PAD__",
                  "__VM_ARG_TAG__"):
        vm_code = vm_code.replace(token, str(random.randint(0x10000, 0x7FFFFFFF)))
    for token in ("__VM_UV_SEED__", "__VM_UV_NIL__", "__VM_UV_BIAS__",
                  "__VM_UV_SHARE__"):
        vm_code = vm_code.replace(token, str(random.randint(0x10000, 0x7FFFFFFF)))
    for token in ("__VM_TABLE_SEED__", "__VM_TABLE_KEY__",
                  "__VM_TABLE_SHARE__"):
        vm_code = vm_code.replace(token, str(random.randint(0x10000, 0x7FFFFFFF)))
    vm_code = vm_code.replace(
        "__VM_BRANCH_SEED__", str(random.randint(0x10000, 0x7FFFFFFF))
    )
    slots: dict[str, int] = {}
    used_slots: set[int] = set()
    for kind, (token, _, _) in _ARITH_SPECS.items():
        while True:
            slot = random.randint(0x1000, 0xFFFFF)
            if slot not in used_slots:
                used_slots.add(slot)
                slots[kind] = slot
                break

    def arithmetic_bank() -> str:
        native_entries: list[str] = []
        graph_entries: list[str] = []
        arithmetic_indices: dict[str, int] = {}
        kinds = list(_ARITH_SPECS)
        random.shuffle(kinds)
        for dense_index, kind in enumerate(kinds, 1):
            _, operator, arity = _ARITH_SPECS[kind]
            arithmetic_indices[kind] = dense_index
            x, y = name_allocator.allocate("helper"), name_allocator.allocate("helper")
            if arity == 1:
                if kind == "UNM" and preserve_native_numbers:
                    native = (f"function({x})if _pisword({x}) then return _pneg({x}) end;"
                              f"return {_target_user_expression(f'{operator}{x}')} end")
                else:
                    operation = (
                        _target_user_expression(f"{operator}{x}")
                        if kind == "UNM"
                        else _target_private_expression(f"{operator}{x}")
                    )
                    native = f"function({x})return {operation} end"
            else:
                if kind in {"ADD", "SUB", "MUL"} and preserve_native_numbers:
                    private_op = {"ADD": "_padd", "SUB": "_psub", "MUL": "_pmul"}[kind]
                    native = (f"function({x},{y})if _pisword({x}) or _pisword({y}) then "
                              f"return {private_op}({x},{y}) end;"
                              f"return {_target_user_expression(f'{x}{operator}{y}')} end")
                else:
                    operation = (
                        _target_user_expression(f"{x}{operator}{y}")
                        if kind in {"ADD", "SUB", "MUL"}
                        else _target_private_expression(f"{x}{operator}{y}")
                    )
                    native = f"function({x},{y})return {operation} end"
            native_entries.append(f"{{{native},{native}}}")
            graph_entries.append(
                "{" + ",".join(
                    _compile_integer_graph_func(
                        kind,
                        preserve_native_numbers,
                        private_state_native,
                    )
                    for _ in range(4)
                ) + "}"
            )

        arithmetic_share_a: list[str] = []
        arithmetic_share_b: list[str] = []
        for kind in kinds:
            share = random.randint(0x10000, 0x7FFFFFFF)
            slot = slots[kind]
            dense_index = arithmetic_indices[kind]
            arithmetic_share_a.append(f'[{slot}]=tonumber("{share}")')
            arithmetic_share_b.append(
                f'[{slot}]=tonumber("{share ^ dense_index}")'
            )
        return (
            "{{" + ",".join(native_entries)
            + "},{" + ",".join(graph_entries)
            + "},{" + ",".join(arithmetic_share_a)
            + "},{" + ",".join(arithmetic_share_b) + "}}"
        )

    arithmetic_route_a: list[str] = []
    arithmetic_route_b: list[str] = []
    for kind, slot in slots.items():
        share = random.randint(0x10000, 0x7FFFFFFF)
        route = int(planned_arithmetic[_ARITH_ROUTE_NAMES[kind]])
        arithmetic_route_a.append(f'[{slot}]=tonumber("{share}")')
        arithmetic_route_b.append(f'[{slot}]=tonumber("{share ^ route}")')
    bundle = (
        "{{" + arithmetic_bank() + "," + arithmetic_bank()
        + "},{" + ",".join(arithmetic_route_a)
        + "},{" + ",".join(arithmetic_route_b) + "}}"
    )
    vm_code = vm_code.replace(
        "__VM_ARITH_BUNDLE__", _exact_graph_source(bundle)
    )
    affine_pairs = []
    for _ in range(16):
        multiplier = random.getrandbits(64) | 1
        inverse = pow(multiplier, -1, 1 << 64)
        signed_multiplier = multiplier if multiplier < (1 << 63) else multiplier - (1 << 64)
        signed_inverse = inverse if inverse < (1 << 63) else inverse - (1 << 64)
        if private_state_native:
            # These are full-width private affine factors, not user numbers.
            # Lua 5.1 must parse their decimal digits before binary64 can
            # round a literal; the generic source translator used to do so.
            affine_pairs.append(
                f'{{_pint("{multiplier}"),_pint("{inverse}")}}'
            )
        else:
            affine_pairs.append(f"{{{signed_multiplier},{signed_inverse}}}")
    vm_code = vm_code.replace(
        "__VM_AFFINE_POOL__",
        _exact_graph_source("{" + ",".join(affine_pairs) + "}"),
    )
    register_maps: list[str] = []
    used_maps: set[tuple[int, int, int]] = set()
    while len(register_maps) < 5:
        spec = (
            random.randrange(1, 1024, 2),
            random.randrange(0, 1024),
            random.randrange(1, 1024, 2),
        )
        if spec in used_maps:
            continue
        used_maps.add(spec)
        register_maps.append("{" + ",".join(map(str, spec)) + "}")
    vm_code = vm_code.replace(
        "__VM_REGISTER_MAPS__",
        _exact_graph_source("{" + ",".join(register_maps) + "}"),
    )
    for kind, (token, _, _) in _ARITH_SPECS.items():
        vm_code = vm_code.replace(token, str(slots[kind]))
    value_token = "__VM_VALUE_GRAPHS__"
    while value_token in vm_code:
        variants = ",".join(_compile_value_graph_func() for _ in range(2))
        vm_code = vm_code.replace(
            value_token, _exact_graph_source("{" + variants + "}"), 1
        )

    call_tags = random.sample(range(0x10000, 0x7FFFFFFF), 4)
    call_replacements = {
        "__VM_CALL_ENTER__": call_tags[0],
        "__VM_CALL_LEAVE__": call_tags[1],
        "__VM_ROUTE_ENTER__": call_tags[2],
        "__VM_ROUTE_LEAVE__": call_tags[3],
    }
    call_graph = (
        "{[" + str(call_tags[2]) + "]="
        + _compile_call_route_func(native_control=native_graph_control)
        + ",[" + str(call_tags[3]) + "]="
        + _compile_call_route_func(native_control=native_graph_control) + "}"
    )
    vm_code = vm_code.replace(
        "__VM_CALL_GRAPHS__", _exact_graph_source(call_graph)
    )
    control_graphs = "{" + ",".join(
        _compile_control_graph_func(native_control=native_graph_control)
        for _ in range(2)
    ) + "}"
    vm_code = vm_code.replace(
        "__VM_CONTROL_GRAPHS__", _exact_graph_source(control_graphs)
    )
    loop_tags = random.sample(range(0x10000, 0x7FFFFFFF), 3)
    loop_graphs = (
        "{[" + str(loop_tags[0]) + "]="
        + _compile_loop_ir_func("FORLOOP", native_control=native_graph_control)
        + ",[" + str(loop_tags[1]) + "]="
        + _compile_loop_ir_func("FORPREP", native_control=native_graph_control)
        + ",[" + str(loop_tags[2]) + "]="
        + _compile_loop_ir_func("TFORLOOP", native_control=native_graph_control) + "}"
    )
    vm_code = vm_code.replace(
        "__VM_LOOP_GRAPHS__", _exact_graph_source(loop_graphs)
    )
    vm_code = vm_code.replace("__VM_LOOP_FORLOOP__", str(loop_tags[0]))
    vm_code = vm_code.replace("__VM_LOOP_FORPREP__", str(loop_tags[1]))
    vm_code = vm_code.replace("__VM_LOOP_TFORLOOP__", str(loop_tags[2]))
    data_tags = random.sample(range(0x10000, 0x7FFFFFFF), 18)
    semantic_kinds = (
        "VALUE", "GET", "SET", "EQ", "LT", "LE", "TRUTH",
        "MOD", "POW", "DIV", "IDIV", "NOT", "LEN", "CONCAT",
        "NEWTABLE", "SETLIST", "CLOSURE", "VARARG",
    )
    def semantic_bank() -> str:
        semantic_order = list(zip(semantic_kinds, data_tags))
        random.shuffle(semantic_order)
        semantic_entries: list[str] = []
        semantic_share_a: list[str] = []
        semantic_share_b: list[str] = []
        for dense_index, (kind, tag) in enumerate(semantic_order, 1):
            share = random.randint(0x10000, 0x7FFFFFFF)
            semantic_entries.append(_compile_semantic_ir_func(
                kind, native_user_arithmetic=preserve_native_numbers,
                native_control=native_graph_control,
            ))
            semantic_share_a.append(f'[{tag}]=tonumber("{share}")')
            semantic_share_b.append(
                f'[{tag}]=tonumber("{share ^ dense_index}")'
            )
        return (
            "{{" + ",".join(semantic_entries)
            + "},{" + ",".join(semantic_share_a)
            + "},{" + ",".join(semantic_share_b) + "}}"
        )

    semantic_route_a: list[str] = []
    semantic_route_b: list[str] = []
    for kind, tag in zip(semantic_kinds, data_tags):
        share = random.randint(0x10000, 0x7FFFFFFF)
        route = int(planned_semantic[_SEMANTIC_ROUTE_NAMES[kind]])
        semantic_route_a.append(f'[{tag}]=tonumber("{share}")')
        semantic_route_b.append(f'[{tag}]=tonumber("{share ^ route}")')
    semantic_graphs = (
        "{{" + semantic_bank() + "," + semantic_bank()
        + "},{" + ",".join(semantic_route_a)
        + "},{" + ",".join(semantic_route_b) + "}}"
    )
    vm_code = vm_code.replace(
        "__VM_SEMANTIC_GRAPHS__", _exact_graph_source(semantic_graphs)
    )
    for token, tag in zip((
        "__VM_DATA_VALUE__", "__VM_DATA_GET__", "__VM_DATA_SET__",
        "__VM_CMP_EQ__", "__VM_CMP_LT__", "__VM_CMP_LE__",
        "__VM_CMP_TRUTH__",
        "__VM_OP_MOD__", "__VM_OP_POW__", "__VM_OP_DIV__",
        "__VM_OP_IDIV__", "__VM_OP_NOT__", "__VM_OP_LEN__",
        "__VM_OP_CONCAT__",
        "__VM_OP_NEWTABLE__", "__VM_OP_SETLIST__",
        "__VM_OP_CLOSURE__", "__VM_OP_VARARG__",
    ), data_tags):
        vm_code = vm_code.replace(token, str(tag))
    pending_tokens = random.sample(range(0x10000, 0x7FFFFFFF), 3)
    for token, value in zip((
        "__VM_PENDING_ADD__", "__VM_PENDING_SUB__", "__VM_PENDING_UNM__",
    ), pending_tokens):
        vm_code = vm_code.replace(token, str(value))
    occurrence_graphs = "{" + ",".join(
        _compile_occurrence_graph_func(
            random.randint(0x10000, 0x7FFFFFFF),
            native_control=native_graph_control,
            native_number_kind=private_state_native,
        )
        for _ in range(graph_family_count)
    ) + "}"
    vm_code = vm_code.replace(
        "__VM_OCCURRENCE_GRAPHS__", _exact_graph_source(occurrence_graphs)
    )

    field_tokens = [
        "__VM_FR_REGS__", "__VM_FR_BOXES__", "__VM_FR_MASK__", "__VM_FR_PC__",
        "__VM_FR_TOP__", "__VM_FR_STATE__", "__VM_FR_VARARG__",
        "__VM_FR_SPLIT__", "__VM_FR_SPLIT_SHARE__", "__VM_FR_SPLIT_EPOCH__", "__VM_FR_SPLIT_TYPE__",
        "__VM_FR_SCRATCH__", "__VM_FR_ACTIVE__",
        "__VM_FR_FLOW_CACHE__", "__VM_FR_SEM_CACHE__", "__VM_FR_LOOP_CACHE__", "__VM_FR_GRAPH_CACHE__", "__VM_FR_REG_SHARES__", "__VM_FR_REG_EPOCHS__", "__VM_FR_REG_TYPES__", "__VM_FR_VALUE_VAULT__", "__VM_FR_VALUE_INDEX__", "__VM_FR_REPR_COUNTERS__", "__VM_FR_REG_SEED__", "__VM_FR_MAP_STATE__", "__VM_FR_LOGICAL_SLOTS__", "__VM_FR_PENDING__", "__VM_FR_LEDGER__", "__VM_FR_PROTO__", "__VM_FR_UPVALS__", "__VM_FR_A__",
        "__VM_FR_C__", "__VM_FR_PARENT__", "__VM_FR_ROUTE_STATE__",
        "__VM_FR_SEM_STATE__", "__VM_Q_KIND__",
        "__VM_Q_PROTO__", "__VM_Q_UPVALS__", "__VM_Q_ARGS__",
        "__VM_Q_CONT__", "__VM_Q_RESULT__", "__VM_Q_TRACE__",
        "__VM_Q_FLOW__", "__VM_Q_BUDGET__", "__VM_Q_LEDGER__",
        "__VM_RES_VALUES__", "__VM_RES_COUNT__",
        "__VM_META_PROTO__", "__VM_META_UPVALS__",
        "__VM_CF_KEY__", "__VM_CF_TRACE__", "__VM_CF_FIELDS__", "__VM_CF_SEAL__",
        "__VM_CF_TARGET__", "__VM_CF_A__", "__VM_CF_B__",
        "__VM_CF_C__", "__VM_CF_COUNT__",
        "__VM_CF_VALUE__", "__VM_CF_STEP__", "__VM_CF_LIMIT__",
        "__VM_CF_TAKE__", "__VM_AP_MARK__", "__VM_AP_SEED__",
        "__VM_AP_COUNT__", "__VM_AP_DATA__",
        "__VM_UV_LEFT__", "__VM_UV_RIGHT__", "__VM_UV_EPOCH__",
        "__VM_UV_KIND__",
        "__VM_TB_LEFT__", "__VM_TB_RIGHT__", "__VM_TB_KEYS__",
        "__VM_TB_REVERSE__", "__VM_TB_SALT__", "__VM_TB_NEXT__",
        "__VM_TB_EXPOSED__",
    ]
    field_slots = random.sample(range(3, 241), len(field_tokens))
    for token, slot in zip(field_tokens, field_slots):
        vm_code = vm_code.replace(token, str(slot))
    for token, value in call_replacements.items():
        vm_code = vm_code.replace(token, str(value))
    return vm_code
