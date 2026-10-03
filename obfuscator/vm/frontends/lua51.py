"""Normalize native Lua 5.1 bytecode into version-independent semantic operations."""
from ..ir import (IRValue, IROperand, IRInstruction, IRBlock, IRFunction,
                  SemanticIR, IRValidationError, normalize_semantic_ir)

OPERATIONS = (
    "MOVE", "LOAD_CONST", "LOAD_BOOL", "LOAD_NIL", "GET_UPVALUE", "GLOBAL_GET",
    "GET_TABLE", "GLOBAL_SET", "SET_UPVALUE", "SET_TABLE", "NEW_TABLE", "SELF",
    "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "NEGATE", "LOGICAL_NOT", "LENGTH",
    "CONCAT", "JUMP", "EQUAL", "LESS_THAN", "LESS_EQUAL", "TEST", "TEST_SET",
    "CALL", "TAIL_CALL", "RETURN", "FOR_LOOP", "FOR_PREP", "ITERATE", "SET_LIST",
    "CLOSE", "CLOSURE", "VARARG",
)


def _decode(word):
    return word & 63, (word >> 6) & 255, (word >> 23) & 511, (word >> 14) & 511, word >> 14


def build_semantic_ir(proto) -> SemanticIR:
    def build(proto, path):
        fid = "f" + ".".join(map(str, path))
        rows = []
        consumed = set()
        first = {}
        size = len(proto.code)
        if proto.is_vararg & 4:
            rows.append([-1, "PACK_VARARG", (IROperand("destination", "register", proto.num_params),),
                         set(), {proto.num_params}, (0,)])
        # A row stores an explicit semantic instruction and source-PC successors.
        for pc, word in enumerate(proto.code):
            if pc in consumed:
                continue
            op, a, b, c, bx = _decode(word)
            if op >= len(OPERATIONS):
                raise IRValidationError(f"unknown Lua 5.1 operation at {fid}:{pc}")
            name = OPERATIONS[op]
            operands = []
            reads, writes = set(), set()
            def add(role, kind, value, count=None, write=False):
                operands.append(IROperand(role, kind, value, count))
                if kind in ("register", "register_range"):
                    registers = range(value, proto.max_stack_size if count is None and kind == "register_range"
                                      else value + (count if kind == "register_range" else 1))
                    (writes if write else reads).update(registers)
            def reg(role, value, write=False): add(role, "register", value, write=write)
            def dest(value=a): reg("destination", value, True)
            def imm(role, value): add(role, "immediate", value)
            def rk(role, value): add(role, "constant" if value >= 256 else "register", value - 256 if value >= 256 else value)
            def span(role, value, count, write=False): add(role, "register_range", value, count, write)
            following = pc + 1
            targets = (following,) if following < size else ()
            if name == "MOVE": dest(); reg("source", b)
            elif name == "LOAD_CONST": dest(); add("value", "constant", bx)
            elif name == "LOAD_BOOL":
                dest(); imm("value", bool(b)); imm("skip", bool(c))
                if c: targets = (pc + 2,)
            elif name == "LOAD_NIL": span("destination", a, b - a + 1, True)
            elif name == "GET_UPVALUE": dest(); add("source", "upvalue", b)
            elif name == "GLOBAL_GET": dest(); add("key", "constant", bx)
            elif name == "GLOBAL_SET": reg("source", a); add("key", "constant", bx)
            elif name == "GET_TABLE": dest(); reg("table", b); rk("key", c)
            elif name == "SET_UPVALUE": reg("source", a); add("destination", "upvalue", b)
            elif name == "SET_TABLE": reg("table", a); rk("key", b); rk("value", c)
            elif name == "NEW_TABLE": dest(); imm("array_hint", b); imm("hash_hint", c)
            elif name == "SELF": span("destination", a, 2, True); reg("receiver", b); rk("key", c)
            elif name in ("ADD", "SUB", "MUL", "DIV", "MOD", "POW"):
                dest(); rk("left", b); rk("right", c)
            elif name in ("NEGATE", "LOGICAL_NOT", "LENGTH"): dest(); reg("source", b)
            elif name == "CONCAT": dest(); span("sources", b, c - b + 1)
            elif name in ("JUMP", "CLOSE"):
                imm("close_from", a if name == "CLOSE" else None)
                targets = (following if name == "CLOSE" else following + bx - 131071,)
                name = "JUMP"
            elif name in ("EQUAL", "LESS_THAN", "LESS_EQUAL"):
                imm("expected", bool(a)); rk("left", b); rk("right", c)
                targets = (following, pc + 2)
            elif name in ("TEST", "TEST_SET"):
                if name == "TEST_SET": dest()
                reg("condition", a if name == "TEST" else b); imm("expected", bool(c))
                targets = (following, pc + 2)
            elif name in ("CALL", "TAIL_CALL"):
                reg("callee", a); span("arguments", a + 1, None if b == 0 else b - 1)
                if name == "CALL": span("results", a, None if c == 0 else c - 1, True)
                else: targets = ()
            elif name == "RETURN": span("values", a, None if b == 0 else b - 1); targets = ()
            elif name in ("FOR_LOOP", "FOR_PREP"):
                span("loop_state", a, 3); reg("iteration", a + 3, True); writes.add(a)
                targets = (following + bx - 131071,) + ((following,) if name == "FOR_LOOP" else ())
            elif name == "ITERATE":
                # 5.1 combines a call, nil test, control copy and skip. Expand it
                # to a call plus conditional branch and explicit skip jump.
                span("iterator", a, 3); span("results", a + 3, c, True)
                name = "ITER_CALL"
            elif name == "SET_LIST":
                reg("table", a); span("values", a + 1, None if b == 0 else b)
                if not c:
                    if following >= size: raise IRValidationError("missing Lua 5.1 SETLIST extension")
                    c = proto.code[following]; consumed.add(following)
                    targets = (following + 1,) if following + 1 < size else ()
                imm("batch", c)
            elif name == "CLOSURE":
                if bx >= len(proto.protos): raise IRValidationError("invalid Lua 5.1 child prototype")
                dest(); add("child", "proto", bx)
                child = proto.protos[bx]
                for offset in range(len(child.upvalues)):
                    bind_pc = following + offset
                    if bind_pc >= size: raise IRValidationError("missing Lua 5.1 closure binding")
                    bind_op, _, bind_b, _, _ = _decode(proto.code[bind_pc])
                    if bind_op not in (0, 4): raise IRValidationError("invalid Lua 5.1 closure binding")
                    consumed.add(bind_pc)
                    add("capture", "register" if bind_op == 0 else "upvalue", bind_b)
                next_pc = following + len(child.upvalues)
                targets = (next_pc,) if next_pc < size else ()
            elif name == "VARARG": span("results", a, None if b == 0 else b - 1, True)
            first[pc] = len(rows)
            rows.append([pc, name, tuple(operands), reads, writes, targets])
            if op == 33:
                rows[-1][5] = (f"row:{len(rows)}",)
                rows.append([pc, "ITER_LOOP", (IROperand("control", "register", a + 2),
                             IROperand("result", "register", a + 3)), {a + 2, a + 3}, {a + 2},
                             (following, f"row:{len(rows) + 1}")])
                rows.append([pc, "JUMP", (IROperand("close_from", "immediate", None),), set(), set(), (pc + 2,)])
        def target(value):
            if isinstance(value, str): index = int(value.split(":")[1])
            else:
                if value not in first:
                    raise IRValidationError(f"Lua 5.1 branch into extension or outside function: {fid}:{value}")
                index = first[value]
            return f"{fid}:b{index}"
        blocks = []
        for index, (pc, name, operands, reads, writes, targets) in enumerate(rows):
            targets = tuple(target(value) for value in targets)
            instruction = IRInstruction(f"{fid}:i{index}", name,
                tuple(f"{fid}:r{r}" for r in sorted(reads)), tuple(f"{fid}:r{r}" for r in sorted(writes)),
                tuple(f"{fid}:k{o.value}" for o in operands if o.kind == "constant"), targets, operands,
                {"source_pc": pc, "source_line": proto.lineinfo[pc] if 0 <= pc < len(proto.lineinfo) else None})
            blocks.append(IRBlock(f"{fid}:b{index}", (instruction,), targets))
        values = tuple(IRValue(f"{fid}:r{i}", "register", i) for i in range(proto.max_stack_size))
        values += tuple(IRValue(f"{fid}:k{i}", "constant", i, literal=value) for i, value in enumerate(proto.constants))
        values += tuple(IRValue(f"{fid}:u{i}", "upvalue", i, value.name) for i, value in enumerate(proto.upvalues))
        return IRFunction(fid, proto.num_params, bool(proto.is_vararg & 2), proto.max_stack_size,
                          values, tuple(blocks), tuple(build(child, (*path, i)) for i, child in enumerate(proto.protos)),
                          str(proto.source or ""), tuple(("register" if u.instack else "upvalue", u.idx) for u in proto.upvalues),
                          {"lines": tuple(proto.lineinfo), "locals": tuple((v.name, v.startpc, v.endpc) for v in proto.locvars),
                           "needs_vararg_table": bool(proto.is_vararg & 4)})
    return normalize_semantic_ir(SemanticIR("semantic-v2", build(proto, (0,))))
