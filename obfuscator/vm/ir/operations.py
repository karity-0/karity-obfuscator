"""Semantic operation contracts shared by frontends and protection passes."""
from dataclasses import dataclass


@dataclass(frozen=True)
class OperandSpec:
    role: str
    kinds: frozenset[str]
    repeated: bool = False
    count: int | None = None


def operand(role, kinds, *, repeated=False, count=None):
    return OperandSpec(role, frozenset(kinds.split("|")), repeated, count)


@dataclass(frozen=True)
class OperationSpec:
    operands: tuple[OperandSpec, ...]
    edges: int | None = None
    effects: frozenset[str] = frozenset()


def spec(*operands, edges=None, effects=()):
    return OperationSpec(operands, edges, frozenset(effects))


R="register"
K="constant"
RK="register|constant"
U="upvalue"
SPAN="register_range"
IMM="immediate"
D=operand("destination",R)
SOURCE=operand("source",R)
LEFT=operand("left",RK)
RIGHT=operand("right",RK)
EXPECTED=operand("expected",IMM)

OPERATIONS = {
    "MOVE": spec(D,SOURCE),
    "LOAD_CONST": spec(D,operand("value",K)),
    "LOAD_BOOL": spec(D,operand("value",IMM),operand("skip",IMM)),
    "LOAD_NIL": spec(operand("destination",SPAN)),
    "GET_UPVALUE": spec(D,operand("source",U),effects=("upvalue_read",)),
    "SET_UPVALUE": spec(SOURCE,operand("destination",U),effects=("upvalue_write",)),
    "GET_UPVALUE_TABLE": spec(D,operand("table",U),operand("key",RK),effects=("table_read","call")),
    "SET_UPVALUE_TABLE": spec(operand("table",U),operand("key",RK),operand("value",RK),effects=("table_write","call")),
    "GET_TABLE": spec(D,operand("table",R),operand("key",RK),effects=("table_read","call")),
    "SET_TABLE": spec(operand("table",R),operand("key",RK),operand("value",RK),effects=("table_write","call")),
    "GLOBAL_GET": spec(D,operand("key",K),effects=("environment_read","call")),
    "GLOBAL_SET": spec(SOURCE,operand("key",K),effects=("environment_write","call")),
    "NEW_TABLE": spec(D,operand("array_hint",IMM),operand("hash_hint",IMM),effects=("allocation",)),
    "SELF": spec(operand("destination",SPAN,count=2),operand("receiver",R),operand("key",RK),effects=("table_read","call")),
    "CONCAT": spec(D,operand("sources",SPAN),effects=("call",)),
    "JUMP": spec(operand("close_from",IMM),edges=1,effects=("close_upvalues",)),
    "TEST": spec(operand("condition",R),EXPECTED,edges=2),
    "TEST_SET": spec(D,operand("condition",R),EXPECTED,edges=2),
    "CALL": spec(operand("callee",R),operand("arguments",SPAN),operand("results",SPAN),effects=("call","top",)),
    "TAIL_CALL": spec(operand("callee",R),operand("arguments",SPAN),edges=0,effects=("call","top","close_upvalues")),
    "RETURN": spec(operand("values",SPAN),edges=0,effects=("top","close_upvalues")),
    "FOR_LOOP": spec(operand("loop_state",SPAN,count=3),operand("iteration",R),edges=2),
    "FOR_PREP": spec(operand("loop_state",SPAN,count=3),operand("iteration",R),edges=1),
    "ITER_CALL": spec(operand("iterator",SPAN,count=3),operand("results",SPAN),effects=("call",)),
    "ITER_LOOP": spec(operand("control",R),operand("result",R),edges=2),
    "SET_LIST": spec(operand("table",R),operand("values",SPAN),operand("batch",IMM),effects=("table_write","top")),
    "CLOSURE": spec(D,operand("child","proto"),operand("capture","register|upvalue",repeated=True),effects=("allocation","capture")),
    "VARARG": spec(operand("results",SPAN),effects=("top",)),
    "PACK_VARARG": spec(D,effects=("allocation","top")),
}
for name in ("ADD","SUB","MUL","MOD","POW","DIV","FLOOR_DIV","BIT_AND","BIT_OR","BIT_XOR","SHIFT_LEFT","SHIFT_RIGHT"):
    OPERATIONS[name]=spec(D,LEFT,RIGHT,effects=("call",))
for name in ("NEGATE","BIT_NOT","LENGTH"):
    OPERATIONS[name]=spec(D,SOURCE,effects=("call",))
OPERATIONS["LOGICAL_NOT"]=spec(D,SOURCE)
for name in ("EQUAL","LESS_THAN","LESS_EQUAL"):
    OPERATIONS[name]=spec(EXPECTED,LEFT,RIGHT,edges=2,effects=("call",))


def operation_errors(instruction):
    """Yield contract violations before a lowerer can interpret operands."""
    contract=OPERATIONS.get(instruction.operation)
    if contract is None:
        yield "unknown semantic operation"
        return
    actual={}
    for item in instruction.operands:
        actual.setdefault(item.role,[]).append(item)
    expected={item.role for item in contract.operands}
    if set(actual)-expected:
        yield "unexpected operand role"
    for item in contract.operands:
        matches=actual.get(item.role,())
        if not item.repeated and len(matches)!=1:
            yield "missing or duplicate operand: " + item.role
        for match in matches:
            if match.kind not in item.kinds:
                yield "invalid operand kind for " + item.role
            if item.count is not None and match.count!=item.count:
                yield "invalid fixed range for " + item.role
    if contract.edges is not None and len(instruction.targets)!=contract.edges:
        yield "invalid control edge count"

    for item in instruction.operands:
        if item.kind!="immediate":
            continue
        if item.role in ("expected","skip") or (instruction.operation=="LOAD_BOOL" and item.role=="value"):
            if type(item.value) is not bool:
                yield "expected boolean immediate for " + item.role
        elif item.role=="close_from":
            if item.value is not None and (type(item.value) is not int or item.value<0):
                yield "invalid upvalue close boundary"
        elif item.role in ("array_hint","hash_hint","batch"):
            if type(item.value) is not int or item.value<(1 if item.role=="batch" else 0):
                yield "invalid nonnegative immediate for " + item.role
