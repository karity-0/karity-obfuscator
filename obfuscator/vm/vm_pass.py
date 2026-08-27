from __future__ import annotations
import subprocess
import platform
import tempfile
import secrets
import string
import random
import time
import zlib
import shutil
import os
import re
from pathlib import Path

from ..passes.base import PostPass
from ..parser import Lua53Parser
from .serializer import (
    serialize,
    assign_vm_ids,
    collect_fuseable_pairs_for_vm,
    patch_integrity_sources,
)
from .kae_blob import encrypt_blob
from .vm_obfuscation import (prune_and_inject_handlers, apply_vop_to_vm,
                             apply_split_to_vm, apply_fuse_to_vm,
                             apply_defer_to_vm, ALL_SPLIT_OPS, DEFER_OPS,
                             apply_dispatch, apply_dispatch_target_hiding,
                             apply_execution_kit,
                             wire_exec_router, build_next_router_kit,
                             build_exec_variants,
                             collect_used_ops_for_vm, collect_used_orig_ops_for_vm)
from .vm_variants import (make_instr_layout, apply_instr_layout,
                          apply_keystream, apply_tamper, apply_line_state)
from .output_emitter import EMITTER_PASS_NAMES, emit_vm_literals
from .junk_injection import inject_junk


if platform.system() == "Windows":
    _LUA    = Path(__file__).parent.parent.parent / "bin" / "lua.exe"
    _LUAC   = Path(__file__).parent.parent.parent / "bin" / "luac53.exe"
else:
    _LUA    = shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua5.3"
    _LUAC   = shutil.which("luac5.3") or shutil.which("luac53") or "luac5.3"

if not _LUA or (isinstance(_LUA, Path) and not _LUA.exists()):
    raise FileNotFoundError("lua5.3 not found.")

if not _LUAC or (isinstance(_LUAC, Path) and not _LUAC.exists()):
    raise FileNotFoundError("luac5.3 not found.")

_VM_LUA_PATH = Path(__file__).parent / "vm.lua"


def _compile(script: str) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False, mode="w", encoding="utf-8") as f:
        f.write(script)
        src_path = f.name

    out_path = src_path + ".luac"
    try:
        result = subprocess.run(
            [str(_LUAC), "-o", out_path, src_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"luac failed: {result.stderr.decode()}")

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(src_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


_B36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def _to_base36(data: bytes) -> str:
    """bytes → "KARITY/length:base36payload" (4바이트 청크, 각 6자리 고정)"""
    length = len(data)
    # length 인코딩
    ln, length_enc = length, ''
    while ln:
        length_enc = _B36[ln % 36] + length_enc
        ln //= 36

    # 4바이트씩 청크로 나눠 각각 6자리 base36으로 인코딩
    # 패딩: 4의 배수로 맞춤
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    parts = []
    for i in range(0, len(padded), 4):
        n = int.from_bytes(padded[i:i+4], 'little')
        chunk = ''
        for _ in range(7):
            chunk = _B36[n % 36] + chunk
            n //= 36
        parts.append(chunk)

    return '"KARITY/' + (length_enc or '0') + ':' + ''.join(parts) + '"'


def _to_table_blob(data: bytes, n_chunks: int) -> str:
    """bytes → 스크램블된 base36 청크 테이블 리터럴 (blob_form="table").

    _to_base36의 "KARITY/..." 문자열을 N조각으로 잘라 {[k]="chunk",...} 형태로
    emit하되, 소스상 순서는 셔플하고 키(k)는 원래 위치(1..N)를 유지한다.
    런타임은 table.concat(t)로 재조립 — concat은 키 1..N을 순서대로 읽으므로
    _to_base36가 만들었을 문자열과 바이트 단위로 동일하다. (run 쪽은 type 분기
    없이 이 형태로 고정 emit되므로 table.concat 프롤로그만 주입하면 된다.)
    """
    s = _to_base36(data)
    assert s[0] == '"' and s[-1] == '"'
    s = s[1:-1]                       # 양끝 따옴표 제거 → 순수 base36 문자열

    L = len(s)
    n_chunks = max(1, min(n_chunks, L))
    size = L // n_chunks
    chunks = []
    for i in range(n_chunks):
        start = i * size
        end   = L if i == n_chunks - 1 else (i + 1) * size
        chunks.append(s[start:end])

    indexed = list(enumerate(chunks, start=1))   # (key, chunk)
    random.shuffle(indexed)                        # 소스 순서만 섞고 키는 유지
    parts = [f'[{k}]="{c}"' for k, c in indexed]
    return "{" + ",".join(parts) + "}"


def _to_numeric_blob(data: bytes) -> str:
    """bytes → 32비트 정수 테이블 리터럴 (blob_form="numeric").

    4바이트 리틀엔디언 청크를 base36 인코딩 없이 그대로 정수로 저장한다:
    {[0]=len,[k]=int,...}. 키(1..N)는 위치를 유지하고 소스 순서만 셔플한다.
    [0]에 원본 바이트 길이를 담아 런타임이 4바이트 정렬 패딩을 잘라낸다.
    ({[n]=10314814,...} 형태 — 문자열/청크와 완전히 다른 컨테이너 모양.)
    """
    L = len(data)
    padded = data + b'\x00' * ((4 - L % 4) % 4)
    parts = [f"[0]={L}"]
    for i in range(0, len(padded), 4):
        n = int.from_bytes(padded[i:i + 4], 'little')
        parts.append(f"[{i // 4 + 1}]={n}")
    random.shuffle(parts)                            # [0] 포함 전체 순서 셔플
    return "{" + ",".join(parts) + "}"


# numeric 형태 재조립 프롤로그: 정수 테이블 blob([0]=len, [1..N]=int32)에서
# 원본 암호문 바이트 문자열을 직접 복원한다(from_base36 우회). 재난독화 전에
# 주입되므로 string.char/table.unpack도 함께 localize된다.
_NUMERIC_DECODE = (
    "(function(_t)local _L=_t[0];local _b={};local _p=0;"
    "for _i=1,#_t do local _n=_t[_i];"
    "_b[_p+1]=_n&0xFF;_b[_p+2]=(_n>>8)&0xFF;"
    "_b[_p+3]=(_n>>16)&0xFF;_b[_p+4]=(_n>>24)&0xFF;_p=_p+4 end;"
    "while #_b>_L do _b[#_b]=nil end;"
    "local _o={};for _i=1,#_b,4096 do local _e=_i+4095;if _e>#_b then _e=#_b end;"
    "_o[#_o+1]=string.char(table.unpack(_b,_i,_e))end;return table.concat(_o)end)(blob)"
)


_LUA_OP_COUNT = 60  # Lua 5.3 opcode 0~46 plus karity pseudo ops
_VOP_SPACE    = 128  # 7비트 op × 256 variant = 32768, 실용 범위는 128*256


def _make_vop_map(used_vops: set[int] | None = None) -> dict[int, list[int]]:
    """원본op(0~46) → alias vop 목록 매핑.

    각 원본 op당 2~3개의 alias vop를 생성.
    serialize 시 alias 중 랜덤 선택해서 emit → 같은 op라도 매번 다른 vop.
    vop = op(7비트) | (variant(8비트) << 7)

    used_vops를 넘기면 그 집합에 누적 — 멀티VM에서 VM 간 vop 공간을 disjoint로
    유지하기 위해 공유 집합을 전달한다.
    """
    if used_vops is None:
        used_vops = set()
    vop_map: dict[int, list[int]] = {}

    for orig in range(_LUA_OP_COUNT):
        n_aliases = random.randint(2, 3)
        aliases = []
        for _ in range(n_aliases):
            while True:
                op_slot = random.randint(0, _VOP_SPACE - 1)
                variant = random.randint(0, 255)
                vop = op_slot | (variant << 7)
                if vop not in used_vops:
                    used_vops.add(vop)
                    aliases.append(vop)
                    break
        vop_map[orig] = aliases
    return vop_map


def _new_unique_vop(used: set[int]) -> int:
    while True:
        vop = random.randint(0, 0x7FFF)
        if vop not in used:
            used.add(vop)
            return vop


def _make_fuse_map(used_vops: set[int],
                   pairs: set[tuple[int, int]]) -> dict[tuple[int, int], int]:
    """fuse 가능한 각 (op1, op2) 쌍마다 고유 vop 1개 할당."""
    return {pair: _new_unique_vop(used_vops) for pair in sorted(pairs)}


def _make_split_map(used_vops: set[int],
                    split_ops: set[int]) -> dict[int, dict[str, tuple[int, ...]]]:
    """각 split 가능 op마다 2-part, 3-part 용 vop 튜플 할당.

    split_ops: split 핸들러를 만들 op 집합 (실제 바이트코드에 등장하는
    splittable op으로 한정 — 안 쓰는 op까지 CFF 핸들러를 만들면 체인 폭증).
    """
    split_map: dict[int, dict[str, tuple[int, ...]]] = {}
    for op in sorted(split_ops):
        split_map[op] = {
            "2": (_new_unique_vop(used_vops), _new_unique_vop(used_vops)),
            "3": (_new_unique_vop(used_vops), _new_unique_vop(used_vops),
                  _new_unique_vop(used_vops)),
        }
    return split_map


def _make_defer_map(used_vops: set[int],
                    defer_ops: set[int]) -> dict[int, int]:
    """Allocate one producer vop for each lazy cross-instruction operation."""
    return {op: _new_unique_vop(used_vops) for op in sorted(defer_ops)}


def _dump_function_stripped(
    vm_func_src: str,
    header: str,
    decoy_name: str,
    decoy_value: str,
) -> bytes:
    """
    vm_func_src(= "return function(...) ... end")를 최종 출력과 동일한
    enclosing 컨텍스트(`header` 주석 + `local a="..."` 프리픽스) 안에서
    load()로 로드해 얻은 내부 함수(_vmf에 해당)를 string.dump(f, true)로
    직렬화한 바이트를 반환한다.

    strip=true라도 함수의 linedefined/lastlinedefined 등은 enclosing
    chunk에서의 위치(앞에 몇 줄이 있는지)에 의존하므로, 최종 출력에서
    _vmf가 정의되는 컨텍스트(헤더 주석 포함)를 그대로 재현해야 빌드 타임
    dump와 런타임 dump가 바이트 단위로 일치한다.
    """
    wrapped = (
        f'{header}local {decoy_name}="{decoy_value}"'
        f'{vm_func_src};'
    )

    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False, mode="w", encoding="utf-8") as f:
        f.write(wrapped)
        src_path = f.name

    dump_path   = src_path + ".dump"
    helper_path = src_path + ".helper.lua"

    src_path_lua  = src_path.replace("\\", "\\\\")
    dump_path_lua = dump_path.replace("\\", "\\\\")

    helper = (
        f'local fh=io.open("{src_path_lua}","rb")\n'
        f'local content=fh:read("a") fh:close()\n'
        f'local chunk,err=load(content)\n'
        f'if not chunk then error(err) end\n'
        f'local f=chunk()\n'
        f'local out=io.open("{dump_path_lua}","wb")\n'
        f'out:write(string.dump(f,true)) out:close()\n'
    )
    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(helper)

    try:
        result = subprocess.run([str(_LUA), helper_path], capture_output=True)
        if result.returncode != 0:
            error = result.stderr.decode(errors="replace")
            matches = re.findall(r':(\d+):', error)
            excerpt = ""
            if matches:
                line_no = max(map(int, matches))
                lines = wrapped.splitlines()
                lo = max(0, line_no - 24)
                hi = min(len(lines), line_no + 3)
                excerpt = "\n" + "\n".join(
                    f"{i + 1}: {lines[i]}" for i in range(lo, hi)
                )
            raise RuntimeError(f"lua dump failed: {error}{excerpt}")

        with open(dump_path, "rb") as f:
            return f.read()
    finally:
        for p in (src_path, dump_path, helper_path):
            if os.path.exists(p):
                os.unlink(p)


def _load_vm() -> str:
    src = _VM_LUA_PATH.read_text(encoding="utf-8")
    cutoff = src.find("\nif arg and arg[0]")
    if cutoff != -1:
        src = src[:cutoff]
    return src


def _hex64() -> str:
    return f"0x{random.getrandbits(64):016X}"


def _rand_lua_name(length: int = 7) -> str:
    return "_" + "".join(random.choices(_NAME_CHARS, k=length))


def _exact_graph_source(source: str) -> str:
    return "--[[KARITY_EXACT_BEGIN]]" + source + "--[[KARITY_EXACT_END]]"


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


def _make_integer_graph_func(op_kind: str) -> str:
    a, b, state, slots, regs, active, boxes = [_rand_lua_name() for _ in range(7)]
    ctx = _rand_lua_name()
    state_key = random.randint(700, 1200)
    carry_key = 611

    # IR nodes are semantic classes plus dependency edges. IDs carry no execution
    # order; a randomized Kahn schedule below decides the emitted topological order.
    nodes: dict[int, dict] = {}
    next_id = 0

    def add_node(kind: str, deps: list[int]) -> int:
        nonlocal next_id
        node_id = next_id
        next_id += 1
        nodes[node_id] = {"kind": kind, "deps": tuple(dict.fromkeys(deps))}
        return node_id

    core = add_node("core", [])
    zero_nodes: list[int] = []
    for _ in range(random.randint(8, 12)):
        deps = random.sample(zero_nodes, k=min(len(zero_nodes), random.randint(0, 2)))
        zero_nodes.append(add_node("zero", deps))

    value = core
    for i in range(random.randint(max(12, len(zero_nodes)), 18)):
        deps = [value, zero_nodes[i % len(zero_nodes)]]
        if random.random() < 0.45:
            deps.append(random.choice(zero_nodes))
        value = add_node("identity", deps)
    sink_zeros = random.sample(zero_nodes, 2)
    sink = add_node("sink", [value, *sink_zeros])

    indegree = {node_id: len(node["deps"]) for node_id, node in nodes.items()}
    children = {node_id: [] for node_id in nodes}
    for node_id, node in nodes.items():
        for dep in node["deps"]:
            children[dep].append(node_id)
    ready = [node_id for node_id, degree in indegree.items() if degree == 0]
    topo: list[int] = []
    while ready:
        node_id = ready.pop(random.randrange(len(ready)))
        topo.append(node_id)
        for child in children[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(topo) != len(nodes):
        raise RuntimeError(f"generated {op_kind} graph contains a cycle")

    names = {node_id: _rand_lua_name() for node_id in nodes}
    lines = ["(function()local " + ",".join(names.values()) + ";"]

    for node_id in topo:
        node = nodes[node_id]
        name = names[node_id]
        deps = [f"{names[d]}({ctx})" for d in node["deps"]]
        cached = f"local q={ctx}.k[{node_id + 1}];if q~=nil then return q end;"
        kind = node["kind"]
        if kind == "core":
            body = f"local r={_make_integer_expr(op_kind, f'{ctx}.a', f'{ctx}.b')};{ctx}.t=({ctx}.t~(r|(~r)));"
        elif kind == "zero":
            terms = deps or [f"{ctx}.a", f"{ctx}.b"]
            joined = "~".join(f"(({term})~({term}))" for term in terms)
            body = (f"local r=({joined});{ctx}.t=(({ctx}.t~r)~(({ctx}.s[{state_key}] or 0)&r));"
                    f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~{ctx}.t~r);")
        elif kind == "identity":
            source = deps[0]
            zeros = "+".join(deps[1:])
            mode = random.randrange(3)
            if mode == 0:
                mask = _hex64()
                expr = f"((({source}~{mask})~{mask})+({zeros}))"
            elif mode == 1:
                key = _hex64()
                expr = f"((({source}+{key})-{key})+({zeros}))"
            else:
                expr = f"(({source})+({zeros})+(({ctx}.t~{ctx}.t)))"
            body = f"local r={expr};{ctx}.t=({ctx}.t~(r&r)~({zeros}));"
        else:
            body = f"local r=({deps[0]})+({deps[1]})+({deps[2]});{ctx}.t=({ctx}.t~r~(r<<1));"
        lines.append(f"{name}=function({ctx}){cached}{body}{ctx}.k[{node_id + 1}]=r;return r end;")

    out = _rand_lua_name()
    slot = _rand_lua_name()
    index = _rand_lua_name()
    lines.extend([
        f"return function({a},{b},{state},{slots},{regs},{active},{boxes})",
        f"{state}={state} or {{}};{active}={active} or {{}};local {ctx}={{a={a},b={b},s={state},k={{}},t=(({a}~{b})~{_hex64()}~({state}[{carry_key}] or 0))}};",
        f"local {out}={names[sink]}({ctx});",
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];if not {boxes}[{slot}] then ",
        f"local q=({out}~{ctx}.t~(({index}*{_hex64()})&-1));{regs}[{slot}]=q;",
        f"{active}[{slot}]=true;{state}[{state_key}]=(({state}[{state_key}] or 0)~q~{slot}) end end end;",
        f"return {out} end end)()",
    ])
    return "".join(lines)


def _make_value_graph_func() -> str:
    value, state, slots, regs, active, boxes, tag = [_rand_lua_name() for _ in range(7)]
    ctx = _rand_lua_name()
    nodes: dict[int, dict] = {0: {"kind": "source", "deps": ()}}
    zeros: list[int] = []
    next_id = 1
    for _ in range(random.randint(7, 11)):
        deps = random.sample(zeros, min(len(zeros), random.randint(0, 2)))
        nodes[next_id] = {"kind": "zero", "deps": tuple(deps)}
        zeros.append(next_id)
        next_id += 1
    current = 0
    for i in range(random.randint(10, 16)):
        deps = [current, zeros[i % len(zeros)]]
        if random.random() < 0.4:
            deps.append(random.choice(zeros))
        nodes[next_id] = {"kind": "identity", "deps": tuple(dict.fromkeys(deps))}
        current = next_id
        next_id += 1
    nodes[next_id] = {"kind": "sink", "deps": (current, *random.sample(zeros, 2))}
    sink = next_id

    indegree = {i: len(node["deps"]) for i, node in nodes.items()}
    children = {i: [] for i in nodes}
    for i, node in nodes.items():
        for dep in node["deps"]:
            children[dep].append(i)
    ready = [i for i, degree in indegree.items() if degree == 0]
    topo: list[int] = []
    while ready:
        i = ready.pop(random.randrange(len(ready)))
        topo.append(i)
        for child in children[i]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)

    names = {i: _rand_lua_name() for i in nodes}
    state_key = random.randint(1201, 1700)
    lines = ["(function()local " + ",".join(names.values()) + ";"]
    for i in topo:
        node = nodes[i]
        name = names[i]
        deps = [f"{names[d]}({ctx})" for d in node["deps"]]
        cached = f"if {ctx}.n[{i + 1}] then return {ctx}.k[{i + 1}] end;"
        if node["kind"] == "source":
            body = f"local r={ctx}.v;"
        elif node["kind"] == "zero":
            calls = "+".join(deps) if deps else f"({ctx}.g~{ctx}.g)"
            body = f"local r=({calls});r=(r~r);{ctx}.t=({ctx}.t~r~({ctx}.g&0xFF));"
        else:
            source = deps[0]
            zeros_expr = "+".join(deps[1:])
            body = f"local z=({zeros_expr});local r={source};{ctx}.t=({ctx}.t~z~({ctx}.g&0xFF));"
        lines.append(
            f"{name}=function({ctx}){cached}{body}{ctx}.n[{i + 1}]=true;"
            f"{ctx}.k[{i + 1}]=r;return r end;"
        )
    out, index, slot = _rand_lua_name(), _rand_lua_name(), _rand_lua_name()
    lines.extend([
        f"return function({value},{state},{slots},{regs},{active},{boxes},{tag})",
        f"local {ctx}={{v={value},s={state},k={{}},n={{}},g={tag},t=(({state}[611] or 0)~{tag}~{_hex64()})}};",
        f"local {out}={names[sink]}({ctx});{state}[{state_key}]=(({state}[{state_key}] or 0)~{ctx}.t~{tag});",
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];if not {boxes}[{slot}] then ",
        f"local q=({ctx}.t~{tag}~(({index}*{_hex64()})&-1));{regs}[{slot}]=q;",
        f"{active}[{slot}]=true;{state}[{state_key}]=(({state}[{state_key}] or 0)~q~{slot}) end end end;",
        f"return {out} end end)()",
    ])
    return "".join(lines)


def _make_call_route_func() -> str:
    """Build an acyclic tail-call router whose only observable result is next(q)."""
    terminal, query, ctx = [_rand_lua_name() for _ in range(3)]
    count = random.randint(14, 22)
    names = [_rand_lua_name() for _ in range(count)]
    order = list(range(count))
    random.shuffle(order)
    lines = ["(function()local " + ",".join(names) + ";"]

    for i in order:
        name = names[i]
        if i == count - 1:
            body = (
                f"{ctx}.q[__VM_Q_FLOW__]=({ctx}.q[__VM_Q_TRACE__]~"
                f"({ctx}.q[__VM_Q_FLOW__] or 0));"
                f"local d={ctx}.q[__VM_Q_LEDGER__];if d then "
                f"d[1]=((d[1] or 0)~{ctx}.q[__VM_Q_TRACE__])&-1 end;"
                f"return {ctx}.f({ctx}.q)"
            )
        elif i == 0:
            salt = _hex64()
            body = (
                f"{ctx}.q[__VM_Q_TRACE__]=({ctx}.q[__VM_Q_TRACE__]~{salt})&-1;"
                f"return {names[1]}({ctx})"
            )
        elif i == 1:
            salt = _hex64()
            body = (
                f"{ctx}.q[__VM_Q_TRACE__]=(({ctx}.q[__VM_Q_TRACE__]+{salt})~"
                f"{ctx}.q[__VM_Q_KIND__])&-1;"
                f"if {ctx}.q[__VM_Q_BUDGET__]>0 then "
                f"{ctx}.q[__VM_Q_BUDGET__]={ctx}.q[__VM_Q_BUDGET__]-1;"
                f"return {names[0]}({ctx}) end;return {names[2]}({ctx})"
            )
        else:
            primary = i + 1
            maximum_skip = min(count - 1, i + random.randint(2, 5))
            alternate = random.randint(primary, maximum_skip)
            salt = _hex64()
            body = (
                f"{ctx}.q[__VM_Q_TRACE__]=(({ctx}.q[__VM_Q_TRACE__]~{salt})+{i + 1})&-1;"
                f"if (({ctx}.q[__VM_Q_TRACE__]~{ctx}.q[__VM_Q_KIND__]~{salt})&1)==0 then "
                f"return {names[primary]}({ctx}) end;"
                f"return {names[alternate]}({ctx})"
            )
        lines.append(f"{name}=function({ctx}){body} end;")

    seed = _hex64()
    lines.append(
        f"return function({terminal},{query})"
        f"{query}[__VM_Q_TRACE__]=({query}[__VM_Q_TRACE__] or "
        f"({query}[__VM_Q_KIND__]~{seed}));"
        f"{query}[__VM_Q_BUDGET__]=({query}[__VM_Q_BUDGET__] or "
        f"((({query}[__VM_Q_KIND__]~{seed})&3)+1));"
        f"return {names[0]}({{f={terminal},q={query}}}) end end)()"
    )
    return "".join(lines)


def _make_control_graph_func() -> str:
    packet, state, ctx = [_rand_lua_name() for _ in range(3)]
    count = random.randint(12, 18)
    names = [_rand_lua_name() for _ in range(count)]
    order = list(range(count))
    random.shuffle(order)
    state_key = random.randint(1701, 2200)
    lines = ["(function()local " + ",".join(names) + ";"]

    for i in order:
        name = names[i]
        if i == count - 1:
            body = f"return {ctx}.q"
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 4))
            salt = _hex64()
            loop_salt = _hex64()
            body = (
                f"local o={ctx}.q[__VM_CF_KEY__];local n=(o~{salt}~"
                f"({ctx}.s[{state_key}] or 0))&-1;"
                f"for j=1,(({ctx}.q[__VM_CF_TRACE__]&3)+1) do "
                f"n=(n~((j*{loop_salt})&-1))&-1 end;"
                f"for _,f in ipairs({ctx}.q[__VM_CF_FIELDS__]) do "
                f"{ctx}.q[f]=({ctx}.q[f]~o)~n end;"
                f"{ctx}.q[__VM_CF_KEY__]=n;"
                f"{ctx}.q[__VM_CF_TRACE__]=({ctx}.q[__VM_CF_TRACE__]~n~{salt})&-1;"
                f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~n~{i + 1});"
                f"if ((n~{ctx}.q[__VM_CF_TRACE__])&1)==0 then "
                f"return {names[primary]}({ctx}) end;"
                f"return {names[alternate]}({ctx})"
            )
        lines.append(f"{name}=function({ctx}){body} end;")

    seed = _hex64()
    lines.append(
        f"return function({packet},{state})"
        f"{packet}[__VM_CF_TRACE__]=({packet}[__VM_CF_TRACE__] or "
        f"({packet}[__VM_CF_KEY__]~{seed}));"
        f"return {names[0]}({{q={packet},s={state}}}) end end)()"
    )
    return "".join(lines)


def _make_occurrence_graph_func(site: int) -> str:
    bank, pick, a, b, state, slots, regs, active, boxes, ctx = [
        _rand_lua_name() for _ in range(10)
    ]
    count = random.randint(7, 11)
    names = [_rand_lua_name() for _ in range(count)]
    order = list(range(count))
    random.shuffle(order)
    state_key = random.randint(2201, 2800)
    lines = ["(function()local " + ",".join(names) + ";"]
    for i in order:
        if i == count - 1:
            body = (
                f"local k=(({ctx}.p~{ctx}.t)&1)+1;"
                f"return {ctx}.g[k]({ctx}.a,{ctx}.b,{ctx}.s,{ctx}.l,"
                f"{ctx}.r,{ctx}.x,{ctx}.o)"
            )
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 3))
            salt = _hex64()
            body = (
                f"{ctx}.t=(({ctx}.t~{salt})+{i + 1}+"
                f"({ctx}.s[{state_key}] or 0))&-1;"
                f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~{ctx}.t~{site});"
                f"if (({ctx}.t~{site})&1)==0 then return {names[primary]}({ctx}) end;"
                f"return {names[alternate]}({ctx})"
            )
        lines.append(f"{names[i]}=function({ctx}){body} end;")
    seed = _hex64()
    lines.append(
        f"return function({bank},{pick},{a},{b},{state},{slots},{regs},{active},{boxes})"
        f"return {names[0]}({{g={bank},p={pick},a={a},b={b},s={state},l={slots},"
        f"r={regs},x={active},o={boxes},t=({site}~{seed}~({state}[611] or 0))}})"
        f"end end)()"
    )
    return "".join(lines)


def _make_loop_ir_func(kind: str) -> str:
    packet, state, ctx = [_rand_lua_name() for _ in range(3)]
    semantic_count = 2 if kind == "FORLOOP" else 1
    wrapper_count = random.randint(7, 11)
    total = semantic_count + wrapper_count + 1
    names = [_rand_lua_name() for _ in range(total)]
    state_key = random.randint(2801, 3300)
    definitions: list[str] = []

    if kind == "FORLOOP":
        definitions.append(
            f"{names[0]}=function({ctx})local q={ctx}.q;"
            f"q[__VM_CF_VALUE__]=q[__VM_CF_VALUE__]+q[__VM_CF_STEP__];"
            f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~{ctx}.g);return q end;"
        )
        definitions.append(
            f"{names[1]}=function({ctx})local q={names[0]}({ctx});local v=q[__VM_CF_VALUE__];"
            f"local d=q[__VM_CF_STEP__];local l=q[__VM_CF_LIMIT__];"
            f"q[__VM_CF_TAKE__]=(d>0 and v<=l) or (d<=0 and v>=l);return q end;"
        )
        previous = 1
    elif kind == "FORPREP":
        definitions.append(
            f"{names[0]}=function({ctx})local q={ctx}.q;"
            f"q[__VM_CF_VALUE__]=q[__VM_CF_VALUE__]-q[__VM_CF_STEP__];return q end;"
        )
        previous = 0
    else:
        definitions.append(
            f"{names[0]}=function({ctx})local q={ctx}.q;"
            f"q[__VM_CF_TAKE__]=(q[__VM_CF_VALUE__]~=nil);return q end;"
        )
        previous = 0

    for i in range(semantic_count, total - 1):
        dep = previous
        salt = _hex64()
        definitions.append(
            f"{names[i]}=function({ctx})local q={names[dep]}({ctx});"
            f"{ctx}.g=(({ctx}.g~{salt})+{i + 1})&-1;"
            f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~{ctx}.g);return q end;"
        )
        previous = i
    definitions.append(
        f"{names[-1]}=function({ctx})return {names[previous]}({ctx}) end;"
    )
    random.shuffle(definitions)
    seed = _hex64()
    return (
        "(function()local " + ",".join(names) + ";"
        + "".join(definitions)
        + f"return function({packet},{state})return {names[-1]}({{q={packet},s={state},"
          f"g=({seed}~({state}[611] or 0))}}) end end)()"
    )


def _make_semantic_ir_func(kind: str) -> str:
    x, y, z, state, ctx = [_rand_lua_name() for _ in range(5)]
    count = random.randint(7, 11)
    names = [_rand_lua_name() for _ in range(count)]
    state_key = random.randint(3301, 3900)
    if kind == "GET":
        semantic = f"local r={ctx}.x[{ctx}.y];"
    elif kind == "SET":
        semantic = f"{ctx}.x[{ctx}.y]={ctx}.z;local r={ctx}.z;"
    elif kind == "EQ":
        semantic = f"local r=({ctx}.x=={ctx}.y);"
    elif kind == "LT":
        semantic = f"local r=({ctx}.x<{ctx}.y);"
    elif kind == "LE":
        semantic = f"local r=({ctx}.x<={ctx}.y);"
    elif kind == "TRUTH":
        semantic = f"local r=(not not {ctx}.x);"
    elif kind == "MOD":
        semantic = f"local r=({ctx}.x%{ctx}.y);"
    elif kind == "POW":
        semantic = f"local r=({ctx}.x^{ctx}.y);"
    elif kind == "DIV":
        semantic = f"local r=({ctx}.x/{ctx}.y);"
    elif kind == "IDIV":
        semantic = f"local r=({ctx}.x//{ctx}.y);"
    elif kind == "NOT":
        semantic = f"local r=(not {ctx}.x);"
    elif kind == "LEN":
        semantic = f"local r=(#{ctx}.x);"
    elif kind == "CONCAT":
        semantic = (
            f"local r={ctx}.x[{ctx}.z];"
            f"for i={ctx}.z-1,1,-1 do r={ctx}.x[i]..r end;"
        )
    elif kind == "NEWTABLE":
        semantic = "local r={};"
    elif kind == "SETLIST":
        semantic = (
            f"for i=1,{ctx}.z[2] do {ctx}.x[{ctx}.z[1]+i]={ctx}.y[i] end;"
            f"local r={ctx}.x;"
        )
    elif kind == "CLOSURE":
        semantic = f"local r={ctx}.x({ctx}.y);"
    elif kind == "VARARG":
        semantic = (
            f"for i=1,{ctx}.z[1] do {ctx}.x({ctx}.y+i-1,{ctx}.z[2][i]) end;"
            f"local r={ctx}.z[1];"
        )
    else:
        semantic = f"local r={ctx}.x;"

    definitions = [
        f"{names[0]}=function({ctx}){semantic}{ctx}.v=r;return r end;"
    ]
    previous = 0
    for i in range(1, count - 1):
        salt = _hex64()
        definitions.append(
            f"{names[i]}=function({ctx})local r={names[previous]}({ctx});"
            f"{ctx}.g=(({ctx}.g~{salt})+{i})&-1;"
            f"{ctx}.s[{state_key}]=(({ctx}.s[{state_key}] or 0)~{ctx}.g);return r end;"
        )
        previous = i
    definitions.append(
        f"{names[-1]}=function({ctx})return {names[previous]}({ctx}) end;"
    )
    random.shuffle(definitions)
    seed = _hex64()
    context = (
        f"{{x={x},y={y},z={z},s={state},g=({seed}~({state}[611] or 0))}}"
    )
    direct_semantic = (
        semantic
        .replace(f"{ctx}.x", x)
        .replace(f"{ctx}.y", y)
        .replace(f"{ctx}.z", z)
    )
    return (
        "(function()local " + ",".join(names) + ";" + "".join(definitions)
        + f"return {{function({x},{y},{z},{state})return {names[-1]}({context}) end,"
          f"function({x},{y},{z},{state}){direct_semantic}return r end}} end)()"
    )


def _random_topological_order(nodes: dict[int, dict], label: str) -> list[int]:
    """Compile-time scheduling for DAG graphs; no runtime node dispatcher remains."""
    indegree = {node_id: len(node["deps"]) for node_id, node in nodes.items()}
    children = {node_id: [] for node_id in nodes}
    for node_id, node in nodes.items():
        for dep in node["deps"]:
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
        raise RuntimeError(f"generated {label} graph contains a cycle")
    return order


def _compile_integer_graph_func(op_kind: str) -> str:
    """Compile an arithmetic DAG into one specialized straight-line handler."""
    a, b, state, slots, regs, active, boxes = [_rand_lua_name() for _ in range(7)]
    trace = _rand_lua_name()
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
    names = {node_id: _rand_lua_name() for node_id in nodes}
    lines = [
        f"function({a},{b},{state},{slots},{regs},{active},{boxes})",
        f"{state}={state} or {{}};{active}={active} or {{}};",
        "local " + ",".join(names.values()) + ";",
        f"local {trace}=(({a}~{b})~{_hex64()}~({state}[611] or 0));",
    ]
    for node_id in order:
        node = nodes[node_id]
        name = names[node_id]
        deps = [names[dep] for dep in node["deps"]]
        if node["kind"] == "core":
            lines.append(
                f"{name}={_make_integer_expr(op_kind, a, b)};"
                f"{trace}=({trace}~({name}|(~{name})));"
            )
        elif node["kind"] == "zero":
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
            lines.append(
                f"{name}=({deps[0]})+({deps[1]})+({deps[2]});"
                f"{trace}=({trace}~{name}~({name}<<1));"
            )

    index, slot, mixed = [_rand_lua_name() for _ in range(3)]
    out = names[sink]
    lines.extend([
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];",
        f"if not {boxes}[{slot}] then local {mixed}=({out}~{trace}~"
        f"(({index}*{_hex64()})&-1));{regs}({slot},{mixed});",
        f"{active}[{slot}]=true;{state}[{state_key}]=(({state}[{state_key}] or 0)~"
        f"{mixed}~{slot}) end end end;return {out} end",
    ])
    return "".join(lines)


def _compile_value_graph_func() -> str:
    """Compile a value diffusion DAG without runtime closures or memo tables."""
    value, state, slots, regs, active, boxes, tag = [_rand_lua_name() for _ in range(7)]
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

    names = {node_id: _rand_lua_name() for node_id in nodes}
    trace = _rand_lua_name()
    state_key = random.randint(1201, 1700)
    lines = [
        f"function({value},{state},{slots},{regs},{active},{boxes},{tag})",
        "local " + ",".join(names.values()) + ";",
        f"local {trace}=(({state}[611] or 0)~{tag}~{_hex64()});",
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
                f"{name}=({source});{name}=({name}~{name});"
                f"{trace}=({trace}~{name}~({tag}&0xFF));"
            )
        else:
            zero_expr = "+".join(deps[1:])
            lines.append(
                f"{name}={deps[0]};{trace}=({trace}~({zero_expr})~({tag}&0xFF));"
            )
    out = names[sink]
    index, slot, mixed = [_rand_lua_name() for _ in range(3)]
    lines.extend([
        f"{state}[{state_key}]=(({state}[{state_key}] or 0)~{trace}~{tag});",
        f"if {slots} then for {index}=1,#{slots} do local {slot}={slots}[{index}];",
        f"if not {boxes}[{slot}] then local {mixed}=({trace}~{tag}~"
        f"(({index}*{_hex64()})&-1));{regs}({slot},{mixed});{active}[{slot}]=true;",
        f"{state}[{state_key}]=(({state}[{state_key}] or 0)~{mixed}~{slot}) end end end;",
        f"return {out} end",
    ])
    return "".join(lines)


def _compiled_label_blocks(entry: str, blocks: list[tuple[str, str]]) -> str:
    """Lay graph blocks out randomly while preserving explicit build-time edges."""
    shuffled = list(blocks)
    random.shuffle(shuffled)
    return f"goto {entry};" + "".join(
        f"::{label}::do {body} end;" for label, body in shuffled
    )


def _compile_call_route_func() -> str:
    terminal, query = [_rand_lua_name() for _ in range(2)]
    count = random.randint(14, 22)
    labels = [_rand_lua_name() for _ in range(count)]
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            body = (
                f"{query}[__VM_Q_FLOW__]=({query}[__VM_Q_TRACE__]~"
                f"({query}[__VM_Q_FLOW__] or 0));local d={query}[__VM_Q_LEDGER__];"
                f"if d then d[1]=((d[1] or 0)~{query}[__VM_Q_TRACE__])&-1 end;"
                f"return {terminal}({query})"
            )
        elif i == 0:
            salt = _hex64()
            body = (
                f"{query}[__VM_Q_TRACE__]=({query}[__VM_Q_TRACE__]~{salt})&-1;"
                f"goto {labels[1]}"
            )
        elif i == 1:
            salt = _hex64()
            body = (
                f"{query}[__VM_Q_TRACE__]=(({query}[__VM_Q_TRACE__]+{salt})~"
                f"{query}[__VM_Q_KIND__])&-1;if {query}[__VM_Q_BUDGET__]>0 then "
                f"{query}[__VM_Q_BUDGET__]={query}[__VM_Q_BUDGET__]-1;goto {labels[0]} end;"
                f"goto {labels[2]}"
            )
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + random.randint(2, 5)))
            salt = _hex64()
            body = (
                f"{query}[__VM_Q_TRACE__]=(({query}[__VM_Q_TRACE__]~{salt})+{i + 1})&-1;"
                f"if (({query}[__VM_Q_TRACE__]~{query}[__VM_Q_KIND__]~{salt})&1)==0 "
                f"then goto {labels[primary]} end;goto {labels[alternate]}"
            )
        blocks.append((label, body))
    seed = _hex64()
    return (
        f"function({terminal},{query}){query}[__VM_Q_TRACE__]=({query}[__VM_Q_TRACE__] "
        f"or ({query}[__VM_Q_KIND__]~{seed}));{query}[__VM_Q_BUDGET__]="
        f"({query}[__VM_Q_BUDGET__] or ((({query}[__VM_Q_KIND__]~{seed})&3)+1));"
        + _compiled_label_blocks(labels[0], blocks) + "end"
    )


def _compile_control_graph_func() -> str:
    packet, state = [_rand_lua_name() for _ in range(2)]
    count = random.randint(12, 18)
    labels = [_rand_lua_name() for _ in range(count)]
    state_key = random.randint(1701, 2200)
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            body = f"return {packet}"
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 4))
            salt, loop_salt = _hex64(), _hex64()
            body = (
                f"local o={packet}[__VM_CF_KEY__];local n=(o~{salt}~"
                f"({state}[{state_key}] or 0))&-1;for j=1,(({packet}[__VM_CF_TRACE__]&3)+1) "
                f"do n=(n~((j*{loop_salt})&-1))&-1 end;for _,f in ipairs("
                f"{packet}[__VM_CF_FIELDS__]) do {packet}[f]=({packet}[f]~o)~n end;"
                f"{packet}[__VM_CF_KEY__]=n;{packet}[__VM_CF_TRACE__]="
                f"({packet}[__VM_CF_TRACE__]~n~{salt})&-1;{state}[{state_key}]="
                f"(({state}[{state_key}] or 0)~n~{i + 1});if ((n~{packet}[__VM_CF_TRACE__])&1)==0 "
                f"then goto {labels[primary]} end;goto {labels[alternate]}"
            )
        blocks.append((label, body))
    seed = _hex64()
    return (
        f"function({packet},{state}){packet}[__VM_CF_TRACE__]=({packet}[__VM_CF_TRACE__] "
        f"or ({packet}[__VM_CF_KEY__]~{seed}));"
        + _compiled_label_blocks(labels[0], blocks) + "end"
    )


def _compile_occurrence_graph_func(family_seed: int) -> str:
    bank, pick, a, b, state, slots, regs, active, boxes, ledger, vm_state = [
        _rand_lua_name() for _ in range(11)
    ]
    site, selector, state_key, policy = [_rand_lua_name() for _ in range(4)]
    count = random.randint(7, 11)
    labels = [_rand_lua_name() for _ in range(count)]
    trace = _rand_lua_name()
    blocks: list[tuple[str, str]] = []
    for i, label in enumerate(labels):
        if i == count - 1:
            key, out, result_value, mixed = [_rand_lua_name() for _ in range(4)]
            body = (
                f"local {key}=(({pick}~{trace}~{selector}~"
                f"({state}[{state_key}] or 0)~{vm_state})%#{bank})+1;"
                f"local {out}={bank}[{key}]({a},{b},{state},{slots},{regs},{active},{boxes});"
                f"local {result_value}=0;if math.type({out})=='integer' then "
                f"{result_value}={out} end;local {mixed}=({trace}~{site}~{selector}~"
                f"{result_value}~{vm_state})&-1;{state}[{state_key}]="
                f"(({state}[{state_key}] or 0)~{mixed});if ({policy}&1)~=0 then "
                f"{state}[611]=(({state}[611] or 0)~{mixed}~{site})&-1 end;"
                f"if ({policy}&2)~=0 then {ledger}[1]=(({ledger}[1] or 0)~"
                f"{mixed}~{selector})&-1 end;return {out}"
            )
        else:
            primary = i + 1
            alternate = random.randint(primary, min(count - 1, i + 3))
            salt = _hex64()
            body = (
                f"{trace}=(({trace}~{salt})+{i + 1}+"
                f"({state}[{state_key}] or 0))&-1;"
                f"{state}[{state_key}]=(({state}[{state_key}] or 0)~{trace}~{site});"
                f"if (({trace}~{site})&1)==0 then goto {labels[primary]} end;"
                f"goto {labels[alternate]}"
            )
        blocks.append((label, body))
    return (
        f"function({bank},{pick},{a},{b},{state},{slots},{regs},{active},{boxes},"
        f"{ledger},{vm_state},{site},{selector},{state_key},{policy})"
        f"local {trace}=({site}~{selector}~{family_seed}~({state}[611] or 0)~"
        f"({state}[{state_key}] or 0)~{vm_state});"
        + _compiled_label_blocks(labels[0], blocks) + "end"
    )


def _compile_loop_ir_func(kind: str) -> str:
    packet, state = [_rand_lua_name() for _ in range(2)]
    trace = _rand_lua_name()
    state_key = random.randint(2801, 3300)
    labels: list[str] = []
    bodies: list[str] = []
    if kind == "FORLOOP":
        labels.extend([_rand_lua_name(), _rand_lua_name()])
        bodies.extend([
            f"{packet}[__VM_CF_VALUE__]={packet}[__VM_CF_VALUE__]+"
            f"{packet}[__VM_CF_STEP__];{state}[{state_key}]="
            f"(({state}[{state_key}] or 0)~{trace});goto {labels[1]}",
            f"local v={packet}[__VM_CF_VALUE__];local d={packet}[__VM_CF_STEP__];"
            f"local l={packet}[__VM_CF_LIMIT__];{packet}[__VM_CF_TAKE__]="
            f"(d>0 and v<=l) or (d<=0 and v>=l)",
        ])
    elif kind == "FORPREP":
        labels.append(_rand_lua_name())
        bodies.append(
            f"{packet}[__VM_CF_VALUE__]={packet}[__VM_CF_VALUE__]-"
            f"{packet}[__VM_CF_STEP__]"
        )
    else:
        labels.append(_rand_lua_name())
        bodies.append(
            f"{packet}[__VM_CF_TAKE__]=({packet}[__VM_CF_VALUE__]~=nil)"
        )
    for _ in range(random.randint(7, 11)):
        if bodies:
            bodies[-1] += f";goto "
        next_label = _rand_lua_name()
        if bodies:
            bodies[-1] += next_label
        labels.append(next_label)
        salt = _hex64()
        bodies.append(
            f"{trace}=(({trace}~{salt})+{len(labels)})&-1;{state}[{state_key}]="
            f"(({state}[{state_key}] or 0)~{trace})"
        )
    bodies[-1] += f";return {packet}"
    blocks = list(zip(labels, bodies))
    seed = _hex64()
    return (
        f"function({packet},{state})local {trace}=({seed}~({state}[611] or 0));"
        + _compiled_label_blocks(labels[0], blocks) + "end"
    )


def _semantic_source(kind: str, x: str, y: str, z: str) -> str:
    if kind == "GET": return f"local r={x}[{y}];"
    if kind == "SET": return f"{x}[{y}]={z};local r={z};"
    if kind == "EQ": return f"local r=({x}=={y});"
    if kind == "LT": return f"local r=({x}<{y});"
    if kind == "LE": return f"local r=({x}<={y});"
    if kind == "TRUTH": return f"local r=(not not {x});"
    if kind == "MOD": return f"local r=({x}%{y});"
    if kind == "POW": return f"local r=({x}^{y});"
    if kind == "DIV": return f"local r=({x}/{y});"
    if kind == "IDIV": return f"local r=({x}//{y});"
    if kind == "NOT": return f"local r=(not {x});"
    if kind == "LEN": return f"local r=(#{x});"
    if kind == "CONCAT": return f"local r={x}[{z}];for i={z}-1,1,-1 do r={x}[i]..r end;"
    if kind == "NEWTABLE": return "local r={};"
    if kind == "SETLIST":
        return f"for i=1,{z}[2] do {x}[{z}[1]+i]={y}[i] end;local r={x};"
    if kind == "CLOSURE": return f"local r={x}({y});"
    if kind == "VARARG":
        return f"for i=1,{z}[1] do {x}({y}+i-1,{z}[2][i]) end;local r={z}[1];"
    return f"local r={x};"


def _compile_semantic_ir_func(kind: str) -> str:
    x, y, z, state = [_rand_lua_name() for _ in range(4)]
    direct = _semantic_source(kind, x, y, z)
    trace = _rand_lua_name()
    result = _rand_lua_name()
    state_key = random.randint(3301, 3900)
    labels = [_rand_lua_name() for _ in range(random.randint(7, 11))]
    blocks: list[tuple[str, str]] = []
    # The semantic source may read the result again (notably CONCAT), so bind
    # every standalone result reference to the compiler-owned local.
    first = re.sub(r"\br\b", result, direct).replace("local " + result, result)
    blocks.append((labels[0], first + f"goto {labels[1]}"))
    for i in range(1, len(labels) - 1):
        salt = _hex64()
        blocks.append((labels[i],
            f"{trace}=(({trace}~{salt})+{i})&-1;{state}[{state_key}]="
            f"(({state}[{state_key}] or 0)~{trace});goto {labels[i + 1]}"))
    blocks.append((labels[-1], f"return {result}"))
    seed = _hex64()
    heavy = (
        f"function({x},{y},{z},{state})local {result};local {trace}="
        f"({seed}~({state}[611] or 0));"
        + _compiled_label_blocks(labels[0], blocks) + "end"
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


def _apply_handler_graphs(
    vm_code: str,
    graph_sites: set[int] | None = None,
    graph_family_count: int = 8,
    runtime_polymorphism_rate: float = 0.0,
    runtime_trace: bool = False,
    semantic_state_threading: bool = False,
    argument_virtualization: bool = False,
    upvalue_virtualization: bool = False,
    table_virtualization: bool = False,
    branch_virtualization: bool = False,
) -> str:
    threshold = max(0, min(0x10000, round(runtime_polymorphism_rate * 0x10000)))
    vm_code = vm_code.replace("__VM_POLY_THRESHOLD__", str(threshold))
    vm_code = vm_code.replace("__VM_POLY_TRACE__", "true" if runtime_trace else "false")
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
            x, y = _rand_lua_name(), _rand_lua_name()
            if arity == 1:
                native = f"function({x})return {operator}{x} end"
            else:
                native = f"function({x},{y})return {x}{operator}{y} end"
            native_entries.append(f"{{{native},{native}}}")
            graph_entries.append(
                "{" + ",".join(
                    _compile_integer_graph_func(kind) for _ in range(4)
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
    for slot in slots.values():
        share = random.randint(0x10000, 0x7FFFFFFF)
        route = random.getrandbits(1)
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
        "{[" + str(call_tags[2]) + "]=" + _compile_call_route_func()
        + ",[" + str(call_tags[3]) + "]=" + _compile_call_route_func() + "}"
    )
    vm_code = vm_code.replace(
        "__VM_CALL_GRAPHS__", _exact_graph_source(call_graph)
    )
    control_graphs = "{" + ",".join(
        _compile_control_graph_func() for _ in range(2)
    ) + "}"
    vm_code = vm_code.replace(
        "__VM_CONTROL_GRAPHS__", _exact_graph_source(control_graphs)
    )
    loop_tags = random.sample(range(0x10000, 0x7FFFFFFF), 3)
    loop_graphs = (
        "{[" + str(loop_tags[0]) + "]=" + _compile_loop_ir_func("FORLOOP")
        + ",[" + str(loop_tags[1]) + "]=" + _compile_loop_ir_func("FORPREP")
        + ",[" + str(loop_tags[2]) + "]=" + _compile_loop_ir_func("TFORLOOP") + "}"
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
            semantic_entries.append(_compile_semantic_ir_func(kind))
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
    for tag in data_tags:
        share = random.randint(0x10000, 0x7FFFFFFF)
        route = random.getrandbits(1)
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
        _compile_occurrence_graph_func(random.randint(0x10000, 0x7FFFFFFF))
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

_VM_RENAME_KEYS = [
    # proto 테이블 키
    "num_params", "is_vararg", "max_stack_size", "vm_id",
    "constants", "code", "avalanche", "graph_sites", "block_routes", "upvalues", "protos",
    "instack", "idx",
    # reader 메서드명
    "u8", "u16", "u32", "u64", "i64", "f64", "str",
]

_NAME_CHARS = string.ascii_lowercase + string.digits

def _rand_name(length: int = 6) -> str:
    return '_' + ''.join(random.choices(_NAME_CHARS, k=length))

def _rename_vm_keys(src: str) -> str:
    """vm.lua 내의 테이블 키 및 reader 메서드명을 랜덤 이름으로 치환."""
    import re
    rename_map = {k: _rand_name() for k in _VM_RENAME_KEYS}
    for orig, new in rename_map.items():
        src = re.sub(rf'\b{re.escape(orig)}\b', new, src)
        src = src.replace(f'["{orig}"]', f'["{new}"]')
        src = src.replace(f"['{orig}']", f"['{new}']")
    return src


def _obfuscate_vm_output(
    script: str,
    pass_names: list[str],
) -> tuple[str, list[dict]]:
    """Run structural VM passes, shared literal emitters, then text post-passes."""
    from ..pipeline import Pipeline
    from ..profiling import Profiler
    from ..registry import PASS_REGISTRY

    before: list[tuple[str, type]] = []
    after: list[tuple[str, type]] = []
    emitter_names: list[str] = []
    identifier_names: list[str] = []

    for name in pass_names:
        if name in EMITTER_PASS_NAMES:
            emitter_names.append(name)
            continue
        if name in {"rename_obf", "localize_globals"}:
            identifier_names.append(name)
            continue

        info = PASS_REGISTRY.get(name)
        if info is None:
            continue

        cls = info["cls"]
        if cls.__name__ == "VMPass":
            continue
        (after if issubclass(cls, PostPass) else before).append((name, cls))

    output = script
    details: list[dict] = []
    shared_ctx = None

    def apply_replacements(source: str, replacements) -> str:
        if not replacements:
            return source
        parts: list[str] = []
        pos = 0
        for replacement in sorted(replacements, key=lambda item: item.start):
            parts.append(source[pos:replacement.start])
            parts.append(replacement.new_text)
            pos = replacement.end + 1
        parts.append(source[pos:])
        return "".join(parts)

    def run_legacy(
        source: str,
        entries: list[tuple[str, type]],
    ) -> tuple[str, list[dict]]:
        if not entries:
            return source, []

        pipeline = Pipeline(show_header=False)
        names: list[str] = []
        for configured_name, cls in entries:
            if cls.__name__ == "FunctionObfuscationPass":
                pipeline.add(cls(skip_vm_dispatcher=True))
            else:
                pipeline.add(cls())
            names.append(configured_name)

        profiler = Profiler()
        transformed = pipeline.run(source, profiler=profiler)
        records: list[dict] = []
        for index, record in enumerate(profiler.records):
            data = record.as_dict()
            configured_name = names[index] if index < len(names) else record.name
            records.append({
                "phase": f"vm_output:{configured_name}",
                "class": record.name,
                "elapsed": data["elapsed"],
                "input_bytes": data["input_bytes"],
                "output_bytes": data["output_bytes"],
                "delta_bytes": data["delta_bytes"],
                **({"parser": data["parser"]} if "parser" in data else {}),
                **(
                    {"replacements": data["replacements"]}
                    if "replacements" in data else {}
                ),
            })
        return transformed, records

    # FunctionObfuscationPass is commonly a no-op for the generated VM. Plan
    # it on the same syntax tree used by the emitters so a no-op does not pay
    # for a throwaway full-source parse. If it does transform the source, the
    # later stages correctly parse the changed text again.
    if (
        before
        and before[0][1].__name__ == "FunctionObfuscationPass"
        and (identifier_names or emitter_names)
    ):
        from ..passes.ts_utils import parse as parse_ts

        parse_start = time.perf_counter()
        shared_ctx = parse_ts(output)
        details.append({
            "phase": "vm_output:source_parse",
            "class": "VmOutputEmitter",
            "elapsed": round(time.perf_counter() - parse_start, 6),
            "input_bytes": len(output.encode("utf-8")),
            "parser": "treesitter",
            "parse_count": 1,
        })

        configured_name, cls = before.pop(0)
        stage_start = time.perf_counter()
        function_pass = cls(skip_vm_dispatcher=True)
        function_replacements = function_pass.run(output, shared_ctx)
        transformed = apply_replacements(output, function_replacements)
        details.append({
            "phase": f"vm_output:{configured_name}",
            "class": cls.__name__,
            "elapsed": round(time.perf_counter() - stage_start, 6),
            "input_bytes": len(output.encode("utf-8")),
            "output_bytes": len(transformed.encode("utf-8")),
            "delta_bytes": len(transformed.encode("utf-8")) - len(output.encode("utf-8")),
            "parser": "treesitter",
            "replacements": len(function_replacements),
            "candidate_functions": function_pass.last_candidate_count,
            "skipped_dispatchers": function_pass.last_skipped_dispatcher_count,
            "transformed_functions": function_pass.last_transformed_count,
            "candidate_scan_elapsed": round(
                function_pass.last_candidate_scan_elapsed, 6,
            ),
            "transform_elapsed": round(
                function_pass.last_transform_elapsed, 6,
            ),
            "backend": "shared_syntax_context",
        })
        output = transformed
        if function_replacements:
            shared_ctx = None

    output, legacy_details = run_legacy(output, before)
    details.extend(legacy_details)
    if legacy_details:
        shared_ctx = None

    if identifier_names or emitter_names:
        from ..passes.localize_globals import LocalizeGlobalsPass
        from ..passes.rename_ts import rename_plan_with_ctx_profiled
        if shared_ctx is None:
            from ..passes.ts_utils import parse as parse_ts

            parse_start = time.perf_counter()
            shared_ctx = parse_ts(output)
            details.append({
                "phase": "vm_output:source_parse",
                "class": "VmOutputEmitter",
                "elapsed": round(time.perf_counter() - parse_start, 6),
                "input_bytes": len(output.encode("utf-8")),
                "parser": "treesitter",
                "parse_count": 1,
            })

        planned_replacements = []
        renamed_spans: set[tuple[int, int]] = set()
        literal_nodes = None
        rename_detail = None
        if "rename_obf" in identifier_names:
            stage_start = time.perf_counter()
            rename_replacements, literal_nodes, rename_profile = (
                rename_plan_with_ctx_profiled(shared_ctx)
            )
            planned_replacements.extend(rename_replacements)
            renamed_spans.update(
                (item.start, item.end) for item in rename_replacements
            )
            rename_detail = {
                "phase": "vm_output:rename_obf",
                "class": "VmIdentifierEmitter",
                "elapsed": round(time.perf_counter() - stage_start, 6),
                "replacements": len(rename_replacements),
                "backend": "structured_emitter",
                "collect_elapsed": round(rename_profile["collect_elapsed"], 6),
                "scope_resolution_elapsed": round(
                    rename_profile["scope_resolution_elapsed"], 6,
                ),
                "replacement_elapsed": round(
                    rename_profile["replacement_elapsed"], 6,
                ),
                "scope_count": rename_profile["scope_count"],
                "identifier_count": rename_profile["identifier_count"],
                "literal_count": rename_profile["literal_count"],
            }
            details.append(rename_detail)

        if "localize_globals" in identifier_names:
            stage_start = time.perf_counter()
            localize_replacements = LocalizeGlobalsPass().replacements_with_ctx(
                output,
                shared_ctx,
                renamed_spans,
            )
            planned_replacements.extend(localize_replacements)
            details.append({
                "phase": "vm_output:localize_globals",
                "class": "VmIdentifierEmitter",
                "elapsed": round(time.perf_counter() - stage_start, 6),
                "replacements": len(localize_replacements),
                "backend": "structured_emitter",
            })

        output, emitter_details = emit_vm_literals(
            output,
            emitter_names,
            ctx=shared_ctx,
            replacements=planned_replacements,
            literal_nodes=literal_nodes,
        )
        if rename_detail is not None:
            render_detail = next(
                (
                    item for item in emitter_details
                    if item.get("phase") == "vm_output:literal_render"
                ),
                None,
            )
            rename_detail["render_elapsed"] = (
                render_detail.get("elapsed", 0.0) if render_detail else 0.0
            )
            rename_detail["render_backend"] = "shared_identifier_literal_render"
        details.extend(emitter_details)

    output, post_details = run_legacy(output, after)
    details.extend(post_details)

    return output, details



_DEFAULT_VM_OPTIONS = {
    # 디스패치 모양: "ifelseif" | "tailcall"(테이블+꼬리호출) | "bsearch"(op 이진탐색)
    #             | "mixed"(VM마다 랜덤)
    "dispatcher_type": "ifelseif",
    "dispatcher_target_hiding": False,
    "semantic_state_threading": False,
    "argument_virtualization": False,
    "upvalue_virtualization": False,
    "table_virtualization": False,
    "branch_virtualization": False,
    # 블롭 저장 형태: "string"(단일 문자열) | "table"(스크램블 청크 테이블) | "random"
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


class VMPass(PostPass):
    def __init__(
        self,
        vm_output_passes: list[str] | None = None,
        vm_options: dict | None = None,
        output_prefix: str = "",
    ):
        self.vm_output_passes = vm_output_passes or []
        self.vm_options = {**_DEFAULT_VM_OPTIONS, **(vm_options or {})}
        self.output_prefix = output_prefix
        self.last_profile: list[dict] = []

    def run(self, script: str) -> str:
        self.last_profile = []
        # 1. luac 컴파일
        _phase_start = time.perf_counter()
        luac_bytes = _compile(script)
        self.last_profile.append({"phase": "compile_luac", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        # 2. 파싱 → junk instruction 삽입
        _phase_start = time.perf_counter()
        proto = Lua53Parser(luac_bytes).parse()
        self.last_profile.append({"phase": "parse_bytecode", "elapsed": round(time.perf_counter() - _phase_start, 6)})
        if self.vm_options.get("junk_instructions", True):
            _phase_start = time.perf_counter()
            proto = inject_junk(proto, rate=self.vm_options.get("junk_rate", 0.15))
            self.last_profile.append({"phase": "inject_junk", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        fake = self.vm_options["fake_handlers"]
        mut  = self.vm_options["mutate_handlers"]

        # 2b. 멀티VM: proto를 N개 VM에 분산 + VM마다 독립 맵 생성
        #     (vop 공간은 공유 used_vops로 VM 간 disjoint 유지)
        _phase_start = time.perf_counter()
        vm_count = max(1, int(self.vm_options.get("vm_count", 1)))
        vm_assign, n = assign_vm_ids(proto, vm_count)

        used_vops: set[int] = set()
        vm_maps: list = []
        used_ops_list: list[set[int]] = []
        for k in range(n):
            vop_map    = _make_vop_map(used_vops)
            split_ops  = ALL_SPLIT_OPS & collect_used_orig_ops_for_vm(proto, vm_assign, k)
            split_map  = _make_split_map(used_vops, split_ops)
            fuse_pairs = collect_fuseable_pairs_for_vm(proto, vm_assign, k)
            fuse_map   = _make_fuse_map(used_vops, fuse_pairs)
            defer_ops  = DEFER_OPS & collect_used_orig_ops_for_vm(proto, vm_assign, k)
            defer_map  = _make_defer_map(used_vops, defer_ops)
            vm_maps.append((vop_map, split_map, fuse_map, defer_map))
            used_ops = collect_used_ops_for_vm(proto, vm_assign, k, vop_map)
            if self.vm_options.get("integrity_constants", False):
                for pseudo_op in range(47, _LUA_OP_COUNT):
                    used_ops.update(vop_map[pseudo_op])
            if float(self.vm_options.get("block_variant_rate", 0.08)) > 0.0:
                for pseudo_op in (58, 59):
                    used_ops.update(vop_map[pseudo_op])
            used_ops_list.append(used_ops)
        self.last_profile.append({"phase": "build_vm_maps", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        # instruction 워드 비트 레이아웃: serializer(packing)와 vm.lua(decode)가
        # 동일 레이아웃을 공유해야 하므로 serialize 전에 per-run 생성해 양쪽에 전달.
        _phase_start = time.perf_counter()
        instr_layout = make_instr_layout()
        constant_tag_names = ("nil", "bool", "int", "float", "str", "iexpr")
        constant_tag_values = random.sample(range(0x20, 0x100), 6)
        constant_tags = dict(zip(constant_tag_names, constant_tag_values))
        constant_kind_values = random.sample(range(0x1000, 0x100000), 6)
        constant_kinds = dict(zip(constant_tag_names, constant_kind_values))
        graph_sites: set[int] = set()
        graph_family_count = 8
        blob = serialize(
            proto,
            vm_assign,
            vm_maps,
            layout=instr_layout,
            graph_sites=graph_sites,
            integrity_options={
                "enabled": self.vm_options.get("integrity_constants", False),
                "rate": self.vm_options.get("integrity_constant_rate", 0.25),
            },
            graph_execution_rate=float(
                self.vm_options.get("graph_execution_rate", 0.1)
            ),
            cross_instruction_rate=float(
                self.vm_options.get("cross_instruction_rate", 0.2)
            ),
            graph_family_count=graph_family_count,
            block_variant_rate=float(
                self.vm_options.get("block_variant_rate", 0.08)
            ),
            block_variant_count=int(
                self.vm_options.get("block_variant_count", 3)
            ),
            block_variant_max_instructions=int(
                self.vm_options.get("block_variant_max_instructions", 6)
            ),
            constant_tags=constant_tags,
        )
        self.last_profile.append({"phase": "serialize_blob", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        # 3. VM 코드 로드 + (단일/멀티) exec 생성
        _phase_start = time.perf_counter()
        dispatch = self.vm_options.get("dispatcher_type", "ifelseif")  # ifelseif | tailcall | bsearch | mixed
        vm_code = _rename_vm_keys(_load_vm())
        for name in constant_tag_names:
            vm_code = vm_code.replace(
                f"__VM_CTAG_{name.upper()}__", str(constant_tags[name])
            )
            vm_code = vm_code.replace(
                f"__VM_CK_{name.upper()}__", str(constant_kinds[name])
            )
        if n == 1:
            vop_map, split_map, fuse_map, defer_map = vm_maps[0]
            vm_code = apply_vop_to_vm(
                vm_code, vop_map,
                float(self.vm_options.get("semantic_diversity_rate", 0.35)),
            )
            vm_code = prune_and_inject_handlers(vm_code, used_ops_list[0],
                                                fake_handlers=fake, mutate=mut)
            vm_code = apply_split_to_vm(vm_code, split_map, mutate=mut)
            vm_code = apply_fuse_to_vm(vm_code, fuse_map, mutate=mut)
            vm_code = apply_defer_to_vm(vm_code, defer_map, mutate=mut)
            # 단일 VM 디스패치 모양: ifelseif(원본 체인) | tailcall | bsearch
            # (mixed면 셋 중 랜덤). 다른 transform 완료 후 최종 단계로만 적용.
            vm_code = apply_dispatch(vm_code, dispatch)
            vm_code = apply_execution_kit(
                vm_code,
                int(self.vm_options.get("helper_variant_count", 3)),
                float(self.vm_options.get("helper_diversity_rate", 0.35)),
            )
            if self.vm_options.get("dispatcher_target_hiding", False):
                vm_code = apply_dispatch_target_hiding(vm_code)
            vm_code = wire_exec_router(vm_code, 0)
            vm_code = build_next_router_kit(vm_code, 1)
        else:
            vm_code = build_exec_variants(vm_code, n, vm_maps, used_ops_list,
                                          fake_handlers=fake, mutate=mut,
                                          dispatch=dispatch,
                                          dispatch_target_hiding=bool(
                                              self.vm_options.get(
                                                  "dispatcher_target_hiding", False
                                              )
                                          ),
                                          helper_variant_count=int(
                                              self.vm_options.get("helper_variant_count", 3)
                                          ),
                                          helper_diversity_rate=float(
                                              self.vm_options.get("helper_diversity_rate", 0.35)
                                          ),
                                          semantic_diversity_rate=float(
                                              self.vm_options.get("semantic_diversity_rate", 0.35)
                                          ))

        # Keep disabled profiles free of semantic-threading calls on the hot
        # fetch/write paths.  The local helpers remain as cold template code,
        # but no per-instruction function-call overhead survives.
        if not self.vm_options.get("semantic_state_threading", False):
            vm_code = vm_code.replace("; _ss_step(_ip,op,A,B,C)", "")
            vm_code = vm_code.replace(
                "\n        _ss_value(slot,encoded,epoch,kind)", ""
            )
            vm_code = vm_code.replace(
                "; _ss_value(i,encoded,epoch,kind)", ""
            )

        # 3a. per-run VM 변형: keystream(_ksm/_kss) + anti-tamper 블록 재생성 후,
        # instruction 레이아웃 토큰(_SH_*/_MASK_OV)을 리터럴로 인라인한다.
        # 레이아웃 인라인은 fused 핸들러가 주입한 _SH_* 토큰까지 잡아야 하므로
        # 모든 핸들러/디스패치 transform 이후에 마지막으로 적용한다.
        vm_code = apply_keystream(vm_code)
        vm_code = apply_tamper(vm_code)
        vm_code = apply_instr_layout(vm_code, instr_layout)
        self.last_profile.append({"phase": "build_vm_code", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        # 3b. 블롭 저장 형태 결정. run은 type 분기 없이 스크립트마다 한 형태로
        # 고정 emit되므로, 형태별 재조립 프롤로그를 from_base36(blob) 자리에 주입한다.
        #   - string : 단일 base36 문자열 (주입 없음)
        #   - table  : 스크램블 청크 테이블 → table.concat 후 from_base36
        #   - numeric: 32비트 정수 테이블 → base36 우회, 바이트 직접 복원
        # 주입은 _obfuscate_vm_output(재난독화) 전에 해야 주입한 전역(table.concat/
        # string.char 등)도 함께 localize/rename 된다. 블롭 리터럴 자체는 _vmf
        # 인자라 dump/crc와 무관(컨테이너 형태를 바꿔도 anti-tamper 영향 없음).
        blob_form = self.vm_options.get("blob_form", "random")
        if blob_form == "random":
            blob_form = random.choice(("string", "table", "numeric"))
        if blob_form == "table":
            vm_code = vm_code.replace("from_base36(blob)",
                                      "from_base36(table.concat(blob))", 1)
        elif blob_form == "numeric":
            vm_code = vm_code.replace("from_base36(blob)", _NUMERIC_DECODE, 1)

        # 4. dump 대상 함수 소스 구성 + 재난독화 (이후 텍스트 변경 없음)
        _phase_start = time.perf_counter()

        vm_func_src = (
            f'return function(...)\n'
            f'local k1,k2,k3,k4,k5,k6,k7 = ... '
            f'{vm_code} return run end'
        )

        # VM output passes 자체를 세분화해서 측정.
        # Handler graphs are generated before VM output passes so identifiers,
        # literals, and whitespace in those backends join the same pipeline.
        _graph_start = time.perf_counter()
        _graph_input_bytes = len(vm_func_src.encode("utf-8"))

        vm_func_src = _apply_handler_graphs(
            vm_func_src,
            graph_sites,
            graph_family_count,
            runtime_polymorphism_rate=float(
                self.vm_options.get("runtime_polymorphism_rate", 0.2)
            ),
            runtime_trace=bool(self.vm_options.get("runtime_trace", False)),
            semantic_state_threading=bool(
                self.vm_options.get("semantic_state_threading", False)
            ),
            argument_virtualization=bool(
                self.vm_options.get("argument_virtualization", False)
            ),
            upvalue_virtualization=bool(
                self.vm_options.get("upvalue_virtualization", False)
            ),
            table_virtualization=bool(
                self.vm_options.get("table_virtualization", False)
            ),
            branch_virtualization=bool(
                self.vm_options.get("branch_virtualization", False)
            ),
        )

        _graph_elapsed = time.perf_counter() - _graph_start
        _graph_output_bytes = len(vm_func_src.encode("utf-8"))
        graph_detail = {
            "phase": "vm_output:handler_graphs",
            "class": "_apply_handler_graphs",
            "elapsed": round(_graph_elapsed, 6),
            "input_bytes": _graph_input_bytes,
            "output_bytes": _graph_output_bytes,
            "delta_bytes": _graph_output_bytes - _graph_input_bytes,
            "graph_sites": len(graph_sites),
            "graph_families": graph_family_count,
            "backend": "pre_output_pipeline",
        }

        vm_func_src, vm_output_details = _obfuscate_vm_output(
            vm_func_src,
            self.vm_output_passes,
        )
        vm_func_src = vm_func_src.replace(
            "--[[KARITY_EXACT_BEGIN]]", "",
        ).replace("--[[KARITY_EXACT_END]]", "")
        vm_output_details.insert(0, graph_detail)

        _line_state_start = time.perf_counter()
        line_finalizer = None
        if "minify" in self.vm_output_passes:
            from ..passes.minify import MinifyPass
            line_finalizer = MinifyPass().run
        vm_func_src, line_state, probe_lines = apply_line_state(
            vm_func_src,
            self.output_prefix,
            finalizer=line_finalizer,
            output_passes=self.vm_output_passes,
        )
        self.last_profile.append({
            "phase": "source_line_state",
            "elapsed": round(time.perf_counter() - _line_state_start, 6),
            "probe_count": len(probe_lines),
            "probe_lines": probe_lines,
        })

        self.last_profile.append({
            "phase": "obfuscate_vm_output",
            "elapsed": round(
                time.perf_counter() - _phase_start,
                6,
            ),
            "details": vm_output_details,
        })
    
        # 재난독화 결과 맨 앞의 헤더 주석을 분리 (dump/key 계산엔 영향 없음)
        header = self.output_prefix

        # 5. 확정된 vm_func_src를 load+dump(strip) → crc32 기반 key 재료
        _phase_start = time.perf_counter()
        wrapper_alphabet = string.ascii_letters
        decoy_name = secrets.choice(wrapper_alphabet)
        vmf_name = "_" + "".join(
            secrets.choice(wrapper_alphabet) for _ in range(3)
        )
        decoy_value = "".join(
            secrets.choice(wrapper_alphabet)
            for _ in range(34)
        )
        dump_bytes = _dump_function_stripped(
            vm_func_src, header, decoy_name, decoy_value,
        )
        dump_crc   = zlib.crc32(dump_bytes) & 0xFFFFFFFF
        effective_crc = (dump_crc ^ line_state) & 0xFFFFFFFF
        if self.vm_options.get("integrity_constants", False):
            blob = patch_integrity_sources(
                blob, effective_crc, line_state, constant_tags,
            )
        self.last_profile.append({"phase": "dump_vm_function", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        alphabet  = string.ascii_letters + string.digits
        rand_tail = ''.join(secrets.choice(alphabet) for _ in range(16))
        _KEY = f"karityObfuscator/{format(effective_crc, '08x')}/{rand_tail}"

        # 6. blob 암호화: nonce(8B) + ciphertext
        _phase_start = time.perf_counter()
        nonce, ct = encrypt_blob(blob, _KEY)
        encrypted_blob = nonce + ct
        if blob_form == "table":
            lua_blob = _to_table_blob(encrypted_blob, random.randint(16, 48))
        elif blob_form == "numeric":
            lua_blob = _to_numeric_blob(encrypted_blob)
        else:
            lua_blob = _to_base36(encrypted_blob)
        self.last_profile.append({"phase": "encrypt_blob", "elapsed": round(time.perf_counter() - _phase_start, 6)})

        # 7. 최종 출력 조합 — vm_func_src(_vmf 본문)는 더 이상 재가공하지 않음
        # vm_func_src: "return function(...) ... end" → _vmf 본문으로 그대로 사용
        vmf_body = vm_func_src[len("return "):]

        raw = (
            f'local {decoy_name}="{decoy_value}"'
            f'local {vmf_name}={vmf_body};'
            f'return ({vmf_name}(1032,413,258,104,953,283,120))'
            f'({lua_blob},"{rand_tail}",{vmf_name})'
        )

        return raw
