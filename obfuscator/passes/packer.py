"""
Karity load-based packer.

The packer is intentionally the outer runtime component rather than another VM:
- selects the smallest raw-DEFLATE candidate before doing expensive encoding
- encrypts the compressed stream with a loader-self-keyed rolling XOR
- builds an external context table outside the packed payload
- couples packed code to that context through state-derived slot routing
- for VM output, externalizes the VM call constants and reconstructs rand_tail
  through the packer auth graph without modifying _vmf itself
- for non-VM output, conservatively externalizes safe top-level functions /
  literal constants and selected reference proxies
"""
from __future__ import annotations

import base64
import os
import platform
import random
import re
import secrets
import shutil
import subprocess
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .base import PostPass


_STUB_PATH = Path(__file__).parent / "pack_stub.lua"
_MASK32 = 0xFFFFFFFF
_ROUTE_MASK = 0x7FFFFFFF

if platform.system() == "Windows":
    _LUA = Path(__file__).parent.parent.parent / "bin" / "lua.exe"
else:
    _LUA = shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua5.3"


_COMPRESSION_CANDIDATES = (
    (9, zlib.Z_DEFAULT_STRATEGY),
    (6, zlib.Z_DEFAULT_STRATEGY),
    (1, zlib.Z_DEFAULT_STRATEGY),
    (9, zlib.Z_FILTERED),
    (9, zlib.Z_RLE),
    (9, zlib.Z_HUFFMAN_ONLY),
    (9, zlib.Z_FIXED),
)

# Only references whose semantics are stable and useful in arbitrary packed source.
# Dotted references are preferred because local shadowing is much less ambiguous.
_REF_PROXY_EXPRESSIONS = {
    "string.byte": "string.byte",
    "string.char": "string.char",
    "string.sub": "string.sub",
    "string.find": "string.find",
    "string.len": "string.len",
    "table.concat": "table.concat",
    "table.unpack": "table.unpack",
    "table.pack": "table.pack",
    "math.floor": "math.floor",
    "math.type": "math.type",
}

# Bare globals are only proxied when the scanner cannot find a top-level local with
# the same name. This keeps the generic path conservative.
_BARE_REF_PROXY_EXPRESSIONS = {
    "type": "type",
    "select": "select",
    "pairs": "pairs",
    "ipairs": "ipairs",
    "next": "next",
    "pcall": "pcall",
    "xpcall": "xpcall",
    "tonumber": "tonumber",
    "tostring": "tostring",
    "rawget": "rawget",
    "rawset": "rawset",
    "setmetatable": "setmetatable",
    "getmetatable": "getmetatable",
}

_VM_TAIL_RE = re.compile(
    r"return\s*\(_vmf\((?P<args>[^)]*)\)\)"
    r"\((?P<blob>.*),\"(?P<tail>[A-Za-z0-9]{16})\",_vmf\)\s*$",
    re.S,
)

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_LITERAL_RE = re.compile(
    r"""(?xs)
    (?:
        nil|true|false|
        [-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?)|
        "(?:[^"\\]|\\.)*"|
        '(?:[^'\\]|\\.)*'
    )
    \s*$
    """
)


@dataclass
class ExtractedFunction:
    name: str
    literal: str
    start: int
    end: int
    deps: set[str] = field(default_factory=set)


@dataclass
class ExtractedConstant:
    name: str
    literal: str
    start: int
    end: int


@dataclass
class ContextPlan:
    slots: dict[str, int]
    state_consts: dict[str, int]
    extracted_functions: list[ExtractedFunction] = field(default_factory=list)
    extracted_constants: list[ExtractedConstant] = field(default_factory=list)
    refs: dict[str, str] = field(default_factory=dict)
    vm_args: list[str] = field(default_factory=list)
    vm_tail: str | None = None
    is_vm: bool = False

    def slot(self, key: str) -> int:
        return self.slots[key]


def _obfuscate_packer_output(script: str, pass_names: list[str]) -> str:
    from ..pipeline import Pipeline
    from ..registry import PASS_REGISTRY

    pipeline = Pipeline(show_header=False)
    for name in pass_names:
        info = PASS_REGISTRY.get(name)
        if info is None:
            continue
        cls = info["cls"]
        if cls.__name__ in {"VMPass", "PackerPass"}:
            continue
        pipeline.add(cls())
    return pipeline.run(script)


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & _MASK32
    return h


def _xorshift32(state: int) -> int:
    state &= _MASK32
    state ^= (state << 13) & _MASK32
    state ^= state >> 17
    state ^= (state << 5) & _MASK32
    return state & _MASK32


def _rolling_xor(data: bytes, seed: int) -> bytes:
    state = (seed | 1) & _MASK32
    out = bytearray(len(data))
    for i, value in enumerate(data, start=1):
        state = _xorshift32(state)
        cipher = value ^ (state & 0xFF)
        out[i - 1] = cipher
        state = (state ^ cipher ^ ((i * 0x9E3779B9) & _MASK32)) & _MASK32
    return bytes(out)


def _compress_candidates(raw: bytes) -> list[bytes]:
    results: list[bytes] = []
    seen: set[bytes] = set()
    for level, strategy in _COMPRESSION_CANDIDATES:
        co = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
        comp = co.compress(raw) + co.flush()
        if comp not in seen:
            seen.add(comp)
            results.append(comp)
    return results


def _best_compression(raw: bytes) -> bytes:
    """Winner-first selection.

    All candidates use the same loader, rolling-XOR length and base64 encoding,
    so compressed byte length monotonically determines final packed size.
    """
    candidates = _compress_candidates(raw)
    if not candidates:
        raise RuntimeError("packer failed to produce a compression candidate")
    return min(candidates, key=len)


def _dump_loader_stripped(loader_src: str) -> bytes:
    """Dump the final loader function in the same visible outer context.

    The packer itself owns the public signature header, so `_P` is always
    compiled immediately after exactly one Pipeline.HEADER regardless of
    whether the outer pipeline also contains VM.
    """
    if not _LUA or (isinstance(_LUA, Path) and not _LUA.exists()):
        raise FileNotFoundError("lua5.3 not found.")
    if not loader_src.startswith("return "):
        raise RuntimeError("packer loader output must start with 'return '")

    from ..pipeline import Pipeline

    loader_body = loader_src[len("return "):]
    wrapped = (
        f"{Pipeline.HEADER}"
        f"local _P={loader_body};"
        f'local _D="";'
        f"return _P"
    )

    with tempfile.NamedTemporaryFile(
        suffix=".lua", delete=False, mode="w", encoding="utf-8"
    ) as f:
        f.write(wrapped)
        src_path = f.name

    dump_path = src_path + ".dump"
    helper_path = src_path + ".helper.lua"

    helper = f"""local src_path=[==[{src_path}]==]
local dump_path=[==[{dump_path}]==]
local fh=assert(io.open(src_path,"rb"))
local src=fh:read("a")
fh:close()
local chunk,err=load(src,nil,"t",_ENV)
if not chunk then error(err) end
local fn=chunk()
local out=assert(io.open(dump_path,"wb"))
out:write(string.dump(fn,true))
out:close()
"""

    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(helper)

    try:
        result = subprocess.run([str(_LUA), helper_path], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(
                "lua packer dump failed: "
                + result.stderr.decode(errors="replace")
            )
        if not os.path.exists(dump_path):
            raise RuntimeError("lua packer dump produced no dump")
        with open(dump_path, "rb") as f:
            return f.read()
    finally:
        for p in (src_path, dump_path, helper_path):
            if os.path.exists(p):
                os.unlink(p)


def _distinct_slots(count: int) -> list[int]:
    used: set[int] = set()
    while len(used) < count:
        # Keep positive integer keys and leave a broad sparse key space.
        used.add(secrets.randbelow(0x70000000) + 0x01000000)
    return list(used)


def _mask_lua_noncode(src: str) -> str:
    """Replace comments/string contents with spaces while preserving length."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        ch = src[i]

        if ch in ("'", '"'):
            quote = ch
            out[i] = " "
            i += 1
            while i < n:
                out[i] = " "
                if src[i] == "\\":
                    i += 1
                    if i < n:
                        out[i] = " "
                        i += 1
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        if src.startswith("--", i):
            # Long comment --[=[ ... ]=]
            m = re.match(r"--\[(=*)\[", src[i:])
            if m:
                eq = m.group(1)
                close = "]" + eq + "]"
                j = src.find(close, i + m.end())
                end = n if j < 0 else j + len(close)
                for k in range(i, end):
                    out[k] = " "
                i = end
                continue

            j = src.find("\n", i)
            end = n if j < 0 else j
            for k in range(i, end):
                out[k] = " "
            i = end
            continue

        # Long string [=[ ... ]=]
        m = re.match(r"\[(=*)\[", src[i:])
        if m:
            eq = m.group(1)
            close = "]" + eq + "]"
            j = src.find(close, i + m.end())
            end = n if j < 0 else j + len(close)
            for k in range(i, end):
                out[k] = " "
            i = end
            continue

        i += 1

    return "".join(out)


def _keyword_tokens(masked: str):
    for m in re.finditer(r"\b[A-Za-z_]\w*\b", masked):
        yield m.group(0), m.start(), m.end()


def _depth_before(masked: str, pos: int) -> int:
    depth = 0
    pending_do = 0
    stack: list[str] = []
    for word, start, _ in _keyword_tokens(masked[:pos]):
        if word == "function":
            stack.append("end")
        elif word == "if":
            stack.append("end")
        elif word in ("for", "while"):
            stack.append("end")
            pending_do += 1
        elif word == "repeat":
            stack.append("until")
        elif word == "do":
            if pending_do:
                pending_do -= 1
            else:
                stack.append("end")
        elif word == "end":
            if stack and stack[-1] == "end":
                stack.pop()
        elif word == "until":
            if stack and stack[-1] == "until":
                stack.pop()
        depth = len(stack)
    return depth


def _find_function_end(masked: str, function_pos: int) -> int | None:
    stack: list[str] = []
    pending_do = 0
    started = False
    for word, start, end in _keyword_tokens(masked[function_pos:]):
        start += function_pos
        end += function_pos
        if not started:
            if word != "function":
                continue
            stack.append("end")
            started = True
            continue

        if word == "function":
            stack.append("end")
        elif word == "if":
            stack.append("end")
        elif word in ("for", "while"):
            stack.append("end")
            pending_do += 1
        elif word == "repeat":
            stack.append("until")
        elif word == "do":
            if pending_do:
                pending_do -= 1
            else:
                stack.append("end")
        elif word == "end":
            if stack and stack[-1] == "end":
                stack.pop()
                if not stack:
                    return end
        elif word == "until":
            if stack and stack[-1] == "until":
                stack.pop()
                if not stack:
                    return end
    return None


def _top_level_locals(src: str, masked: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(r"\blocal\s+(?:function\s+)?([A-Za-z_]\w*)", masked):
        if _depth_before(masked, m.start()) == 0:
            names.add(m.group(1))
    return names


def _find_simple_constants(src: str, masked: str) -> list[ExtractedConstant]:
    result: list[ExtractedConstant] = []
    pat = re.compile(
        r"\blocal\s+([A-Za-z_]\w*)\s*=\s*"
        r"(nil|true|false|[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?)|"
        r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"
    )
    for m in pat.finditer(src):
        if masked[m.start():m.start()+5] != "local":
            continue
        if _depth_before(masked, m.start()) != 0:
            continue
        name = m.group(1)
        literal = m.group(2)
        # Reject values that are written again later.
        later_mask = masked[m.end():]
        if re.search(rf"(?<![\w.:]){re.escape(name)}\s*=", later_mask):
            continue
        result.append(ExtractedConstant(name, literal, m.start(), m.end()))
    return result


def _find_top_level_functions(
    src: str,
    masked: str,
    top_locals: set[str],
    extractable_names: set[str],
) -> list[ExtractedFunction]:
    result: list[ExtractedFunction] = []

    patterns = (
        re.compile(r"\blocal\s+function\s+([A-Za-z_]\w*)\s*\("),
        re.compile(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*function\s*\("),
    )

    seen: set[tuple[int, int]] = set()
    for pat in patterns:
        for m in pat.finditer(masked):
            if _depth_before(masked, m.start()) != 0:
                continue
            key = (m.start(), m.end())
            if key in seen:
                continue
            seen.add(key)

            func_pos = masked.find("function", m.start(), m.end())
            if func_pos < 0:
                continue
            func_end = _find_function_end(masked, func_pos)
            if func_end is None:
                continue

            name = m.group(1)
            literal = src[func_pos:func_end]
            # `local function f(a) ... end` is statement syntax; once moved
            # into a context-table value it must become the anonymous literal
            # `function(a) ... end`. `local f=function(a)...end` is already
            # expression-compatible.
            if src[m.start():m.end()].lstrip().startswith("local function"):
                literal = re.sub(
                    rf"^function\s+{re.escape(name)}\s*\(",
                    "function(",
                    literal,
                    count=1,
                )
            if not (40 <= len(literal) <= 1600):
                continue

            lm = _mask_lua_noncode(literal)

            # Parameters and local declarations are not free dependencies.
            param_match = re.match(r"function\s*\(([^)]*)\)", lm)
            local_names = set()
            if param_match:
                local_names.update(
                    p.strip()
                    for p in param_match.group(1).split(",")
                    if re.fullmatch(r"[A-Za-z_]\w*", p.strip())
                )
            local_names.update(
                x.group(1)
                for x in re.finditer(r"\blocal\s+(?:function\s+)?([A-Za-z_]\w*)", lm)
            )

            idents = set(_IDENT_RE.findall(lm))
            deps = (idents & top_locals) - local_names - {name}

            # A candidate is safe only when every outer-local dependency can
            # itself be moved into the context.
            if not deps.issubset(extractable_names):
                continue

            result.append(
                ExtractedFunction(
                    name=name,
                    literal=literal,
                    start=m.start(),
                    end=func_end,
                    deps=deps,
                )
            )

    result.sort(key=lambda f: f.start)
    return result


def _code_substitute(src: str, replacements: dict[str, str]) -> str:
    """Identifier/dotted-reference replacement outside strings and comments."""
    if not replacements:
        return src

    masked = _mask_lua_noncode(src)
    keys = sorted(replacements, key=len, reverse=True)
    pattern = re.compile(
        "|".join(
            rf"(?<![\w]){re.escape(k)}(?![\w])"
            for k in keys
        )
    )

    out: list[str] = []
    pos = 0
    for m in pattern.finditer(masked):
        key = m.group(0)
        # Bare identifiers used as fields/methods are not variable refs.
        if "." not in key:
            j = m.start() - 1
            while j >= 0 and masked[j].isspace():
                j -= 1
            if j >= 0 and masked[j] in ".:":
                continue
        out.append(src[pos:m.start()])
        out.append(replacements[key])
        pos = m.end()
    out.append(src[pos:])
    return "".join(out)


def _alloc_plan(script: str) -> ContextPlan:
    masked = _mask_lua_noncode(script)
    top_locals = _top_level_locals(script, masked)
    constants = _find_simple_constants(script, masked)
    constant_names = {c.name for c in constants}

    # First pass: function names are extractable from one another.
    rough_funcs: list[str] = []
    for p in (
        re.compile(r"\blocal\s+function\s+([A-Za-z_]\w*)\s*\("),
        re.compile(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*function\s*\("),
    ):
        for m in p.finditer(masked):
            if _depth_before(masked, m.start()) == 0:
                rough_funcs.append(m.group(1))
    extractable_names = set(rough_funcs) | constant_names
    funcs = _find_top_level_functions(
        script, masked, top_locals, extractable_names
    )

    # Random but bounded extraction. Prefer functions with dependencies so the
    # outer and inner programs form a real graph instead of a flat bag.
    # Build a dependency-closed random subset. If selected function A depends
    # on top-level function B, B must move out with A or A would lose its
    # lexical dependency after extraction.
    safe_by_name = {f.name: f for f in funcs}
    funcs = [
        f for f in funcs
        if all((d in constant_names) or (d in safe_by_name) for d in f.deps)
    ]
    safe_by_name = {f.name: f for f in funcs}

    selected_names: set[str] = set()
    if funcs:
        seeds = list(funcs)
        random.shuffle(seeds)
        target = random.randint(2, min(6, len(funcs))) if len(funcs) >= 2 else 1
        queue = [f.name for f in seeds[:target]]
        while queue and len(selected_names) < 8:
            name = queue.pop()
            if name in selected_names or name not in safe_by_name:
                continue
            selected_names.add(name)
            for dep in safe_by_name[name].deps:
                if dep in safe_by_name and dep not in selected_names:
                    queue.append(dep)

    funcs = sorted(
        (safe_by_name[name] for name in selected_names),
        key=lambda f: f.start,
    )

    needed_constants = set()
    for f in funcs:
        needed_constants |= f.deps & constant_names

    optional_constants = [c for c in constants if c.name not in needed_constants]
    random.shuffle(optional_constants)
    selected_constants = [c for c in constants if c.name in needed_constants]
    selected_constants.extend(optional_constants[: max(0, random.randint(1, 4) - len(selected_constants))])

    # Reference proxies present in the payload. Bare refs are excluded when a
    # top-level local shadows that name.
    refs: dict[str, str] = {}
    for ref, expr in _REF_PROXY_EXPRESSIONS.items():
        if ref in masked and random.random() < 0.55:
            refs[ref] = expr
    for ref, expr in _BARE_REF_PROXY_EXPRESSIONS.items():
        if ref not in top_locals and re.search(rf"\b{re.escape(ref)}\b", masked):
            if random.random() < 0.35:
                refs[ref] = expr

    vm_match = _VM_TAIL_RE.search(script)
    is_vm = vm_match is not None
    vm_args: list[str] = []
    vm_tail: str | None = None
    if vm_match:
        vm_args = [x.strip() for x in vm_match.group("args").split(",")]
        vm_tail = vm_match.group("tail")

        # Never touch inside _vmf. Generic extraction/ref-proxying would change
        # its stripped dump and invalidate existing VM integrity.
        funcs = []
        selected_constants = []
        refs = {}

    base_keys = [
        "hash", "dump", "b64", "byte", "char", "concat",
        "state", "decode",
        "k0", "k1", "k2", "k3", "mul",
        "d0", "d1", "d2",
        "decoy0", "decoy1", "decoy2",
    ]
    extra_keys = (
        [f"func:{f.name}" for f in funcs]
        + [f"const:{c.name}" for c in selected_constants]
        + [f"ref:{name}" for name in refs]
        + [f"vmarg:{i}" for i in range(len(vm_args))]
    )
    keys = base_keys + extra_keys
    slots = dict(zip(keys, _distinct_slots(len(keys))))

    state_consts = {
        "k0": secrets.randbits(32),
        "k1": secrets.randbits(32),
        "k2": secrets.randbits(32),
        "k3": secrets.randbits(32),
        "mul": secrets.randbits(32) | 1,
        "decoy_seed0": secrets.randbits(32),
        "decoy_seed1": secrets.randbits(32),
        "decoy_seed2": secrets.randbits(32),
    }

    return ContextPlan(
        slots=slots,
        state_consts=state_consts,
        extracted_functions=funcs,
        extracted_constants=selected_constants,
        refs=refs,
        vm_args=vm_args,
        vm_tail=vm_tail,
        is_vm=is_vm,
    )


def _d0(x: int, plan: ContextPlan) -> int:
    return _xorshift32(x ^ plan.state_consts["k0"])


def _d1(x: int, plan: ContextPlan) -> int:
    return ((_d0(x, plan) + plan.state_consts["k1"]) * plan.state_consts["mul"]) & _MASK32


def _d2(x: int, plan: ContextPlan) -> int:
    return _xorshift32(_d1(x, plan) ^ plan.state_consts["k2"])


def _context_state(dump_hash: int, plan: ContextPlan) -> int:
    s = (dump_hash ^ plan.state_consts["k3"]) & _MASK32
    s = _xorshift32(s)
    s = _d2(s, plan)
    return (s ^ plan.state_consts["k1"]) & _MASK32


def _auth_xor(data: bytes, state: int) -> bytes:
    s = (state | 1) & _MASK32
    out = bytearray(len(data))
    for i, b in enumerate(data, 1):
        s = _xorshift32(s)
        out[i - 1] = b ^ (s & 0xFF)
        s = (s ^ ((i * 0x45D9F3B) & _MASK32)) & _MASK32
    return bytes(out)


def _slot_expr(actual_slot: int, state: int) -> str:
    encoded = actual_slot ^ (state & _ROUTE_MASK)
    return f"__KCTX[(0x{encoded:X}~(__KSTATE&0x{_ROUTE_MASK:X}))]"


def _rewrite_function_literal(
    literal: str,
    plan: ContextPlan,
) -> str:
    mapping: dict[str, str] = {}
    for f in plan.extracted_functions:
        mapping[f.name] = f"_C[{plan.slot('func:' + f.name)}]"
    for c in plan.extracted_constants:
        mapping[c.name] = f"_C[{plan.slot('const:' + c.name)}]"
    for ref in plan.refs:
        mapping[ref] = f"_C[{plan.slot('ref:' + ref)}]"
    return _code_substitute(literal, mapping)


def _make_proxy_expr(ref_expr: str, plan: ContextPlan, proxy_slot: int, index: int) -> str:
    # A called dependency chooses the real reference. The sibling key is a
    # deliberately wrong alternative and becomes reachable if the dependency
    # graph is modified.
    fixed_input = (plan.state_consts["decoy_seed0"] ^ (index * 0x9E3779B9)) & _MASK32
    route = _d0(fixed_input, plan)
    wrong = route ^ ((index + 1) | 1)
    wrong_expr = random.choice(("tostring", "type", "tonumber"))
    return (
        f"_C[{proxy_slot}]=function(...)"
        f"local q=_C[{plan.slot('d0')}](_C,0x{fixed_input:08X});"
        f"local t={{[0x{route:08X}]={ref_expr},[0x{wrong:08X}]={wrong_expr}}};"
        f"return t[q](...) end;"
    )


def _context_setup(plan: ContextPlan) -> str:
    s = plan.slots
    c = plan.state_consts
    parts = ["local _C={}"]

    parts.extend([
        f"_C[{s['hash']}]=_hash;",
        f"_C[{s['dump']}]=_dump;",
        f"_C[{s['b64']}]=_b64;",
        f"_C[{s['byte']}]=_byte;",
        f"_C[{s['char']}]=_char;",
        f"_C[{s['concat']}]=_concat;",
        f"_C[{s['k0']}]=0x{c['k0']:08X};",
        f"_C[{s['k1']}]=0x{c['k1']:08X};",
        f"_C[{s['k2']}]=0x{c['k2']:08X};",
        f"_C[{s['k3']}]=0x{c['k3']:08X};",
        f"_C[{s['mul']}]=0x{c['mul']:08X};",
    ])

    # Actual dependency chain: d2 -> d1 -> d0 -> constants.
    parts.append(
        f"_C[{s['d0']}]=function(c,x)"
        f"local v=(x~c[{s['k0']}])&0xFFFFFFFF;"
        "v=(v~((v<<13)&0xFFFFFFFF))&0xFFFFFFFF;"
        "v=(v~(v>>17))&0xFFFFFFFF;"
        "v=(v~((v<<5)&0xFFFFFFFF))&0xFFFFFFFF;"
        "return v end;"
    )
    parts.append(
        f"_C[{s['d1']}]=function(c,x)"
        f"return ((_C[{s['d0']}](c,x)+c[{s['k1']}])*c[{s['mul']}])&0xFFFFFFFF end;"
    )
    parts.append(
        f"_C[{s['d2']}]=function(c,x)"
        f"local v=(_C[{s['d1']}](c,x)~c[{s['k2']}])&0xFFFFFFFF;"
        "v=(v~((v<<13)&0xFFFFFFFF))&0xFFFFFFFF;"
        "v=(v~(v>>17))&0xFFFFFFFF;"
        "v=(v~((v<<5)&0xFFFFFFFF))&0xFFFFFFFF;"
        "return v end;"
    )

    # Decoy dependencies. Some are called by proxy wrappers, but their values
    # are only meaningful as routing keys rather than a visible boolean check.
    for i, key in enumerate(("decoy0", "decoy1", "decoy2")):
        seed = c[f"decoy_seed{i}"]
        dep = ("d0", "d1", "d2")[i]
        parts.append(
            f"_C[{s[key]}]=function(c,x)"
            f"local q=_C[{s[dep]}](c,(x~0x{seed:08X})&0xFFFFFFFF);"
            f"return (q~((q<<{i+1})&0xFFFFFFFF))&0xFFFFFFFF end;"
        )

    parts.append(
        f"_C[{s['state']}]=function(c)"
        f"local h=c[{s['hash']}](c[{s['dump']}](_self,true));"
        f"local v=(h~c[{s['k3']}])&0xFFFFFFFF;"
        "v=(v~((v<<13)&0xFFFFFFFF))&0xFFFFFFFF;"
        "v=(v~(v>>17))&0xFFFFFFFF;"
        "v=(v~((v<<5)&0xFFFFFFFF))&0xFFFFFFFF;"
        f"v=_C[{s['d2']}](c,v);"
        f"return (v~c[{s['k1']}])&0xFFFFFFFF end;"
    )

    parts.append(
        f"_C[{s['decode']}]=function(c,e)"
        f"local v=_C[{s['state']}](c)|1;"
        f"local raw=c[{s['b64']}](e);local o={{}};"
        "for i=1,#raw do "
        "v=(v~((v<<13)&0xFFFFFFFF))&0xFFFFFFFF;"
        "v=(v~(v>>17))&0xFFFFFFFF;"
        "v=(v~((v<<5)&0xFFFFFFFF))&0xFFFFFFFF;"
        f"o[i]=c[{s['char']}](c[{s['byte']}](raw,i)~(v&0xFF));"
        "v=(v~((i*0x45D9F3B)&0xFFFFFFFF))&0xFFFFFFFF end;"
        f"return c[{s['concat']}](o) end;"
    )

    for const in plan.extracted_constants:
        parts.append(
            f"_C[{plan.slot('const:' + const.name)}]={const.literal};"
        )

    # Function bodies live outside the packed payload. Dependencies between
    # extracted functions/constants are rewritten to context accesses.
    for func in plan.extracted_functions:
        literal = _rewrite_function_literal(func.literal, plan)
        parts.append(
            f"_C[{plan.slot('func:' + func.name)}]={literal};"
        )

    for i, (ref, expr) in enumerate(plan.refs.items()):
        parts.append(
            _make_proxy_expr(
                expr,
                plan,
                plan.slot("ref:" + ref),
                i,
            )
        )

    for i, value in enumerate(plan.vm_args):
        parts.append(f"_C[{plan.slot('vmarg:' + str(i))}]={value};")

    return "".join(parts)


def _render_loader(stub: str, plan: ContextPlan, scalar_values: dict[str, int]) -> str:
    values = {
        **scalar_values,
        "__CTX_STATE_SLOT__": plan.slot("state"),
        "__CTX_DECODE_SLOT__": plan.slot("decode"),
    }
    for token, value in values.items():
        stub = stub.replace(token, f"0x{value:08X}")
    stub = stub.replace("__CTX_SETUP__", _context_setup(plan))
    return stub


def _rewrite_generic_payload(script: str, plan: ContextPlan, state: int) -> str:
    replacements: list[tuple[int, int, str]] = []

    # Replace extracted top-level definitions with state-routed context aliases.
    for f in plan.extracted_functions:
        expr = _slot_expr(plan.slot("func:" + f.name), state)
        replacements.append((f.start, f.end, f"local {f.name}={expr}"))

    for c in plan.extracted_constants:
        expr = _slot_expr(plan.slot("const:" + c.name), state)
        replacements.append((c.start, c.end, f"local {c.name}={expr}"))

    # Apply structural replacements from right to left before ref proxying.
    body = script
    for start, end, text in sorted(replacements, reverse=True):
        body = body[:start] + text + body[end:]

    ref_mapping = {
        ref: _slot_expr(plan.slot("ref:" + ref), state)
        for ref in plan.refs
    }
    body = _code_substitute(body, ref_mapping)

    # The state function itself is supplied as a separate argument so the
    # bootstrap does not expose its sparse context slot in the payload.
    prefix = (
        "local __KCTX,__KSTATEF=...;"
        "local __KSTATE=__KSTATEF(__KCTX);"
    )
    return prefix + body


def _rewrite_vm_payload(script: str, plan: ContextPlan, state: int) -> str:
    m = _VM_TAIL_RE.search(script)
    if not m or plan.vm_tail is None:
        return script

    encoded_args = [
        _slot_expr(plan.slot("vmarg:" + str(i)), state)
        for i in range(len(plan.vm_args))
    ]

    tail_enc = base64.b64encode(
        _auth_xor(plan.vm_tail.encode("ascii"), state)
    ).decode("ascii")

    replacement = (
        f"return (_vmf({','.join(encoded_args)}))"
        f"({m.group('blob')},__KDECODE(__KCTX,\"{tail_enc}\"),_vmf)"
    )
    body = script[:m.start()] + replacement + script[m.end():]

    # Keep this prefix on the current source line. _vmf itself is byte-for-byte
    # untouched and its line number is not shifted, preserving the VM dump CRC.
    prefix = (
        "local __KCTX,__KSTATEF,__KDECODE=...;"
        "local __KSTATE=__KSTATEF(__KCTX);"
    )
    return prefix + body


def _render_packed(loader_src: str, payload: str, plan: ContextPlan) -> str:
    from ..pipeline import Pipeline

    if not loader_src.startswith("return "):
        raise RuntimeError("packer loader output must start with 'return '")

    loader_body = loader_src[len("return "):]
    return (
        f"{Pipeline.HEADER}"
        f"local _P={loader_body};"
        f'local _D="{payload}";'
        f"return _P(_D,_P)\n"
    )


class PackerPass(PostPass):
    """Final self-keyed packer with cross-layer external-context coupling."""

    def __init__(self, packer_output_passes: list[str] | None = None):
        self.packer_output_passes = packer_output_passes or []
        self.last_profile: list[dict] = []

    def run(self, script: str) -> str:
        self.last_profile = []

        # Context shape is decided before the loader is finalized. The actual
        # state-routed indices are rendered only after the loader dump hash is known.
        plan = _alloc_plan(script)

        salt, type_bad, type_ok, lua_c, lua_lua, print_ok, print_bad = (
            secrets.randbits(32) for _ in range(7)
        )
        scalar_values = {
            "__SALT__": salt,
            "__FP_TYPE_BAD__": type_bad,
            "__FP_TYPE_OK__": type_ok,
            "__FP_C__": lua_c,
            "__FP_LUA__": lua_lua,
            "__FP_PRINT_OK__": print_ok,
            "__FP_PRINT_BAD__": print_bad,
        }

        loader_src = _render_loader(
            _STUB_PATH.read_text(encoding="utf-8"),
            plan,
            scalar_values,
        )
        loader_src = _obfuscate_packer_output(
            loader_src,
            self.packer_output_passes,
        )

        dump_hash = _fnv1a32(_dump_loader_stripped(loader_src))
        state = _context_state(dump_hash, plan)

        if plan.is_vm:
            payload_src = _rewrite_vm_payload(script, plan, state)
        else:
            payload_src = _rewrite_generic_payload(script, plan, state)

        raw = payload_src.encode("utf-8")

        # Free build-time optimization: pick the winner before rolling-XOR/base64.
        comp = _best_compression(raw)

        expected_fp = type_ok ^ lua_c ^ print_ok
        seed = (
            dump_hash
            ^ salt
            ^ expected_fp
            ^ ((len(comp) * 0x045D9F3B) & _MASK32)
        ) & _MASK32

        encrypted = _rolling_xor(comp, seed)
        payload = base64.b64encode(encrypted).decode("ascii")
        return _render_packed(loader_src, payload, plan)
