"""
per-run VM 다형성 변형 3종. 각 함수는 vm.lua 템플릿(마커/토큰 포함)을 받아
런타임 정확성을 보존하는 랜덤 변형을 적용한다.

  1) instruction 워드 비트 레이아웃  (make_instr_layout / apply_instr_layout)
  2) 런타임 keystream 함수 _ksm/_kss  (apply_keystream)
  3) anti-tamper 검사 블록             (apply_tamper)

레이아웃은 serializer와 vm.lua가 공유해야 하므로 별도 dict로 만들어 양쪽에 전달한다.
keystream/tamper는 vm.lua 안에서만 완결되므로 마커 사이를 교체한다.
"""
from __future__ import annotations
import hashlib
import random
import re


# ---------------------------------------------------------------------------
# 1. instruction 워드 비트 레이아웃
# ---------------------------------------------------------------------------
# 제약: op은 비트 0(7비트) 고정. A(8)/BC(18, B=C+9 연속)/variant(8)는 비트 [7,47]
# 안에서 disjoint 배치(모든 필드가 _ksm의 48비트 마스크 범위 안에 있어야 마스킹됨).
def make_instr_layout() -> dict[str, int]:
    blocks = [("BC", 18), ("A", 8), ("V", 8)]
    random.shuffle(blocks)
    total_w = sum(w for _, w in blocks)     # 34
    spare   = (47 + 1 - 7) - total_w        # [7,47]=41비트 중 34 사용 → 여유 7
    pos = 7
    placed: dict[str, int] = {}
    for name, w in blocks:
        gap = random.randint(0, spare)
        spare -= gap
        pos += gap
        placed[name] = pos
        pos += w
    C = placed["BC"]
    return {"A": placed["A"], "B": C + 9, "C": C, "V": placed["V"]}


_SH_DEF_RE   = re.compile(r'^[ \t]*local _SH_A,_SH_B,_SH_C,_SH_V=.*\n', re.M)
_MASK_DEF_RE = re.compile(r'^[ \t]*local _MASK_OV=.*\n', re.M)


def apply_instr_layout(vm_code: str, layout: dict[str, int]) -> str:
    """vm.lua의 _SH_*/_MASK_OV 토큰을 layout 리터럴로 인라인한다.

    standalone 기본값 def 라인은 제거하고(토큰이 def LHS에 남으면 문법 오류),
    나머지 모든 _SH_*/_MASK_OV 참조를 숫자 리터럴로 치환한다. fused 핸들러가
    주입한 _SH_* 토큰까지 잡으려면 모든 핸들러 transform 이후에 호출해야 한다.
    """
    a, b, c, v = layout["A"], layout["B"], layout["C"], layout["V"]
    mask_ov = 0x7F | (0xFF << v)

    vm_code = _SH_DEF_RE.sub("", vm_code, count=1)
    vm_code = _MASK_DEF_RE.sub("", vm_code, count=1)

    reps = {
        "_MASK_OV": hex(mask_ov),   # _SH_* 보다 먼저(부분일치 방지용은 아니나 명시적)
        "_SH_A": str(a), "_SH_B": str(b), "_SH_C": str(c), "_SH_V": str(v),
    }
    for tok, val in reps.items():
        vm_code = re.sub(rf'\b{tok}\b', val, vm_code)
    return vm_code


# ---------------------------------------------------------------------------
# 2. 런타임 keystream 함수 (_ksm / _kss)
# ---------------------------------------------------------------------------
# _ksm/_kss는 대칭 XOR 키스트림(마스킹·해제가 같은 함수 호출)이라 (i,_ksd)의
# 순수 함수이기만 하면 임의 형태가 가능하다. 폭 불변식만 지키면 된다:
#   _ksm: 결과를 48비트(&M)로 마스킹(코드 필드가 비트 [0,47]에 있으므로).
#   _kss: 바이트 키(&0xFF).
_KSM_MASK = "0xFFFFFFFFFFFF"


def _odd32() -> int:
    return random.randrange(1, 0x100000000) | 1


def _render_ksm() -> str:
    M  = _KSM_MASK
    k1 = _odd32(); k2 = _odd32()
    s1 = random.randint(11, 23); s2 = random.randint(7, 17)
    lines = [
        "local function _ksm(i)",
        f"    local x=(i*{k1})&{M}",
        f"    x=(x~((_ksd*{k2})&{M}))&{M}",
        f"    x=(x~(x>>{s1})~((i<<{s2})&{M}))&{M}",
    ]
    # 선택적 추가 믹싱 단계(구조도 매번 다르게)
    if random.random() < 0.7:
        k3 = _odd32()
        lines.append(random.choice([
            f"    x=(x+((i*{k3})&{M}))&{M}",
            f"    x=(x~((_ksd*{k3})&{M})~(x>>{random.randint(9,21)}))&{M}",
            f"    x=(x~(({M})&(i*{k3})))&{M}",
        ]))
    lines.append("    return x")
    lines.append("end")
    return "\n".join(lines)


def _render_kss() -> str:
    k1 = random.randrange(1, 256) | 1
    k2 = random.randrange(0, 256)
    s1 = random.randint(2, 5)
    return (
        "local function _kss(s)\n"
        "    local out={}\n"
        "    for i=1,#s do\n"
        f"        local m=((i*{k1})~_ksd~(i>>{s1})~{k2})&0xFF\n"
        "        out[i]=(string.byte(s,i)~m)&0xFF\n"
        "    end\n"
        "    local chunks={}\n"
        "    for i=1,#out,4096 do\n"
        "        local last=i+4095; if last>#out then last=#out end\n"
        "        chunks[#chunks+1]=string.char(table.unpack(out,i,last))\n"
        "    end\n"
        "    return table.concat(chunks)\n"
        "end"
    )


_KSTREAM_RE = re.compile(r'--<<KSTREAM>>.*?--<<ENDKSTREAM>>', re.S)


def apply_keystream(vm_code: str) -> str:
    """KSTREAM 마커 사이(_ksm/_kss 정의)를 랜덤 상수/구조로 재생성한다."""
    body = "--<<KSTREAM>>\n" + _render_ksm() + "\n" + _render_kss() + "\n--<<ENDKSTREAM>>"
    return _KSTREAM_RE.sub(lambda _m: body, vm_code, count=1)


# ---------------------------------------------------------------------------
# 3. anti-tamper 검사 블록
# ---------------------------------------------------------------------------
# 불변식: clean 실행에서 _t==0 → crc 항등(팩타임 키와 일치). 따라서 아래는 자유롭게
# 랜덤화 가능하다 — 검사 항목/순서/가중치, 혼합식 f(_t) (단 f(0)=0 필수).
# 검사 대상 내장함수는 stock Lua 5.3에서 반드시 C 함수여야 한다(아니면 clean에서도
# _t가 증가해 키가 깨진다). 아래 풀은 전부 C 라이브러리 함수.
_TAMPER_C_POOL = [
    "string.byte", "string.char", "string.format", "string.sub", "string.rep",
    "string.len", "string.find", "string.gsub", "string.match", "string.gmatch",
    "table.unpack", "table.concat", "table.pack", "table.remove", "table.insert",
    "math.floor", "math.abs", "math.max", "math.min", "math.modf", "math.sqrt",
    "tostring", "tonumber", "select", "type", "rawget", "rawset",
    "setmetatable", "getmetatable", "ipairs", "next", "pcall",
]
# 항상 포함(메커니즘 핵심): 체커 자기보호 + run이 실제로 의존하는 함수들.
_TAMPER_ALWAYS = [
    "debug.getinfo", "string.dump", "debug.gethook",
    "error", "pcall", "tostring", "tonumber", "string.match",
]


def _render_tamper() -> str:
    lines: list[str] = []
    lines.append("--<<TAMPER>>")
    lines.append("local _hk,_hm,_hc=debug.gethook()")
    lines.append("local _t=0")

    def w() -> int:
        return random.randint(1, 0x3FFF)

    hook_checks = [
        f"if _hk~=nil then _t=_t+{w()} end",
        f"if _hm and #_hm>0 then _t=_t+{w()} end",
        f"if _hc and _hc~=0 then _t=_t+{w()} end",
    ]
    random.shuffle(hook_checks)

    # _isC 정의는 debug hook 검사 뒤, isC 검사 앞 어디든 가능. 위치 고정(간단).
    isc_def = ('local function _isC(f) local ok,info=pcall(debug.getinfo,f,"S") '
               'return ok and info~=nil and info.what=="C" end')

    pool = list(dict.fromkeys(_TAMPER_C_POOL))  # dedup, 순서 유지
    pool = [fn for fn in pool if fn not in _TAMPER_ALWAYS]
    random.shuffle(pool)
    fns = list(_TAMPER_ALWAYS) + pool[:random.randint(3, 7)]
    random.shuffle(fns)
    isc_checks = [f"if not _isC({fn}) then _t=_t+{w()} end" for fn in fns]

    lines.extend(hook_checks)
    lines.append(isc_def)
    lines.extend(isc_checks)

    # 혼합식 f(_t): f(0)=0 보장(모든 항이 _t 배수/시프트).
    k1 = random.randrange(1, 0x100000000) | 1
    mixes = [
        f"(_t*{k1})&0xFFFFFFFF",
        f"((_t*{k1})~((_t<<{random.randint(1,13)})&0xFFFFFFFF))&0xFFFFFFFF",
        f"((_t*{k1})+((_t*{random.randrange(1,0x100000000)|1})&0xFFFFFFFF))&0xFFFFFFFF",
    ]
    lines.append(f"crc=(crc~({random.choice(mixes)}))&0xFFFFFFFF")
    lines.append("--<<ENDTAMPER>>")
    return "\n    ".join(lines)


_TAMPER_RE = re.compile(r'--<<TAMPER>>.*?--<<ENDTAMPER>>', re.S)


def apply_tamper(vm_code: str) -> str:
    """TAMPER 마커 사이(변조 검사 블록)를 랜덤 항목/순서/가중치/혼합식으로 재생성."""
    return _TAMPER_RE.sub(lambda _m: _render_tamper(), vm_code, count=1)


# ---------------------------------------------------------------------------
# 4. source-line state
# ---------------------------------------------------------------------------
_U32_MASK = 0xFFFFFFFF


def _line_state_mix(lines: list[int], steps: list[tuple[int, int, int]]) -> int:
    state = 0
    for line, (mul, add, shift) in zip(lines, steps):
        state = ((state ^ ((line * mul) & _U32_MASK)) + add) & _U32_MASK
        state = (state ^ (state >> shift)) & _U32_MASK
    return state


def apply_line_state(
    vm_func_src: str,
    output_prefix: str = "",
    finalizer=None,
    output_passes: list[str] | None = None,
) -> tuple[str, int, list[int]]:
    """Inject line probes and compute the clean state from the final layout.

    Runtime code never compares against a visible expected line. Observed line
    values become a per-build local state; the builder derives the same value
    for encryption and integrity-constant encoding.  The block is generated
    after the large VM output pipeline, so it uses the small structured literal
    emitter directly instead of reparsing the complete VM source.
    """
    anchor = "return function(...)"
    anchor_pos = vm_func_src.find(anchor)
    if anchor_pos < 0:
        raise ValueError("VM function source is missing its return-function anchor")

    seed_bytes = hashlib.sha256(repr(random.getstate()).encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(seed_bytes, "big"))
    probe_count = rng.randint(3, 5)
    alphabet = "abcdefghijklmnopqrstuvwxyz"

    def ident(tag: str) -> str:
        tail = "".join(rng.choice(alphabet) for _ in range(8))
        return f"_l{tag}{tail}"

    parser_name = ident("p")
    state_name = ident("s")
    probe_names = [ident("f") for _ in range(probe_count)]
    message_names = [ident("e") for _ in range(probe_count)]
    value_names = [ident("v") for _ in range(probe_count)]
    tokens = [f"K{rng.getrandbits(32):08x}" for _ in range(probe_count)]
    fallbacks = [rng.getrandbits(24) | 1 for _ in range(probe_count)]
    steps = [
        (rng.getrandbits(32) | 1, rng.getrandbits(32), rng.randint(5, 17))
        for _ in range(probe_count)
    ]

    selected_passes = list(output_passes or [])
    localize = "localize_globals" in selected_passes
    if localize:
        env_name = ident("g")
        error_name = ident("r")
        pcall_name = ident("c")
        tostring_name = ident("t")
        tonumber_name = ident("n")
        match_name = ident("m")
        string_name = ident("q")
        block: list[str] = [
            f"local {env_name}=_ENV",
            f'local {error_name}={env_name}["error"]',
            f'local {pcall_name}={env_name}["pcall"]',
            f'local {tostring_name}={env_name}["tostring"]',
            f'local {tonumber_name}={env_name}["tonumber"]',
            f'local {string_name}={env_name}["string"]',
            f'local {match_name}={string_name}["match"]',
        ]
    else:
        error_name = "error"
        pcall_name = "pcall"
        tostring_name = "tostring"
        tonumber_name = "tonumber"
        match_name = "string.match"
        block = []

    for probe_name, token in zip(probe_names, tokens):
        # Keep each declaration on one source line.  The declaration position
        # remains a stable marker even when its string literal is lowered.
        block.append(
            f'local function {probe_name}() {error_name}("{token}") end'
        )
    parser_value_name = ident("x")
    block.append(
        f"local function {parser_name}(e,z) local {parser_value_name}="
        f"{tostring_name}(e) return {tonumber_name}("
        f'{match_name}({parser_value_name},":(%d+):")) or z end'
    )
    for probe_name, message_name in zip(probe_names, message_names):
        block.append(f"local _,{message_name}={pcall_name}({probe_name})")
    for message_name, value_name, fallback in zip(message_names, value_names, fallbacks):
        block.append(f"local {value_name}={parser_name}({message_name},{fallback})")
    block.append(f"local {state_name}=0")
    for value_name, (mul, add, shift) in zip(value_names, steps):
        block.append(
            f"{state_name}=(({state_name}~(({value_name}*0x{mul:08X})&0xFFFFFFFF))"
            f"+0x{add:08X})&0xFFFFFFFF"
        )
        block.append(
            f"{state_name}=({state_name}~({state_name}>>{shift}))&0xFFFFFFFF"
        )

    block_source = "\n".join(block)
    literal_passes = [
        name for name in selected_passes
        if name in {"number_obf", "string_obf", "boolean_obf"}
    ]
    if literal_passes:
        from .output_emitter import emit_vm_literals

        # Line-state generation intentionally owns a private PRNG so adding
        # this late stage cannot perturb the main pipeline's random sequence.
        global_random_state = random.getstate()
        try:
            random.setstate(rng.getstate())
            block_source, _ = emit_vm_literals(block_source, literal_passes)
            rng.setstate(random.getstate())
        finally:
            random.setstate(global_random_state)

    vm_func_src = re.sub(r"\b_LS\b", state_name, vm_func_src)
    anchor_pos = vm_func_src.find(anchor)
    if finalizer is not None:
        # The large VM source has already passed through the finalizer.  Only
        # this late fragment is new; minifying the complete multi-megabyte VM
        # again was the remaining max-profile hot-path duplication.
        block_source = finalizer(block_source)
        insertion = " " + block_source + " "
    else:
        insertion = "\n" + block_source + "\n"
    insert_at = anchor_pos + len(anchor)
    result = vm_func_src[:insert_at] + insertion + vm_func_src[insert_at:]

    prefix_lines = output_prefix.count("\n")
    probe_lines: list[int] = []
    for probe_name in probe_names:
        marker_pos = result.find(f"function {probe_name}")
        if marker_pos < 0:
            raise AssertionError("line probe marker disappeared during rendering")
        probe_lines.append(prefix_lines + result[:marker_pos].count("\n") + 1)

    return result, _line_state_mix(probe_lines, steps), probe_lines
