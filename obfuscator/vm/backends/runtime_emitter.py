from __future__ import annotations
from obfuscator.names import NameAllocator
import subprocess
import tempfile
import secrets
import string
import random
import hashlib
import time
import zlib
import os
import re
from pathlib import Path

from obfuscator.passes.base import PostPass
from obfuscator.toolchain import LuaToolchain, LIBRARY_DUMP_FUNCTION
from obfuscator.vm.backends.handler_codec import (
    patch_integrity_sources,
)
from obfuscator.vm.kae_blob import encrypt_blob
from obfuscator.vm.vm_variants import apply_instr_layout
from obfuscator.vm.output_emitter import EMITTER_PASS_NAMES, emit_vm_literals
from obfuscator.vm.runtime_trace import apply_runtime_trace


def _compile(script: str, toolchain: LuaToolchain | None = None) -> bytes:
    toolchain = toolchain or LuaToolchain()
    if toolchain.lua_library:
        return toolchain.run_library(script, "compile")
    luac = toolchain.luac()
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False, mode="w", encoding="utf-8") as f:
        f.write(script)
        src_path = f.name

    out_path = src_path + ".luac"
    try:
        result = subprocess.run(
            [luac, "-o", out_path, src_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"luac failed: {result.stderr.decode()}")

        with open(out_path, "rb") as f:
            data = f.read()
        if data[:6] != b"\x1bLua\x53\x00":
            raise RuntimeError("luac_executable must produce standard Lua 5.3 bytecode")
        return data
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


def _dump_function_stripped(
    vm_func_src: str,
    header: str,
    decoy_name: str,
    decoy_value: str,
    toolchain: LuaToolchain | None = None,
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
    toolchain = toolchain or LuaToolchain()
    if toolchain.lua_library:
        return toolchain.run_library(wrapped, "dump")

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
        result = subprocess.run([toolchain.lua(), helper_path], capture_output=True)
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


def _load_vm(backend_adapter, lowered_ir, library_dump: bool = False, target=None) -> str:
    if target is None:
        from ..targets.lua53 import Lua53Target
        target=Lua53Target()
    src = target.runtime_template('vm.lua')
    if library_dump:
        src = src.replace("string.dump(self_func,true)", LIBRARY_DUMP_FUNCTION + "(self_func,true)")
    cutoff = src.find("\nif arg and arg[0]")
    if cutoff != -1:
        src = src[:cutoff]
    return backend_adapter.compose_runtime(src, lowered_ir, target=target)


_CLASSIC_SEMANTIC_TOKENS = (
    "__VM_DATA_VALUE__", "__VM_DATA_GET__", "__VM_DATA_SET__",
    "__VM_CMP_EQ__", "__VM_CMP_LT__", "__VM_CMP_LE__",
    "__VM_CMP_TRUTH__", "__VM_OP_MOD__", "__VM_OP_POW__",
    "__VM_OP_DIV__", "__VM_OP_IDIV__", "__VM_OP_NOT__",
    "__VM_OP_LEN__", "__VM_OP_CONCAT__", "__VM_OP_NEWTABLE__",
    "__VM_OP_SETLIST__", "__VM_OP_CLOSURE__", "__VM_OP_VARARG__",
)

_CLASSIC_ARITHMETIC_TOKENS = (
    "__VM_SLOT_ADD__", "__VM_SLOT_SUB__", "__VM_SLOT_MUL__",
    "__VM_SLOT_BAND__", "__VM_SLOT_BOR__", "__VM_SLOT_BXOR__",
    "__VM_SLOT_SHL__", "__VM_SLOT_SHR__", "__VM_SLOT_UNM__", "__VM_SLOT_BNOT__",
)


def _apply_classic_runtime_tokens(vm_code: str) -> str:
    """Resolve current transform tokens without generating Karity graphs."""
    semantic_tags = random.sample(range(0x10000, 0x7FFFFFFF),
                                  len(_CLASSIC_SEMANTIC_TOKENS))
    for token, value in zip(_CLASSIC_SEMANTIC_TOKENS, semantic_tags):
        vm_code = vm_code.replace(token, str(value))

    slot_tokens = _CLASSIC_ARITHMETIC_TOKENS
    slot_values = random.sample(range(0x10000, 0x7FFFFFFF), len(slot_tokens))
    for token, value in zip(slot_tokens, slot_values):
        vm_code = vm_code.replace(token, str(value))

    unresolved = sorted(
        token for token in set(re.findall(r"__VM_[A-Z0-9_]+__", vm_code))
        if token != "__VM_HOT_LOOP__"
    )
    if unresolved:
        raise RuntimeError(
            "classic runtime has unresolved VM tokens: " + ", ".join(unresolved)
        )
    return vm_code



_VM_RENAME_KEYS = [
    # proto table keys
    "num_params", "is_vararg", "max_stack_size", "vm_id",
    "constants", "code", "avalanche", "graph_sites", "block_routes", "upvalues", "protos",
    "instack", "idx",
    # reader method names
    "u8", "u16", "u32", "u64", "i64", "f64", "str",
]


def _rename_vm_keys(src: str) -> str:
    """vm.lua 내의 테이블 키 및 reader 메서드명을 랜덤 이름으로 치환."""
    import re
    allocator = NameAllocator.for_source(src, seed=random.getrandbits(64))
    rename_map = {k: allocator.allocate(k) for k in _VM_RENAME_KEYS}
    for orig, new in rename_map.items():
        src = re.sub(rf'\b{re.escape(orig)}\b', new, src)
        src = src.replace(f'["{orig}"]', f'["{new}"]')
        src = src.replace(f"['{orig}']", f"['{new}']")
    return src


def _obfuscate_vm_output(
    script: str,
    pass_names: list[str],
    *,
    compact_globals: bool = False,
) -> tuple[str, list[dict]]:
    """Run structural VM passes, shared literal emitters, then text post-passes."""
    from obfuscator.pipeline import Pipeline
    from obfuscator.profiling import Profiler
    from obfuscator.registry import PASS_REGISTRY

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
        # Keep fun phrases visible after the structured string/number emitters.
        (after if issubclass(cls, PostPass) or name == "meme_strings" else before).append((name, cls))

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
        from obfuscator.passes.ts_utils import parse as parse_ts

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
        from obfuscator.passes.localize_globals import LocalizeGlobalsPass
        from obfuscator.passes.rename_ts import rename_plan_with_ctx_profiled
        if shared_ctx is None:
            from obfuscator.passes.ts_utils import parse as parse_ts

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
            localize_replacements = LocalizeGlobalsPass(
                compact_aliases=compact_globals,
            ).replacements_with_ctx(
                output,
                shared_ctx,
                renamed_spans,
                reserved_names={item.new_text for item in planned_replacements},
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

    if "rename_obf" in identifier_names:
        from obfuscator.passes.rename_ts import rename_script_ts
        stage_start = time.perf_counter()
        output = rename_script_ts(output)
        details.append({"phase": "vm_output:final_names",
                        "elapsed": round(time.perf_counter() - stage_start, 6)})

    output, post_details = run_legacy(output, after)
    details.extend(post_details)

    # Never expose build-time dispatcher annotations, even without minify.
    output = output.replace("--[[VM_DISPATCH_ENTRY]]", " ")
    return output, details



def emit_runtime(backend_adapter, lowered_ir, context) -> str:
    from ..targets.lua53 import Lua53Target
    target = context.target or Lua53Target()
    proto = lowered_ir.program
    protection_plan = lowered_ir.protection_plan
    protected_semantic_ir = lowered_ir.semantic_ir
    root_protection = protection_plan.functions[protected_semantic_ir.root.id]
    planned_runtime_variants = backend_adapter.runtime_variants(lowered_ir)
    output_transform = context.output_transform or _obfuscate_vm_output

    prepared = lowered_ir.backend_data["layout"]
    instr_layout = prepared.instruction_layout
    constant_tags, constant_kinds = prepared.constant_tags, prepared.constant_kinds
    constant_tag_names = tuple(constant_tags)
    materialization = lowered_ir.backend_data.get("materialization")
    blob = backend_adapter.serialize_program(lowered_ir, context)

    # 3. VM 코드 로드 + (단일/멀티) exec 생성
    _phase_start = time.perf_counter()
    runtime_source = _load_vm(backend_adapter, lowered_ir,
                             target.library_dump_normalization and bool(context.toolchain.lua_library),
                             target=target)
    if materialization is not None:
        runtime_source = materialization.prepare_runtime(runtime_source)
        context.profile.append({"phase": "materialize_host_constants", "elapsed": 0.0,
                                "constants": len(materialization.references)})
    vm_code = _rename_vm_keys(apply_runtime_trace(
        target.prepare_runtime(runtime_source, lowered_ir),
        enabled=bool(lowered_ir.policy.get("runtime_trace", False)),
    ))
    for name in constant_tag_names:
        vm_code = vm_code.replace(
            f"__VM_CTAG_{name.upper()}__", str(constant_tags[name])
        )
        vm_code = vm_code.replace(
            f"__VM_CK_{name.upper()}__", str(constant_kinds[name])
        )
    vm_code = backend_adapter.emit_handlers(vm_code, lowered_ir, planned_runtime_variants)

    # 3a. per-run VM 변형: keystream(_ksm/_kss) + anti-tamper 블록 재생성 후,
    # instruction 레이아웃 토큰(_SH_*/_MASK_OV)을 리터럴로 인라인한다.
    # 레이아웃 인라인은 fused 핸들러가 주입한 _SH_* 토큰까지 잡아야 하므로
    # 모든 핸들러/디스패치 transform 이후에 마지막으로 적용한다.
    vm_code = target.apply_keystream(vm_code)
    vm_code = target.apply_tamper(vm_code)
    vm_code = apply_instr_layout(vm_code, instr_layout)
    context.profile.append({"phase": "build_vm_code", "elapsed": round(time.perf_counter() - _phase_start, 6)})

    # 3b. 블롭 저장 형태 결정. run은 type 분기 없이 스크립트마다 한 형태로
    # 고정 emit되므로, 형태별 재조립 프롤로그를 from_base36(blob) 자리에 주입한다.
    #   - string : 단일 base36 문자열 (주입 없음)
    #   - table  : 스크램블 청크 테이블 → table.concat 후 from_base36
    #   - numeric: 32비트 정수 테이블 → base36 우회, 바이트 직접 복원
    # 주입은 output_transform(재난독화) 전에 해야 주입한 전역(table.concat/
    # string.char 등)도 함께 localize/rename 된다. 블롭 리터럴 자체는 _vmf
    # 인자라 dump/crc와 무관(컨테이너 형태를 바꿔도 anti-tamper 영향 없음).
    blob_form = root_protection["blob_form"]
    if blob_form == "table":
        vm_code = vm_code.replace("from_base36(blob)",
                                  "from_base36(table.concat(blob))", 1)
    elif blob_form == "numeric":
        decode_call = target.blob_decode_call()
        vm_code = vm_code.replace(
            decode_call, target.numeric_blob_decoder(_NUMERIC_DECODE), 1,
        )

    # 4. dump 대상 함수 소스 구성 + 재난독화 (이후 텍스트 변경 없음)
    _phase_start = time.perf_counter()

    runtime_entry = target.runtime_entry_symbol()
    vm_func_src = (
        f'return function(...)\n'
        f'local k1,k2,k3,k4,k5,k6,k7 = ... '
        f'{vm_code} return {runtime_entry} end'
    )

    # Backend-local runtime construction must precede target finalization and
    # output passes: graphs, direct tokens, and any future representation all
    # need the same identifier, syntax, and integrity treatment.  The shared
    # emitter intentionally makes no backend-kind decision here.
    _runtime_body_start = time.perf_counter()
    _runtime_body_input_bytes = len(vm_func_src.encode("utf-8"))
    runtime_body = backend_adapter.emit_runtime_body(
        vm_func_src, lowered_ir, target=target,
    )
    vm_func_src = runtime_body.source
    _runtime_body_elapsed = time.perf_counter() - _runtime_body_start
    _runtime_body_output_bytes = len(vm_func_src.encode("utf-8"))
    graph_detail = {
        "phase": runtime_body.phase,
        "class": runtime_body.implementation,
        "elapsed": round(_runtime_body_elapsed, 6),
        "input_bytes": _runtime_body_input_bytes,
        "output_bytes": _runtime_body_output_bytes,
        "delta_bytes": _runtime_body_output_bytes - _runtime_body_input_bytes,
        "graph_sites": runtime_body.graph_sites,
        "graph_families": runtime_body.graph_families,
        "backend": runtime_body.backend,
    }

    # Graph banks and blob decoders may introduce target API operations too.
    # Finalize the complete runtime before output passes rename its identifiers.
    vm_func_src = target.finalize_runtime(vm_func_src)
    vm_func_src, vm_output_details = output_transform(
        vm_func_src,
        context.output_passes,
    )
    vm_func_src = vm_func_src.replace(
        "--[[KARITY_EXACT_BEGIN]]", "",
    ).replace("--[[KARITY_EXACT_END]]", "")
    vm_output_details.insert(0, graph_detail)

    vm_func_src = target.lower_source(vm_func_src)
    _line_state_start = time.perf_counter()
    vm_func_src, line_state, probe_lines = target.bind_lines(vm_func_src, context)
    context.profile.append({
        "phase": "source_line_state",
        "elapsed": round(time.perf_counter() - _line_state_start, 6),
        "probe_count": len(probe_lines),
        "probe_lines": probe_lines,
    })

    context.profile.append({
        "phase": "obfuscate_vm_output",
        "elapsed": round(
            time.perf_counter() - _phase_start,
            6,
        ),
        "details": vm_output_details,
    })

    # 재난독화 결과 맨 앞의 헤더 주석을 분리 (dump/key 계산엔 영향 없음)
    header = context.output_prefix

    # 5. 확정된 vm_func_src를 load+dump(strip) → crc32 기반 key 재료
    _phase_start = time.perf_counter()
    wrapper_alphabet = string.ascii_letters
    wrapper_names = NameAllocator.for_source(vm_func_src, seed=random.getrandbits(64))
    decoy_name = wrapper_names.allocate("decoy")
    vmf_name = wrapper_names.allocate("vm")
    decoy_value = "".join(
        secrets.choice(wrapper_alphabet)
        for _ in range(34)
    )
    dump_bytes = target.dump_function(
        vm_func_src, header, decoy_name, decoy_value, context.toolchain,
    )
    dump_crc   = zlib.crc32(dump_bytes) & 0xFFFFFFFF
    effective_crc = (dump_crc ^ line_state) & 0xFFFFFFFF
    if lowered_ir.policy.get("integrity_constants", False):
        blob = patch_integrity_sources(
            blob, effective_crc, line_state, constant_tags,
        )
    context.profile.append({"phase": "dump_vm_function", "elapsed": round(time.perf_counter() - _phase_start, 6)})

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
    context.profile.append({"phase": "encrypt_blob", "elapsed": round(time.perf_counter() - _phase_start, 6)})

    # 7. 최종 출력 조합 — vm_func_src(_vmf 본문)는 더 이상 재가공하지 않음
    # vm_func_src: "return function(...) ... end" → _vmf 본문으로 그대로 사용
    return target.wrap(vm_func_src, decoy_name, decoy_value, vmf_name, lua_blob, rand_tail)
