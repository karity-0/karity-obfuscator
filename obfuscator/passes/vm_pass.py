from __future__ import annotations
import subprocess
import tempfile
import secrets
import string
import random
import zlib
import os
from pathlib import Path

from .base import PostPass
from .parser import Lua53Parser
from .serializer import serialize
from .kae_blob import encrypt_blob
from .vm_obfuscation import collect_used_ops, prune_and_inject_handlers, apply_vop_to_vm

_LUA         = Path(__file__).parent.parent.parent / "bin" / "lua.exe"
_LUAC        = Path(__file__).parent.parent.parent / "bin" / "luac53.exe"
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


def _to_base36(data: bytes) -> str:
    """bytes → "length:base36payload" 형식"""
    length = len(data)
    n = int.from_bytes(data, 'big') if data else 0
    digits = []
    while n:
        digits.append('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[n % 36])
        n //= 36
    payload = ''.join(reversed(digits)) if digits else '0'
    ln, length_enc = length, ''
    while ln:
        length_enc = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[ln % 36] + length_enc
        ln //= 36
    return '"KARITY/' + (length_enc or '0') + ':' + payload + '"' 


_LUA_OP_COUNT = 47  # Lua 5.3 opcode 0~46
_VOP_SPACE    = 128  # 7비트 op × 256 variant = 32768, 실용 범위는 128*256


def _make_vop_map() -> dict[int, list[int]]:
    """원본op(0~46) → alias vop 목록 매핑.

    각 원본 op당 2~3개의 alias vop를 생성.
    serialize 시 alias 중 랜덤 선택해서 emit → 같은 op라도 매번 다른 vop.
    vop = op(7비트) | (variant(8비트) << 7)
    """
    used_vops: set[int] = set()
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


def _dump_function_stripped(vm_func_src: str, header: str = "") -> bytes:
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
        f'{header}'
        f'local a="obfuscated using karity obfuscator"'
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
        f'local f=load(content)()\n'
        f'local out=io.open("{dump_path_lua}","wb")\n'
        f'out:write(string.dump(f,true)) out:close()\n'
    )
    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(helper)

    try:
        result = subprocess.run([str(_LUA), helper_path], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"lua dump failed: {result.stderr.decode()}")

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


def _obfuscate_vm_output(script: str, pass_names: list[str]) -> str:
    """VM 출력물에 passes 재적용."""
    from ..pipeline import Pipeline
    from ..registry import PASS_REGISTRY
 
    pipeline = Pipeline()
    for name in pass_names:
        info = PASS_REGISTRY.get(name)
        if info is None:
            continue

        cls = info["cls"]

        if cls.__name__ == "VMPass":
            continue

        pipeline.add(cls())
 
    return pipeline.run(script)



_DEFAULT_VM_OPTIONS = {
    "fake_handlers": True,
    "mutate_handlers": True,
}


class VMPass(PostPass):
    def __init__(self, vm_output_passes: list[str] | None = None, vm_options: dict | None = None):
        self.vm_output_passes = vm_output_passes or []
        self.vm_options = {**_DEFAULT_VM_OPTIONS, **(vm_options or {})}

    def run(self, script: str) -> str:
        # 1. luac 컴파일
        luac_bytes = _compile(script)

        # 2. 파싱 → 커스텀 직렬화
        vop_map = _make_vop_map()
        proto = Lua53Parser(luac_bytes).parse()
        blob  = serialize(proto, vop_map)

        # 3. VM 코드 로드 + vopmap 적용 + 핸들러 prune/가짜 핸들러 삽입
        used_ops = collect_used_ops(proto, vop_map)
        vm_code = apply_vop_to_vm(_load_vm(), vop_map)
        vm_code = prune_and_inject_handlers(
            vm_code,
            used_ops,
            fake_handlers=self.vm_options["fake_handlers"],
            mutate=self.vm_options["mutate_handlers"],
        )

        # 4. dump 대상 함수 소스 구성 + 재난독화 (이후 텍스트 변경 없음)
        vm_func_src = (
            f'return function(...)\n'
            f'local k1,k2,k3,k4,k5,k6,k7 = ... '
            f'{vm_code} return run end'
        )
        vm_func_src = _obfuscate_vm_output(vm_func_src, self.vm_output_passes)

        # 재난독화 결과 맨 앞의 헤더 주석을 분리 (dump/key 계산엔 영향 없음)
        from ..pipeline import Pipeline
        header = ""
        if vm_func_src.startswith(Pipeline.HEADER):
            header = Pipeline.HEADER
            vm_func_src = vm_func_src[len(header):]

        # 5. 확정된 vm_func_src를 load+dump(strip) → crc32 기반 key 재료
        dump_bytes = _dump_function_stripped(vm_func_src, header)
        dump_crc   = zlib.crc32(dump_bytes) & 0xFFFFFFFF

        alphabet  = string.ascii_letters + string.digits
        rand_tail = ''.join(secrets.choice(alphabet) for _ in range(16))
        _KEY = f"karityObfuscator/{format(dump_crc, '08x')}/{rand_tail}"

        # 6. blob 암호화: nonce(8B) + ciphertext
        nonce, ct = encrypt_blob(blob, _KEY)
        encrypted_blob = nonce + ct
        lua_blob = _to_base36(encrypted_blob)

        # 7. 최종 출력 조합 — vm_func_src(_vmf 본문)는 더 이상 재가공하지 않음
        # vm_func_src: "return function(...) ... end" → _vmf 본문으로 그대로 사용
        vmf_body = vm_func_src[len("return "):]

        raw = (
            f'{header}'
            f'local a="obfuscated using karity obfuscator"'
            f'local _vmf={vmf_body};'
            f'return (_vmf(1032,413,258,104,953,283,120))'
            f'({lua_blob},"{rand_tail}",_vmf)\n'
        )

        return raw