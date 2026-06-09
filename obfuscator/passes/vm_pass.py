from __future__ import annotations
import subprocess
import tempfile
import os
import random
import re
from pathlib import Path

from .base import PostPass
from .parser import Lua53Parser
from .serializer import serialize
from .kae_blob import encrypt_blob

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
    return '"' + (length_enc or '0') + ':' + payload + '"' 


_LUA_OP_COUNT = 47  # Lua 5.3 opcode 0~46


def _make_shuffle_map() -> dict[int, int]:
    """원본op → 셔플op 매핑 (랜덤 순열)"""
    ops = list(range(_LUA_OP_COUNT))
    shuffled = ops[:]
    random.shuffle(shuffled)
    return {orig: shuf for orig, shuf in zip(ops, shuffled)}
 
 
def _apply_shuffle_to_vm(vm_code: str, shuffle_map: dict[int, int]) -> str:
    """vm.lua exec 분기의 op==N 숫자를 shuffle_map[N] 으로 직접 치환"""
    return re.sub(r'op==(\d+)', lambda m: f"op=={shuffle_map[int(m.group(1))]}", vm_code)


def _load_vm() -> str:
    src = _VM_LUA_PATH.read_text(encoding="utf-8")
    cutoff = src.find("\nif arg and arg[0]")
    if cutoff != -1:
        src = src[:cutoff]
    return src


def _obfuscate_vm_output(script: str) -> str:
    """VM 출력물에 passes 재적용."""
    from .string_obfuscation import StringObfuscationPass
    from .boolean_obfuscation import BooleanObfuscationPass
    from .number_obfuscation import NumberObfuscationPass
    from .minify import MinifyPass
    from .rename_obfuscation import RenameObfuscationPass
    from ..pipeline import Pipeline

    return (
        Pipeline()
        #.add(StringObfuscationPass())
        #.add(BooleanObfuscationPass())
        #.add(NumberObfuscationPass())
        #.add(RenameObfuscationPass())
        #.add(MinifyPass())
    ).run(script)


class VMPass(PostPass):
    def run(self, script: str) -> str:
        # 1. luac 컴파일
        luac_bytes = _compile(script)

        # 2. 파싱 → 커스텀 직렬화
        shuffle_map = _make_shuffle_map()
        proto = Lua53Parser(luac_bytes).parse()
        blob  = serialize(proto, shuffle_map)

        # 3. VM 코드 로드 + opmap
        vm_code = _apply_shuffle_to_vm(_load_vm(), shuffle_map)

        # 4. blob 암호화: nonce(8B) + ciphertext
        _KEY = "karityObfuscator"
        nonce, ct = encrypt_blob(blob, _KEY)
        encrypted_blob = nonce + ct
        lua_blob = _to_base36(encrypted_blob)

        # 5. 최종 출력 조합
        raw = (
            f"local _vm=(function()\n"
            f"{vm_code}\n"
            f"return {{a=run}}\n"
            f"end)()\n"
            f"_vm.a({lua_blob},'karityObfuscator')\n"
        )

        # 6. VM 출력물 재난독화
        return _obfuscate_vm_output(raw)