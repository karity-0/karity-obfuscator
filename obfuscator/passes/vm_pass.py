from __future__ import annotations
import subprocess
import platform
import tempfile
import shutil
import os
from pathlib import Path

from .base import PostPass
from .parser import Lua53Parser
from .serializer import serialize

if platform.system() == "Windows":
    _LUAC = Path(__file__).parent.parent.parent / "bin" / "luac53.exe"
else:
    _LUAC = shutil.which("luac5.3") or shutil.which("luac53") or "luac5.3"

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


def _to_lua_string(data: bytes) -> str:
    return '"' + "".join(f"\\{b}" for b in data) + '"'


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
        .add(StringObfuscationPass())
        .add(BooleanObfuscationPass())
        .add(NumberObfuscationPass())
        .add(RenameObfuscationPass())
        .add(MinifyPass())
    ).run(script)


class VMPass(PostPass):
    def run(self, script: str) -> str:
        # 1. luac 컴파일
        luac_bytes = _compile(script)

        # 2. 파싱 → 커스텀 직렬화 (헤더 제거, debug info 제거)
        proto = Lua53Parser(luac_bytes).parse()
        blob  = serialize(proto)

        # 3. VM 코드 로드
        vm_code = _load_vm()

        # 4. blob → Lua 문자열
        lua_blob = _to_lua_string(blob)

        # 5. 최종 출력 조합
        raw = (
            f"local _vm=(function()\n"
            f"{vm_code}\n"
            f"return {{run=run}}\n"
            f"end)()\n"
            f"_vm.run({lua_blob})\n"
        )

        # 6. VM 출력물 재난독화
        return _obfuscate_vm_output(raw)