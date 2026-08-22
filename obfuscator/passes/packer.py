"""
load 기반 패커 (PostPass).

최종 VM 출력을 여러 raw-DEFLATE 후보로 압축하고 가장 작은 최종 packed
결과를 선택한다. 압축 payload는 최종 loader 함수의 stripped bytecode hash와
load fingerprint에서 파생한 rolling-XOR stream으로 감싼 뒤 base64로 임베드한다.
"""
from __future__ import annotations

import base64
import os
import platform
import secrets
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path

from .base import PostPass


_STUB_PATH = Path(__file__).parent / "pack_stub.lua"
_MASK32 = 0xFFFFFFFF

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


def _obfuscate_packer_output(script: str, pass_names: list[str]) -> str:
    from ..pipeline import Pipeline
    from ..registry import PASS_REGISTRY

    # Outer pipeline adds the public header once at the very end.
    # Re-obfuscating the loader must not add another header because the
    # loader's exact enclosing line context is part of string.dump().
    pipeline = Pipeline(show_header=False)
    for name in pass_names:
        info = PASS_REGISTRY.get(name)
        if info is None:
            continue
        pipeline.add(info["cls"]())
    return pipeline.run(script)


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & _MASK32
    return h


def _xorshift32(state: int) -> int:
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


def _dump_loader_stripped(loader_src: str) -> bytes:
    """Dump the loader in the exact enclosing context used by the final output.

    string.dump(..., true) still preserves line-definition metadata.  The
    runtime loader is bound as `local _P=<function>` immediately after the
    outer Pipeline.HEADER, so build-time dumping must reproduce that prefix.
    """
    if not _LUA or (isinstance(_LUA, Path) and not _LUA.exists()):
        raise FileNotFoundError("lua5.3 not found.")

    if not loader_src.startswith("return "):
        raise RuntimeError("packer loader pass output must start with 'return '")

    from ..pipeline import Pipeline

    loader_body = loader_src[len("return "):]
    wrapped = (
        f"{Pipeline.HEADER}"
        f"local _P={loader_body};"
        f"return _P"
    )

    with tempfile.NamedTemporaryFile(
        suffix=".lua",
        delete=False,
        mode="w",
        encoding="utf-8",
    ) as f:
        f.write(wrapped)
        src_path = f.name

    dump_path = src_path + ".dump"
    helper_path = src_path + ".helper.lua"
    src_lua = src_path.replace("\\", "\\\\")
    dump_lua = dump_path.replace("\\", "\\\\")

    helper = (
        f'local fh=assert(io.open("{src_lua}","rb"))\n'
        f'local src=fh:read("a") fh:close()\n'
        f'local chunk,err=load(src) if not chunk then error(err) end\n'
        f'local fn=chunk()\n'
        f'local out=assert(io.open("{dump_lua}","wb"))\n'
        f'out:write(string.dump(fn,true)) out:close()\n'
    )

    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(helper)

    try:
        result = subprocess.run([str(_LUA), helper_path], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(
                "lua packer dump failed: "
                + result.stderr.decode(errors="replace")
            )

        with open(dump_path, "rb") as f:
            return f.read()
    finally:
        for path in (src_path, dump_path, helper_path):
            if os.path.exists(path):
                os.unlink(path)

def _distinct_u32(count: int) -> list[int]:
    values: set[int] = set()
    while len(values) < count:
        values.add(secrets.randbits(32))
    return list(values)


def _render_loader(stub: str, values: dict[str, int]) -> str:
    for token, value in values.items():
        stub = stub.replace(token, f"0x{value:08X}")
    return stub


def _render_packed(loader_src: str, payload: str) -> str:
    if not loader_src.startswith("return "):
        raise RuntimeError("packer loader pass output must start with 'return '")

    loader_body = loader_src[len("return "):]

    # Keep _P before _D.  _dump_loader_stripped() reproduces this exact
    # enclosing prefix, while the outer Pipeline adds HEADER afterwards.
    return (
        f'local _P={loader_body};'
        f'local _D="{payload}";'
        f'return _P(_D,_P)\n'
    )


class PackerPass(PostPass):
    """최종 출력을 압축/암호화해 self-keyed load 스텁으로 감싼다."""

    def __init__(self, packer_output_passes: list[str] | None = None):
        self.packer_output_passes = packer_output_passes or []

    def run(self, script: str) -> str:
        raw = script.encode("utf-8")
        salt, type_bad, type_ok, lua_c, lua_lua, print_ok, print_bad = _distinct_u32(7)
        values = {
            "__SALT__": salt,
            "__FP_TYPE_BAD__": type_bad,
            "__FP_TYPE_OK__": type_ok,
            "__FP_C__": lua_c,
            "__FP_LUA__": lua_lua,
            "__FP_PRINT_OK__": print_ok,
            "__FP_PRINT_BAD__": print_bad,
        }

        loader_src = _render_loader(_STUB_PATH.read_text(encoding="utf-8"), values)
        loader_src = _obfuscate_packer_output(loader_src, self.packer_output_passes)

        dump_hash = _fnv1a32(_dump_loader_stripped(loader_src))
        expected_fp = type_ok ^ lua_c ^ print_ok

        best: str | None = None
        best_size: int | None = None
        for comp in _compress_candidates(raw):
            seed = (
                dump_hash
                ^ salt
                ^ expected_fp
                ^ ((len(comp) * 0x045D9F3B) & _MASK32)
            ) & _MASK32
            encrypted = _rolling_xor(comp, seed)
            payload = base64.b64encode(encrypted).decode("ascii")
            packed = _render_packed(loader_src, payload)
            size = len(packed.encode("utf-8"))
            if best_size is None or size < best_size:
                best = packed
                best_size = size

        if best is None:
            raise RuntimeError("packer failed to produce a compression candidate")
        return best
