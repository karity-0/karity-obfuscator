"""
load 기반 패커 (PostPass).

최종 출력 문자열을 raw DEFLATE로 압축 → base64로 임베드 → 런타임에
inflate 후 `load`로 실행하는 작은 스텁으로 감싼다.

- 압축은 Python `zlib`(raw deflate, wbits=-15)로 하고, 복원은 순수 Lua
  inflate 스텁(`pack_stub.lua`)이 담당한다.
- VM 자기-dump 무결성(crc)과 충돌하지 않는다: 스텁은 원본 출력을
  **byte-exact**로 복원해 `load`하므로, _vmf가 동일 소스로 재컴파일되어
  dump/crc가 그대로 유지된다(라운드트립이 무손실인 한 안전).
- 반드시 다른 모든 패스(특히 VMPass) **이후 마지막**에 실행되어야 한다.

스텁 형태는 `pack_stub.lua`에서 편집 가능하다(__DATA__/__ACTION__ 치환).
"""
from __future__ import annotations

import base64
import zlib
from pathlib import Path

from .base import PostPass

_STUB_PATH = Path(__file__).parent / "pack_stub.lua"
_HEADER = "-- obfuscated using karity obfuscator!\n"
_ACTION = "return load(_inf(_b64(_D)))()"


class PackerPass(PostPass):
    """최종 출력을 압축/임베드해 load 스텁으로 감싼다."""

    def run(self, script: str) -> str:
        raw = script.encode("utf-8")
        co = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw deflate (헤더/체크섬 없음)
        comp = co.compress(raw) + co.flush()
        payload = base64.b64encode(comp).decode("ascii")

        stub = _STUB_PATH.read_text(encoding="utf-8")
        packed = stub.replace("__DATA__", payload).replace("__ACTION__", _ACTION)
        return _HEADER + packed
