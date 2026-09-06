from __future__ import annotations

import os
import shutil
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def lua_executable() -> str:
    """Return the Lua 5.3 executable used by local and CI tests."""
    bundled = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    if bundled.exists():
        return str(bundled)

    for name in ("lua5.3", "lua53", "lua"):
        system = shutil.which(name)
        if system:
            return system

    raise RuntimeError(
        "Lua interpreter not found "
        "(checked bundled bin/lua and lua5.3/lua53/lua on PATH)"
    )
