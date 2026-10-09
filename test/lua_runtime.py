from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def _toolchain(lua_version: str):
    # Some scripts import this helper before putting the repository on sys.path.
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    from obfuscator.toolchain import LuaToolchain
    return LuaToolchain(lua_version=lua_version)


def lua_executable(lua_version: str = "5.3") -> str:
    """Use the production bundled/PATH resolver on both Windows and Linux."""
    return _toolchain(lua_version).lua()


def luac_executable(lua_version: str = "5.3") -> str:
    """Resolve a compiler with the same version-specific toolchain contract."""
    return _toolchain(lua_version).luac()
