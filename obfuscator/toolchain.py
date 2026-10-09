"""Per-build Lua tools, resolved only when a pass needs them."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .config_types import ObfuscatorConfig


TOOLCHAIN_KEYS = ("lua_executable", "luac_executable", "lua_library")
_BIN = Path(__file__).resolve().parents[1] / "bin"

# Normalize native dumps without changing the embedding runtime state.
LIBRARY_DUMP_FUNCTION = (
    Path(__file__).with_name("dump_normalizer.lua").read_text(encoding="utf-8").strip()
)


def _executable(value: str | None, key: str, bundled: str, names: tuple[str, ...], lua_version: str = "5.3") -> str:
    if value:
        path = Path(value).expanduser()
        if path.is_file():
            return str(path.resolve())
        # A configured path must never silently fall back to another runtime.
        if path.name == value:
            found = shutil.which(value)
            if found:
                return found
        raise FileNotFoundError(f"{key}: executable not found: {value}")
    path = _BIN / bundled
    if path.is_file():
        return str(path)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    raise FileNotFoundError(f"{key}: Lua {lua_version} tool not found; set {key} explicitly")


@dataclass(frozen=True)
class LuaToolchain:
    lua_executable: str | None = None
    luac_executable: str | None = None
    lua_library: str | None = None
    lua_version: str = "5.3"

    def __post_init__(self):
        if self.lua_version not in ("5.1", "5.3"):
            raise ValueError("unsupported Lua toolchain version")

    @classmethod
    def from_config(cls, config: ObfuscatorConfig) -> LuaToolchain:
        return cls(lua_executable=config.get("lua_executable"),
                   luac_executable=config.get("luac_executable"),
                   lua_library=config.get("lua_library"),
                   lua_version=config.get("target", {}).get("lua_version", "5.3"))

    def lua(self) -> str:
        if self.lua_version == "5.1":
            return _executable(self.lua_executable, "lua_executable",
                               "lua51.exe" if os.name == "nt" else "lua51", ("lua5.1", "lua51"), "5.1")
        return _executable(self.lua_executable, "lua_executable",
                           "lua.exe" if os.name == "nt" else "lua",
                           ("lua5.3", "lua53", "lua"))

    def luac(self) -> str:
        if self.lua_version == "5.1":
            return _executable(self.luac_executable, "luac_executable",
                               "luac51.exe" if os.name == "nt" else "luac51", ("luac5.1", "luac51"), "5.1")
        return _executable(self.luac_executable, "luac_executable",
                           "luac53.exe" if os.name == "nt" else "luac53",
                           ("luac5.3", "luac53", "luac"))

    def library(self) -> str | None:
        """Resolve an explicit library for embedding consumers; never load it here."""
        if not self.lua_library:
            return None
        path = Path(self.lua_library).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"lua_library: library not found: {self.lua_library}")
        return str(path.resolve())

    def run_library(self, script: str, operation: str = "execute", *, lua_version: str | None = None) -> bytes:
        """Compile, dump a returned function, or execute in an isolated DLL host.

        Explicit lua_library takes priority over executables for build operations.
        The worker keeps native crashes and Lua state out of the GUI process.
        """
        library = self.library()
        lua_version = lua_version or self.lua_version
        if library is None:
            raise ValueError("lua_library is not configured")
        with tempfile.TemporaryDirectory(prefix="karity-lua-library-") as folder:
            source = Path(folder) / "source.lua"
            output = Path(folder) / "result.bin"
            source.write_text(script, encoding="utf-8")
            python = Path(sys.executable)
            if python.name.lower() == "pythonw.exe":
                python = python.with_name("python.exe")
            command = [str(python), str(Path(__file__).with_name("lua_library_worker.py")),
                       library, operation, str(source), str(output)]
            if lua_version != "5.3":
                command.append(lua_version)
            try:
                result = subprocess.run(
                    command, capture_output=True, timeout=120,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("lua_library worker timed out after 120 seconds") from exc
            if result.returncode or not output.is_file():
                error = result.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"lua_library worker failed ({result.returncode}): {error}")
            return output.read_bytes()
