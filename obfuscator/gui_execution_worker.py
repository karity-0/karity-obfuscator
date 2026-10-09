"""Child process entry point for library-backed and Lua 5.1 fallback runs."""
from pathlib import Path
import sys


if __name__ == "__main__":
    try:
        mode, source, version, *libraries = sys.argv[1:]
        script = Path(source).read_bytes()
        if mode == "library":
            from lua_library_worker import run
            run(libraries[0], "execute", script, version)
        else:
            from lupa.lua51 import LuaRuntime
            LuaRuntime(encoding=None).execute(script)
    except Exception as exc:
        print(str(exc), file=sys.stderr, flush=True)
        sys.exit(1)
