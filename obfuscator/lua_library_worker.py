"""Isolated Lua 5.3 C API worker. Invoked by LuaToolchain, not the GUI process."""
from __future__ import annotations

import ctypes as C
from pathlib import Path
import sys


def run(library: str, operation: str, source: bytes) -> bytes:
    try:
        dll = C.CDLL(library)
    except OSError as exc:
        raise RuntimeError(
            f"cannot load lua_library {library}: {exc}. "
            f"Use a library matching this {C.sizeof(C.c_void_p) * 8}-bit Python "
            "and install its DLL dependencies."
        ) from exc

    def bind(name, result, *args):
        try:
            fn = getattr(dll, name)
        except AttributeError as exc:
            raise RuntimeError(f"lua_library is missing Lua 5.3 C API symbol {name}") from exc
        fn.restype = result
        fn.argtypes = args
        return fn

    state_type = C.c_void_p
    newstate = bind("luaL_newstate", state_type)
    close = bind("lua_close", None, state_type)
    load = bind("luaL_loadbufferx", C.c_int, state_type, C.c_char_p,
                C.c_size_t, C.c_char_p, C.c_char_p)
    pcall = bind("lua_pcallk", C.c_int, state_type, C.c_int, C.c_int,
                 C.c_int, C.c_ssize_t, C.c_void_p)
    tostring = bind("lua_tolstring", C.c_void_p, state_type, C.c_int,
                    C.POINTER(C.c_size_t))
    settop = bind("lua_settop", None, state_type, C.c_int)
    gettype = bind("lua_type", C.c_int, state_type, C.c_int)
    openlibs = bind("luaL_openlibs", None, state_type)
    writer_type = C.CFUNCTYPE(C.c_int, state_type, C.c_void_p, C.c_size_t, C.c_void_p)
    dump = bind("lua_dump", C.c_int, state_type, writer_type, C.c_void_p, C.c_int)

    state = newstate()
    if not state:
        raise RuntimeError("lua_library: could not create Lua state")
    try:
        def check(status):
            if status:
                size = C.c_size_t()
                pointer = tostring(state, -1, C.byref(size))
                message = C.string_at(pointer, size.value).decode("utf-8", errors="replace") if pointer else "non-string Lua error"
                raise RuntimeError(f"lua_library: {message}")

        def dump_top(strip):
            parts = []
            errors = []

            @writer_type
            def writer(_state, data, size, _user):
                try:
                    parts.append(C.string_at(data, size))
                    return 0
                except Exception as exc:
                    errors.append(exc)
                    return 1

            status = dump(state, writer, None, int(strip))
            if status or errors:
                raise RuntimeError("lua_library: lua_dump failed")
            return b"".join(parts)

        # Check the actual format before using the library to build anything.
        check(load(state, b"return 1", 8, b"=version-check", b"t"))
        header = dump_top(True)
        compat = None
        if header[:6] == b"\x1bLua\x53\x02" and hasattr(dll, "lua_compat"):
            # The optional compatibility export selects standard dumps.
            compat = bind("lua_compat", None, C.c_int)
            compat(1)
            header = dump_top(True)
        if header[:6] != b"\x1bLua\x53\x00":
            raise RuntimeError(f"lua_library must produce standard Lua 5.3 bytecode; got header {header[:17].hex()}")
        if header[12:17] != bytes((4, 8, 4, 8, 8)):
            raise RuntimeError("lua_library bytecode layout is unsupported (requires 64-bit size_t/integer and double numbers)")
        settop(state, 0)

        if operation not in {"compile", "dump", "execute"}:
            raise ValueError(f"unknown Lua library operation: {operation}")
        if compat is not None and operation == "execute":
            compat(0)
        if operation != "compile":
            openlibs(state)
        check(load(state, source, len(source), b"=karity", b"t"))
        if operation == "compile":
            return dump_top(False)
        check(pcall(state, 0, 1 if operation == "dump" else 0, 0, 0, None))
        if operation == "execute":
            return b""
        if gettype(state, -1) != 6:  # LUA_TFUNCTION
            raise RuntimeError("lua_library: dump wrapper did not return a function")
        return dump_top(True)
    finally:
        close(state)


if __name__ == "__main__":
    try:
        library, operation, source_path, output_path = sys.argv[1:]
        result = run(library, operation, Path(source_path).read_bytes())
        Path(output_path).write_bytes(result)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
