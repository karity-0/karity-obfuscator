# Lua targets and toolchains

Select Lua 5.1 or 5.3 independently of the Classic, Karity or MOV backend with
`target.lua_version` or `--lua-version`. Source syntax must match the target;
this is not a general Lua 5.3-to-5.1 translator. Lua 5.4, LuaJIT chunks and
Luau are not supported targets.

Lua 5.1 keeps user values as native Lua values. Its runtime assets own exact
private-word storage, instruction decoding, argument packets and target APIs.
Generated output does not inject the general `int64.lua` or `lua51_shim.lua`
compatibility runtimes. Internal wide state is separate from binary64 user numbers.

See [Lua 5.1 pass support](lua51-pass-matrix.md) for source/output restrictions.
`function_obf` supports both stages; packing and several bitwise/integer-dependent
passes remain unavailable on Lua 5.1. VM dump integrity requires
`runtime_specific` compatibility and a matching target runtime; `portable`
compatibility does not permit the VM stage.

## Lua 5.1 tools and integrity dumps

Set `lua_executable`, `luac_executable` or `lua_library` to matching Lua 5.1
tools. A library takes priority; otherwise an explicit compiler compiles chunks
and an explicit interpreter creates integrity dumps. With no explicit tools the
adapter uses `lupa.lua51`. A compiler-only configuration still needs Lupa for
integrity dumps. Missing explicit tools fail without fallback. Automatic Lua 5.1
lookup cannot select the bundled Lua 5.3 executable.

The adapter accepts standard binary64 Lua 5.1 chunks. Python and Lua normalize
function dumps into a private checksum representation, removing source/debug
names and canonicalizing endianness and integer/size_t widths. This is not a
loadable Lua chunk. Instructions, constants including signed zero, function
shape and definition line bounds remain covered by integrity checks.

On Windows, `python tools/build_lua51_test_tools.py --help` describes an optional
GCC build of the pinned official Lua 5.1.5 source. Set `KARITY_LUA51_TEST_TOOLS`
to its output directory to enable external executable/compiler/DLL regressions.
That download is not part of CI; unset tools mean those checks are skipped,
not verified. Native in-repository Lua 5.1 tests use Lupa.

## Regression coverage

`test/run_ci.py` runs the shared regression manifest. Target-specific suites
cover frontends, exact private words, dump layouts, pass boundaries, source
environments, numeric edge cases, closures, errors and coroutine boundaries.
Closure/GC and generated-source regressions exercise both Lua versions and
all three backends. Unsupported combinations fail explicitly rather than
silently dropping protection.

`tools/audit_lua51_dependencies.py` checks generated output for compatibility
dependencies and executes each build. Its generated report is saved under
ignored `local/` by default; `--output` selects another report path.
