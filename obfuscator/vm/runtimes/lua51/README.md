# Lua 5.1 runtime assets

`Lua51Target.runtime_template()` selects these files before backend composition:

- `vm.lua`: loader, private state helpers and Karity executor.
- `classic_exec.lua`: Classic executor and the host handlers reused by MOV.
- `mov_exec.lua`: MOV register, storage and execution fragments.

Keep executor composition markers and the shared handler ABI compatible with
the backend builders. Semantic IR, protection planning, physical layout and
MOV microcode remain shared Python implementations. Runtime fixes that apply
to both versions must be applied to these assets and the Lua 5.3 assets.

These files are generation templates. Native `TARGET_*` regions contain Lua
5.1 implementations, but unresolved generation tokens and internal integer
expressions still need target lowering. The final output currently retains
the transitional `int64.lua` and `lua51_shim.lua` dependencies; these assets
must not be presented as a completed shim-free runtime.

Validate changes with `python test/run_ci.py`. The Lua 5.1 runtime and word
regressions cover all three backends; the IR regression verifies target
selection, and the host-materialization regression checks both Lua versions.
