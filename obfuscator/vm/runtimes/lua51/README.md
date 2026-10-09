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
5.1 implementations; unresolved generation tokens and typed private-word
expressions are lowered at build time. The final runtime does not embed
`int64.lua` or `lua51_shim.lua`, or call a whole-source arithmetic translator.
Those legacy modules remain as independent test oracles, not runtime inputs.

Validate changes with `python test/run_ci.py`. The Lua 5.1 runtime and word
regressions cover all three backends; the IR regression verifies target
selection, and the host-materialization regression checks both Lua versions.
