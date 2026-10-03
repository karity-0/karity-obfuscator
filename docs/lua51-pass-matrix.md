# Lua 5.1 pass boundary matrix

The source pass runs before Lua 5.1 compilation. A VM output pass runs on the
generated VM function before its Lua 5.1 dump and integrity hash. The output
stage is **not** a general Lua 5.3-to-5.1 translator; passes that emit 5.3
operators must be rejected before building the VM.

| Pass | Source stage | VM output stage | Reason for a restriction |
|---|---|---|---|
| `strip_info`, `remove_comment`, `string_encode`, `table_obf`, `rename_obf`, `minify` | supported | supported | Lua 5.1-compatible transformations |
| `localize_globals` | unsupported | supported | Only the VM function receives a lexical `_ENV`; its output aliases use one table to stay within Lua 5.1's 200-local limit. |
| `function_obf` | supported | supported | Common-syntax bounded arithmetic predicates, affine state encoding and relative additive transitions; no bit library or int64 shim. |
| `string_obf`, `boolean_obf`, `number_obf`, `anti_decompile` | unsupported | unsupported | Emit bitwise and/or integer-only Lua 5.3 expressions. |
| `meme_strings` | unsupported | unsupported | Its 64-bit integer arithmetic can change binary64 values; it also corrupts private VM fields when applied to output. |
| `anti_debug` | unsupported | invalid stage | Emits a bitwise junk loop and wraps the whole script, which destroys the VM dump function anchor. |
| `vm` | supported with runtime-specific compatibility | invalid stage | VM is a stage, not its own output transformation. |
| `pack` | unsupported | invalid stage | The packer needs 5.3 operations and is a stage, not a VM output transformation. |

`python test/run_lua51_pass_matrix_regression.py` executes seven supported source
pass builds through Classic and 30 VM output builds across Classic, Karity,
and MOV (including function protection and combined rename/localize/minify). These are executable
smoke cases, not a claim that every Lua 5.1 semantic corner case is covered.
`python test/run_target_capability_regression.py` checks explicit rejection
through configuration and the direct `VMPass` API. Other Lua 5.1 runtime,
frontend, word, dump, and host regressions provide separate semantic coverage.

`python test/run_function_lua51_regression.py` compares original and protected
execution on native Lua 5.1 and 5.3 across all three boundary modes, multiple
seeds, nested closures/recursion, loops, multiple returns and arbitrary parameters.
The original input must itself use the selected target's syntax. This is not a
Lua 5.3-to-5.1 source translator or verified Luau support. `function_obf` alone
works with portable compatibility; `vm` still requires runtime-specific compatibility.

When selecting Lua 5.1 from a configuration whose default VM output passes
contain a restricted pass, choose a supported output list explicitly (for
example `--vm-output-passes rename_obf,localize_globals,minify`). The build
reports the incompatible pass instead of silently dropping it.
