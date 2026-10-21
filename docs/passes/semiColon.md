# SemiColon

An optional visual pass that appends semicolons to complete Lua statements.
Lua 5.3 follows the repeating **1 → 3 → 2 → 1** pattern in source order:

```lua
local a=1;local b=2;;;a=a+b;;print(a);
```

Lua 5.1 accepts only one optional statement terminator, so it uses single
semicolons. Existing terminators, strings, comments, table fields, and terminal
`return`/`break` statements stay intact. The pass adds no lines, expressions,
helper functions, or runtime checks. `NO_OBF` regions remain untouched.

Select **SemiColon** in the GUI, or add `"semicolon"` to `passes`,
`vm_output_passes`, or `packer_output_passes`. A source-list entry after VM or
Packer is routed into that stage before its integrity hash is finalized.
Existing presets do not enable it automatically. This changes appearance,
not protection strength; later beautifiers may remove the decoration.
