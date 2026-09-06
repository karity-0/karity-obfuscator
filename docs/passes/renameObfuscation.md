# Rename Obfuscation

`rename_obf` assigns short Lua identifiers through the shared `NameAllocator`.
Bindings stay symbolic during analysis; final spelling is chosen by reference
count, with declaration order breaking ties. Names use an ASCII base-N alphabet
(`a` through `Z`, then two-character names with digits allowed after the first
character). Frequently used bindings receive the shortest names first.

Lexical resolution handles block shadowing, declaration order, local initializers,
closures, recursive local functions, loop bindings and repeat/until visibility.
Keywords and free/global identifiers are reserved. `_ENV` and implicit method
`self` keep their Lua-defined meaning. Table fields, method names, labels,
strings and comments are not local variables and retain their spelling.
Each binding receives a unique name across the chunk, conservatively avoiding
capture across nested functions. Sibling scopes do not currently reuse names.
Private generated table fields use a separate allocator namespace.

Generated runtime templates may use internal symbols such as `_zN` while their
structure is still being transformed. They pass through the same lexical planner
at the final source emission boundary. Base pipelines finalize after generated
helpers; VM output finalizes before minification and the dump/integrity key;
packer output uses the same pipeline. Names inside serialized bytecode or data
strings are never rewritten after hashing. Enable `rename_obf` in each output
pass list whose generated locals should be compacted.

Optional configuration applies to source, VM output and packer output renaming:

```json
{
  "rename_obf_options": {"seed": 42, "readable": false}
}
```

Omit `seed` for the deterministic default alphabet. A seed shuffles identifier
characters while preserving shortest-name-first allocation; it does not guarantee
reproducibility of cryptographic randomness elsewhere in a build. Set `readable`
to `true` for descriptive names such as `_counter_0` while debugging. The Python
API also accepts `RenameObfuscationPass(seed=42, readable=True)` and the same
keyword arguments on `rename_script_ts`.

Regression: `python test/run_rename_regression.py`.
