# Global localization

`localize_globals` collects recognized standard-library member accesses and bare
global functions into local aliases reached through `_ENV`. For example,
`string.char(...)` can use an alias initialized from `_ENV["string"]["char"]`.
The pass reduces repeated visible global access and lookup work; it does not
virtualize arbitrary global state.

## Ordering and environment assumptions

Run it after renaming and after transforms that introduce library references,
particularly `string_obf`, and before minification/final runtime dumping. The
shared VM output emitter can combine rename/localization plans against one syntax
context; references known to be renamed locals are excluded from localization.
Do not treat this as a general scope resolver when invoking the pass alone on
unrenamed user code whose locals shadow standard-library names.

Aliases capture values when the enclosing generated body starts. Replacing
`string.char`, `print`, a library table or `_ENV` later will not necessarily affect
those captured aliases. Programs that depend on monkey-patching or dynamic
metatable-based global lookup should test that behavior or disable localization
for that context. Missing standard libraries may also fail earlier during alias
initialization instead of only when an original conditional access is reached.

For dumped VM functions, alias declarations belong inside the captured function;
placing them in an outer chunk would introduce upvalue dependencies at reload.
Localization must finish before integrity hashes are derived.

## Configuration and verification

The pass is available in all three pass lists. See [pass contexts](../configuration.md).
VM output emitter and GUI/semantic regressions exercise the integrated pipeline;
application-specific mutable-environment behavior still requires application tests.
Implementation: [localize_globals.py](../../obfuscator/passes/localize_globals.py).
