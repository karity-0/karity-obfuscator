# Host image constants

Set `target.environment` to `cheatengine`, `target.compatibility` to
`binary_specific`, and provide `target.host_images` as executable/DLL paths.
The VM materialization stage resolves those files once per build. CLI users can
repeat `--host-image PATH`; the GUI accepts one path per line.

The common IR and backend IR retain their ordinary constants. A separate
materialization plan selects matching byte strings and copies the serialized
representation with empty strings in those positions. The runtime restores
the values before executing the VM. Constants not found in suitable image
storage retain their existing representation; selecting images does not
guarantee that every string will be moved out of the output.

`CEBinaryResolver` records module name, SHA-256, pointer width, machine, PE
timestamp/image version, section data and relocation ranges. References use
RVAs, never file offsets or fixed load addresses. Only readable initialized data
is eligible. Writable, executable, discardable, relocated and import-table
storage is excluded conservatively. Supported images are x86 PE32 and x64
PE32+; unsupported relocation types fail explicitly. PE image version fields
are metadata and are not interpreted as the product's release version.
The layout follows [Microsoft's PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

The emitted reader enumerates CE's own modules, checks the selected module's
width and file digest, and reads at its current base plus the resolved RVA.
It checks the recovered bytes before using them. It uses `readBytesLocal`, so
it does not read from the process currently attached to CE. These interfaces
are documented in [CE's Lua API reference](https://github.com/cheat-engine/cheat-engine/blob/master/Cheat%20Engine/bin/celua.txt).

CE's native MD5 APIs provide file/content mismatch detection at runtime.
They are not a collision-resistant guarantee against a hostile host. Build
metadata retains SHA-256 for artifact identity. Replacing the module file,
patching its mapped contents, unavailable APIs or unloading a referenced module
can invalidate the output. The reader caches module bases for one execution;
module unloading/reloading during that execution is unsupported.

This first provider handles byte strings. Typed numeric constants, including
negative zero, retain their current serialization. Classic, Karity and MOV use
the same provider and reader. Native Lua 5.1/5.3 tests exercise all six backend
combinations with simulated CE APIs and synthetic PE images. Actual CE-host
execution has not been verified in this workspace. Native code lowering is a
separate feature and is not enabled by selecting host images.
