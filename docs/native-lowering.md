# Native execution domain

`get_domain_backend("native", "ce_native")` selects a bounded native backend.
Existing `vm_options.backend` choices still select Classic, Karity or MOV.
Both domains consume ProtectedIR; host/version-specific IR copies are not used.

The initial native subset is a non-vararg leaf function with one reachable
basic block, at most four register slots and four parameters, and one scalar
return. It supports integer constants, MOVE, ADD, SUB, MUL, NEGATE, BIT_AND,
BIT_OR, BIT_XOR and BIT_NOT. Unsupported functions receive explicit rejection
reasons in the native IR dump. Branches, calls, tables, floating-point constants,
division, multiple results and larger frames remain on the Lua path.

```python
from obfuscator.vm.backends import get_domain_backend
from obfuscator.vm.backends.native import NativeBackendContext
from obfuscator.vm.targets.profile import TargetProfile

context = NativeBackendContext(TargetProfile(
    environment="cheatengine", runtime_abi="windows-x64",
    compatibility="runtime_specific",
))
backend = get_domain_backend("native", "ce_native")
native_ir = backend.optimize(backend.lower(protected_ir, context), context)
factory_source = backend.emit(native_ir, context)
```

Evaluate the emitted factory in CE, then supply the original Lua functions
indexed by their common IR function IDs:

```lua
local module = factory({["f0.0"] = original_function})
local result = module.functions["f0.0"](4, 2)
module.close()
```

The wrapper uses native code only when every declared parameter is a Lua
integer. Other inputs call the supplied original function, retaining coercion,
metamethod and return behavior. Native arithmetic wraps at 64 bits. Allocation
is lazy; `close()` releases this module's allocations, prevents further calls,
and can be retried after a reported cleanup failure. Callers must retain the
module and close it when its functions are no longer needed.

Code uses volatile registers and the caller's 32-byte home area. It never
changes RSP, calls another native function or dereferences a source pointer.
This leaf subset follows the [Windows x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).
The CE wrapper uses local assembly/execution APIs with explicit target-self
selection, described in [CE's Lua reference](https://github.com/cheat-engine/cheat-engine/blob/master/Cheat%20Engine/bin/celua.txt).

This is an explicit API proof of concept. Automatic mixed VM/native function
routing, allocation ownership for escaping VM closures, 32-bit hosts, Lua 5.1
numeric semantics and general native regions are not implemented. The emitted
arithmetic runs in regression tests on Windows x64, and its CE wrapper is
tested with simulated CE APIs. Actual CE execution is not verified here.
