# Anti-debug wrapper

`anti_debug` is a pre-pass that wraps the source in a `debug.gethook()` check.
With no installed hook the original source executes. If a hook is present, the
wrapper runs an intentional infinite junk loop instead. It does not throw a
normal diagnostic error or time out by itself.

If `debug` is not a table, or `debug.gethook` is missing, the wrapper permits the
source to run. This avoids treating every restricted environment as a debugger,
but also means this check can be bypassed. A host controlling the debug library
can change its result. This is a hook check, not comprehensive debugger detection.

## Configuration and compatibility

Add `anti_debug` to `passes`; as a pre-pass its wrapper is available to later
source transforms. It is also accepted in output contexts, where it wraps that
context's generated code. Profilers, coverage tools and legitimate instrumentation
that install Lua hooks can trigger the loop. Disable the pass for those debugging
sessions and always use an external process timeout when testing hook behavior.
The junk body uses Lua 5.3 operators; Lua 5.1 is not a supported target here.

This pass is separate from `vm_options.runtime_trace`: disabling runtime trace
removes diagnostic instrumentation during generation, while this wrapper changes
what runs when a hook is detected. Release-check requires source anti-debug
protection but does not certify resistance to a controlled runtime.

Implementation: [anti_debug.py](../../obfuscator/passes/anti_debug.py).
The shared [verification suite](../../test/run_ci.py) exercises configured source
and packed builds; use controlled, timeout-bounded application tests for hooks.
