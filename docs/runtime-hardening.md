# Runtime hardening

## Encoded integer operations and helper integrity

Karity on Lua 5.3 enables `encoded_bitwise` and `distributed_integrity` by
default. Either can be explicitly disabled with `--vm-option NAME=false`.
Lua 5.1 and other backends do not implicitly enable these features.

`encoded_bitwise` is the compatibility option name for automatic integer
representation selection. It covers AND/OR/XOR/NOT, signed and oversized shifts,
EQ/LT/LE, floor division and modulo. ADD/SUB/MUL/NEGATE retain the existing cheap
modular affine route; Boolean packets can continue through shared arithmetic.
Single operations, joins and nonadjacent consumers are supported. A conversion
cache is guarded by the register epoch and map generation. It holds only integer
shares and does not retain guest objects.

Boolean circuits implement addition, selection, comparison, multiplication and
restoring division. Negative division uses Lua floor correction, minimum integer
divided by -1 wraps, and zero divisors raise the appropriate Lua error. Shift
counts remain shared throughout the six-stage selection and range check,
including negative and minimum-integer counts. Affine/Boolean conversions use
masked circuits; combining shares at conversion produces an affine encoded word,
not the original integer. These circuits have nontrivial execution cost.

Whole-program semantic type analysis proves whether every physical use of a
handler has integer operands. Proven aliases omit the general guest operation
route; unused integer aliases and composite bodies are removed too. Missing or
mixed facts retain Lua float, coercion and metamethod behavior. Analysis does not
infer function parameter types from observed calls. Backend diagnostics report
proof coverage, retained/elided decisions and reasons; these are static
opportunities, not counts of executed paths.

Proved split/fused/deferred handlers and synthesized regions share the integer
paths. Split/fused boundaries can normalize back to affine storage without
materializing an original integer. Active arithmetic graphs execute through
integer-specialized graph entry points and retain their occurrence, scratch,
state and ledger effects; graph-required evaluation is an explicit native-value
boundary. Protected captured integer cells use their existing cross-frame affine
format directly; native cells and cells with external accessors use their coherent
native API. Native calls, returns and table operations also use ordinary values
where their existing contracts require them. Guest DIV
and POW remain native floating operations, including with integer inputs. This
is not a claim that all Lua operations or host boundaries avoid native values.

`distributed_integrity` relocates two or three eligible pure generated helpers
into a private bank and rewrites their actual lexical execution references to
that bank. Independent checkers cover those helpers and neighboring checkers.
They compare both original function identity and the stripped function dump.
Expected fingerprints are extracted from final child prototype bytes, stored
outside hashed code and bound into the existing VM key. The source/prototype
correspondence is validated; no guest code is executed to obtain fingerprints.
Native 32-bit and 64-bit size_t dump layouts are supported. Initial checks cover
all selected regions; sparse loop/executor checkpoints use periods 257/509/1021.
These counters are internal execution checkpoints, not wall-clock guarantees.
Heavy output transformations that eliminate all eligible pure helpers fail
explicitly rather than claiming coverage. The option adds code and runtime cost.

Explicitly enabling either control is rejected for Karity Lua 5.1 and reported
unsupported on other backends. Their defaults are target-specific; preset budgets
are unchanged. Existing environment, source
line, self-dump and guest lifetime contracts remain active. Local fingerprints
and identity snapshots do not authenticate a fully controlled host or supply an
externally held secret.

`test/run_encoded_operations_regression.py` checks encoded arithmetic and actual
native execution; `test/run_helper_integrity_regression.py` checks each helper/
checker replacement, same-bytecode replacement, manifests, module environments
and packed execution.

Every generated VM checks its essential native dependencies, including string
assembly functions, rather than randomly omitting them. The core loader captures
validated call targets. Entry from the host, native-call boundaries and sparse
dispatch ticks recheck hook state and captured dependency identities. A detected
mismatch invalidates that runtime instance even if user code catches the error.
These checks reject active debug hooks and unexpected changes to protected
standard-library functions while the runtime is active. Assignments performed by
the VM itself update the expected public binding; the runtime continues to use
its captured implementation. This preserves deliberate source-level overrides.
The capture table is initialized before early runtime helpers. Guard entries
validate that table and the protected-value helper identities using lexical
primitives; replacing a mutable dispatch slot does not replace the entry guard.

Bare classifies a limited set of closed ordinary calls using all reaching
definitions in semantic IR. Only generated CLOSURE producers and their MOVE
chains qualify; parameters, native/global/table lookups, captured callees,
unknown joins, tailcalls, open ranges and spill/captured result stores stay conservative.
Qualified caller-side pre/post checks use the existing periodic poll instead of
forcing a full scan. The callee still checks fully on entry and before return,
including entry from an unprotected host or native callback. Unknown/native
ordinary CALLs and the post-yield resume path retain immediate full checks. Poll sites and
the 127-event period remain; this is not a wall-clock detection guarantee.
Guard IR metadata records the event and proof reason. Native/bootstrap and
data-recovery checks remain active. This policy does not authenticate arbitrary
host edits to private Lua stack/upvalue state or promise detection of every
mutation restored between observations.

Karity, Classic, MOV and Bare run a shared native bootstrap protocol on Lua 5.1
and 5.3. It compares `debug.getinfo` function, stack, option and explicit-thread
queries using native witnesses. A private coroutine exercises line hooks,
hook removal followed by quiet execution, and count hooks. Installation settings
alone are insufficient: the callback must actually execute on that private
coroutine. The protocol checks suspended-thread metadata too. It never installs
or removes a hook on the caller's coroutine. Private hooks are cleared on normal
completion and on errors when the supplied native APIs permit cleanup.

The private protocol varies per build: bounded worker arithmetic and loop forms,
cumulative yield/return values, line/count ordering, count interval, internal
mode identifiers and metadata query order. Expected results are derived during
generation with exact Lua 5.1/5.3 arithmetic. API event/type/status names retain
their specified meanings. Stack lookup stops at the witness or end of stack,
with a 64-query bound. Known Lua 5.3 targets require nparams/isvararg fields;
Lua 5.1 retains its optional-field contract. Variation is not authentication or
a secret challenge against a host that controls all observations.

These active probes run once per runtime initialization. They require standard
coroutine and thread-debug APIs; missing or inconsistent implementations fail
explicitly. The new bootstrap-only API references are checked every 127 guard
events, using the existing counter and failure latch. Existing full native,
environment and current-thread hook checks retain their earlier scheduling.
Authorized VM writes update either dependency bank. A table-owner index avoids
scanning authorization records for unrelated writes; it does not cache successful
integrity validation. Coroutine-library metatables join the existing environment
watching policy.

This protocol does not enumerate inactive guest coroutines or authenticate a
fully controlled host that forges all observations consistently. New reference
changes can remain undetected until the periodic checkpoint, and changes restored
between observations may be missed. A dishonest hook setter can also refuse
private-thread cleanup; the caller's hook is still never cleared to compensate.
The bootstrap comparisons currently remain native and are bound into the existing
dump/line identity. They are not additional protected Semantic IR decisions or
per-region VM-program authentication. See `test/run_runtime_probes_regression.py`
for protocol, cleanup, periodic-delay, authorization and generated-backend tests.

The compiler-owned native capture table uses unique randomized numeric slots and
shuffled declaration order. Its static references are rewritten in the same
binding-aware pass; generic integrity iteration records the resulting numeric
keys. This runs before output transformations and runtime identity binding and
does not depend on StripInfo's conservative escape analysis. Initializers still
obtain the actual native API references from the selected runtime environment.
The protected-value function table and its private API bank also use randomized
numeric slots. The compiler rewrites their definitions, nested accesses and the
explicit API-bank integrity record by lexical binding; unrelated guest tables
and native library field names retain their original meaning. These private
keys are numbered even when StripInfo is disabled.
The capture bank also includes numeric type/integer helpers, binary string
packing, optional tamper-pool functions and clock/locale APIs. Runtime calls use
the captured numeric slots; the initial native lookup expressions remain in the
bank initializer. Lua 5.1 omits Lua 5.3-only entries. Reader metadata/word/header
methods and upvalue accessor/reference/environment fields receive generated
names without changing diagnostic string literals.
Lua 5.1's escaped execution-context keys, including its dump function and
source-line state, are also explicitly renamed by the generator rather than
depending on generic StripInfo escape analysis.

String constants have an inner per-entry encrypted envelope before outer blob
encryption. Its content check and keystream are rebound to the final runtime dump
and source-line state. The decrypted outer blob therefore still contains encoded
string payloads; parsing it does not briefly produce all original string literals.
The envelope and runtime content fingerprints are obfuscation mechanisms, not a
standard cryptographic AEAD or an externally provisioned secret-key boundary.

Karity keeps strings as a distinct protected value representation: encrypted byte
storage with validated contents and cell bindings. It no longer treats strings as
ordinary plaintext objects in reference cells. Internal equality, truth, length
and all-string concatenation operate on that representation. Equality checks all
bytes at a matching length rather than returning at the first differing byte;
this is not a constant-time guarantee from the Lua host. Recognized native
`string.char`, `string.sub`, `string.len` and eligible `table.concat` calls can
produce or consume protected values directly. Metamethod-bearing tables, unusual
arguments and operations requiring Lua's own coercion retain native fallbacks.
Other arithmetic, locale-sensitive comparison and arbitrary native API calls may
materialize strings as required to preserve Lua behavior. Native table keys and
values, returned values and external callbacks are observable host boundaries.

Classic retains its native-value execution model and MOV its own encoded-value
model. Both use the shared per-constant envelope and host guards. They do not
inherit Karity's new register/upvalue string representation.

Normal VM assignments establish a new string-cell binding. A read verifies both
the binding and encoded content, so replacing a reference or editing ciphertext
without updating the legitimate state is detected. Native tables, functions,
userdata and threads remain actual Lua objects; their identity, mutation and GC
semantics are not replaced with hashes of their contents.

Source-location state uses three to five native faults on private nil operands
(indexing, calling, length, arithmetic or concatenation), without explicit
`error()` calls or diagnostic marker strings. Fault definitions, captured readers
and observations are placed at separate outer-function initialization boundaries.
Every build uses pattern, direct byte/digit and plain substring readers; some
faults contribute through two different readers. Each observation updates key
state independently, so a conflicting reader is not replaced by a healthy one.
The byte reader needs neither patterns nor `tonumber`. All observations complete
before the runtime entry is returned and the encrypted blob is opened. Final
source positions, including output prefixes and minification, determine the
builder's matching state. This adds one structural parse to find legal insertion
boundaries in the finalized VM. Only new fragments undergo literal lowering;
when minification is enabled, the assembled runtime is compacted once before
recording source positions, including late environment/observation joins.

Generated VM invariant failures omit internal diagnostics such as opcode values,
blob-format details, metadata indices and register-vault state. They still raise
an error with no diagnostic object or source-location prefix. This normalization
shares the native-capture analysis and runs before output obfuscation and runtime
identity binding. Numeric-loop/division semantics, explicit guest errors and the
separate integrity-failure path are preserved. Authored runtime templates retain
their diagnostic text for development.
The integrity guard likewise raises an error without a diagnostic object, and
compiler-owned MOV statement assertions retain their conditions while omitting
their diagnostic strings.

Invalid numeric-loop arguments use a small native numeric `for` on the rejected
value. Lua itself produces the error body; the generated runtime contains no
`for` diagnostic literals or explicit error call for these failures. Existing
argument validation order, numeric coercions and integer-limit handling remain
target-specific. Error source locations and stack frames still belong to the VM.

The final wrapper binds the VM factory directly. The unused outer branding/
random-string local has been removed from both target wrappers and the build-time
dump context. The output prefix still supplies the same function line positions
for runtime identity and source-location binding.
The VM entry now receives the blob and the VM function itself, plus an original
vararg packet only when needed. The old public random-tail argument and fixed
key prefix have been removed from both generation and execution. The blob key
uses the integrity-adjusted dump CRC in hexadecimal; the separate random nonce
still diversifies blob encryption. This removes public key inputs and markers,
not an externally held secret. The visible `KARITY/` blob-format marker remains.
Packing recognizes both current wrappers and legacy random-tail wrappers.
The outer factory is invoked without arguments, retaining the two-stage
`factory()(blob, factory)` shape. Its seven formerly fixed numeric arguments
and unused parameter locals have been removed; packing accepts an empty
factory-argument list as well as older nonempty lists.

`vm_options.environment_policy` defaults to `compatible`. A late bootstrap keeps
the original guest environment separate from the environment used by runtime
helpers. When a forwarding proxy exposes a `_G` table with the required own API
fields, helpers use that table; guest global reads and writes retain the original
environment. Bootstrap capabilities still require a small number of initial
lookups. A recovered `_G` is not proof of a pristine host, and a proxy without a
suitable backing table retains its normal lookup behavior.

The bootstrap watches the actual metatables of both environments and the native
string/table/math/debug tables. Later metatable replacement or changes to their
`__index`/`__newindex` handlers invalidate the instance. VM-mediated assignments
and `setmetatable` calls validate the previous state and refresh the affected
snapshot after a successful write, preserving intentional source behavior.
`strict` additionally requires the initial environment to own essential APIs and
rejects initial function-valued lookup/write handlers on watched tables. It can
therefore reject legitimate sandbox environments and is an explicit opt-in.
Bootstrap locals are renamed and its guest/native/check slots use randomized
numeric keys. These checks do not authenticate capabilities supplied by a host
that was already instrumented before initialization.
The selected policy is specialized during generation: compatible output omits
strict-only tests, and strict output omits proxy recovery. Capability capture
and initial snapshots remain at entry. Guard and authorized-refresh definitions
occupy separate outer initialization boundaries, both before the first statement
that defines or uses a guard consumer. Their shared private state also uses
random numeric keys, and scoped definitions add no persistent factory locals.

The attack model remains an analyst who owns the Lua host. Checks whose answers
come from that same host can still be falsified by a sufficiently adapted host.
In particular, this does not claim to eliminate pristine `string.dump` replay or
to hide strings handed to an external function. The regression suite tests the
specific earlier extraction, cell-editing and late-hook paths, alongside native
execution equivalence on Lua 5.1/5.3 and the blob backends.

Bare uses a separate source adapter: guard decisions and guest protection calls
compile into semantic IR. Atomic call groups emit directly, while a shared native
package performs repeated inspection and constant recovery. Unused string/write/
environment/getter/tailcall helpers are omitted, and numeric-loop conversion is
shared across guest functions. `native_capture.py` captures referenced APIs in a
randomized numeric bank, including the APIs needed by late readers/output helpers.
Shared repeated host checks live in `host_guards.py`; the dump CRC helper is
shared with blob emission. The common `line_state.py` disperses three to five
native fault closures, reader definitions and observations with random slots.
Their final source lines and the dump CRC key a compact external constant pool,
avoiding self-hash circularity. Per-build tags, a printable alphabet and masked
record offsets replace the old escaped-string record lists. Guest constants are
deduplicated across functions; a random sentinel always checks the identity path.
Native inspection/recovery/reader/dump/CRC and call-boundary primitives remain
native; the guard captures its original inspector/failure functions and makes
the fail/continue decision in IR. Entry/call/return boundaries retain guest writes,
setmetatable, coroutine, tailcall and dead-argument collection semantics.
This is a substantial fixed output/startup cost for small inputs. It requires
debug/dump capabilities and a compatible target dump ABI. Packing keeps the
finalized function unchanged and preserves its source lines and guest varargs.
Run `python test/run_source_protection_regression.py` for Bare-specific code,
line, payload, hook, environment, guest mutation, tailcall and packing checks.

Run `python test/run_runtime_security_regression.py` for focused checks; it is
also part of `python test/run_ci.py`.
