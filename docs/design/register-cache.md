# Register caches across resumed frames

An open-upvalue getter captures `rget` from the invocation which opened its cell.
When that owner frame resumes, register banks, epochs, mapping state and cells
remain shared, but its new invocation gets a separate native-read cache. Clearing
the resumed cache or a sibling closure's cache cannot clear the older getter's
cache. Previously a function could remain cached after the owner stored a table,
causing a stale type or incorrect value. Both Lua 5.1 and 5.3 reproduced this.

Both Karity templates now store `{value, epoch, generation, epoch_bank_address}`.
`rget` first completes any pending producer, then checks mapping generation and
the shared register epoch. A generation match makes the cached bank address valid;
an epoch match makes its decoded value valid. A miss computes current bank
addresses and decodes again. The generation check short-circuits before using an
old bank address. Valid hits avoid computing all four bank addresses. Unset
registers, explicit nil and false remain distinguishable through wrapper tables.

Getter variants copy the entire `RGET` region before specializing decoding, so
they inherit this validation. Classic and MOV use separate executors; their
closure behavior is regression tested without changing those executors. Existing
graph, representation rotation, pending producers and integrity binding remain
enabled. Existing generated files need regeneration: this is a generator fix,
not an integrity-breaking edit to emitted code.

`python test/run_register_cache_regression.py --full` covers both targets, all
backends, four Karity dispatcher/helper configurations, overwritten owner slots,
sibling writes, nil/false and protected state. Isolated checks of the actual
template guard cover repeated valid hits, unchanged-epoch remapping and pending
completion. The shared CI manifest includes the full regression.

[Performance comparison](../performance/register-cache.md) measures the old,
full-position validating, cached-address validating and disabled caches in real
VM builds. Correct workloads are used for old-cache timings; a broken result is
never treated as a performance baseline. The measurements include initialization
and loading, so they do not measure isolated getter-call nanoseconds.

To regenerate a local Strong protocol fixture from its actual source:

```powershell
python tools/verify_register_cache_strong.py --source PATH --key CANDIDATE
```

The default profile is `builtin:strong`; explicit `--config`/`--profile` preserve
the original build settings when supplied. CHECK, MIX, MAP and a combined session
are compared against native execution of the source. Input and output artifacts
remain local; a recovered payload cannot substitute for an unavailable original
source when claiming an exact rebuild.
