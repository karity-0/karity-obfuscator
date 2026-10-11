# Scalar finalization and token Minify

Baseline: `4cb0a92`, branch `future`. Windows 11, CPython 3.15.0, native Lua
5.3, `test/scripts/01_helloWorld.lua`, seed 9300, `PYTHONHASHSEED=0`.
[Raw measurements and code hashes](scalar-finalization.json).

## Ordinary builds

| Backend/preset | Build seconds | Peak working set MiB | Output bytes |
|---|---:|---:|---:|
| mov high | 23.626 → 17.381 | 243.2 → 241.0 | 2,287,884 → 2,285,910 |
| mov max | 26.848 → 28.870 | 234.0 → 231.4 | 1,384,898 → 1,385,891 |
| karity high | 150.027 → 104.272 | 1420.9 → 993.1 | 12,382,076 → 12,194,847 |
| karity max | 194.580 → 144.856 | 1685.2 → 1169.3 | 8,218,414 → 8,195,835 |

Current host load was elevated: an overall CPU snapshot was 43%, and the same
baseline is substantially slower than in the earlier finalization report.
Do not mix these wall times with that report's idle-machine measurements.
Retained builds run serially without other local builds. Karity high was
repeated to replace an exploratory pair briefly overlapped by a verification
run. All eight retained outputs match original stdout. Runtime is sampled once.

In this paired sample Karity high/max build times fall about 30.5%/25.6%; peak
working sets fall about 30.1%/30.6%. MOV high improves, but MOV max's single
sample is slower; no universal speedup is claimed. More idle-machine inputs,
seeds and repetitions are needed for stable absolute targets. Twenty seconds
has not been achieved or guaranteed. Existing cryptographic packer randomness
remains enabled, so packed sizes need not be identical.

## Changes and preserved coverage

Scalar emitters retain each original literal's character interval through every
configured stage. After checking a restricted identifier-free token grammar,
Rename and StripInfo plan against the retained original syntax context. The
literal and identifier edits are assembled together in original coordinates.
This removes the expanded-source parse and a second whole-source assembly.

Numeric table keys retain projected syntax: expanding a numeric key to an
expression preserves StripInfo's existing conservative decision. Private string
key edits consume enclosed literal regions without overlapping replacements.
Origin/protected spans survive assembly. Source scopes, alias escape checks,
frequency ordering and naming seeds are retained.

Unknown generated syntax takes full final analysis on the already-generated
output; random generation is not retried. StringObf helpers, localized aliases,
readable hints, explicit repeated StripInfo and custom post-passes keep their
existing analysis paths. This is interval metadata plus lexical certification,
not a variable-name convention or a blanket exclusion of generated code.

Minify scans literal/comment/code/gap tokens once and preserves necessary Lua
lexical boundaries, quoted bytes and native hook newlines. It removes repeated
whole-string substitutions and placeholder restoration. Inline long comments
between identifiers now retain a token gap. Loader and VM wrappers recognize
the return keyword independently of a trailing space. Packer constant-cache
replacements also keep token gaps when replacing delimited expressions.

Number/Meme strategies, source StringObf → CFF, VM handler/state/dispatch
protection, `vm_count`, presets, budgets and compiler checks are unchanged.
Smaller output here reflects whitespace compaction, not removed protection.

## Verification

- 114 direct exact-output finalizer cases and 38 seeded scalar-pipeline cases;
  original versus generated Lua 5.1/5.3 returned values, scopes and aliases.
- Numeric origin/protected-span retention and an injected helper/reference
  strategy that must fall back and rename the new binding.
- 14 Minify native cases, idempotence and 224 direct Lua 5.1/5.3 gap cases.
- Compact return wrappers and cached expressions at keyword boundaries, with
  native loader dumps and Lua 5.1/5.3 execution including trailing nil.
- Existing Rename/StripInfo, typing, line-state and Literal Mosaic regressions.
  External Lua 5.1 toolchain testing remains optional and was skipped locally
  because KARITY_LUA51_TEST_TOOLS is unset.
- Every measured MOV/Karity high/max output executes as the original.

The full CI manifest retains the VM-output-emitter regression and its original
runtime limits. Further candidates are VM state transfer/merge data structures
and number-format helper calculations; these are not changed in this patch.
