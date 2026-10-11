# VM output finalization optimization

Baseline: `5118d82`, branch `future`. Measurements use Windows 11, Python
3.15.0, native Lua 5.3, `test/scripts/01_helloWorld.lua` (20 bytes), seed 9300,
and `PYTHONHASHSEED=0`. Builds run serially with diagnostics disabled. The
[raw report](vm-output-finalization.json) contains wall time, output size,
runtime and child peak working set (sampled every 50 ms, excluding grandchildren).
Baseline rows were retained from the first isolated comparison; every final
optimized row was rerun after the last implementation change.

## Ordinary build results

| Backend/preset | Build seconds | Peak working set MiB | Output bytes |
|---|---:|---:|---:|
| MOV high | 10.365 → 7.929 | 242.6 → 241.7 | 2,287,884 → 2,287,884 |
| MOV max | 11.658 → 10.605 | 250.9 → 234.8 | 1,384,677 → 1,384,843 |
| Karity high | 90.679 → 55.158 | 2532.8 → 1423.4 | 12,382,076 → 12,382,076 |
| Karity max | 122.568 → 76.580 | 3014.1 → 1686.2 | 8,217,588 → 8,217,790 |

Karity high/max build wall time falls about 39%/38%; peak working set falls
about 44% in both. MOV high/max fall about 24%/9%. All eight outputs execute
with original stdout. Each runtime sample is a single execution, so runtime
variation is not presented as an execution-speed optimization. Existing packer
cryptographic randomness is preserved; small max-output size differences are
expected. This single fixture/seed measures a large generated-runtime workload,
not an across-project speed guarantee.

## Implementation and protection coverage

- Final Rename and a single StripInfo share one final syntax tree, one binding
  graph and one replacement assembly. Analysis still runs after literal and
  alias generators; it does not assume all generated variables were registered.
- Without StringObf/localized-alias consumers, ordinary naming is deferred to
  the final analysis instead of assigning names both before and after literal
  expansion. Readable-name hints retain their existing two assignments.
- A Tree-sitter query finds all identifiers. Python scope traversal skips only
  subtrees containing none. Requested literal captures remain source ordered;
  `sparse=False` keeps the full walk for auditing. Scope statistics describe
  visited analysis scopes; pruning empty scopes does not remove program scopes.
- StripInfo decodes only candidate field keys and their constant concatenation
  dependencies, including failed-result caching. Private-table alias/escape and
  rebinding checks remain intact. Labels/comments use shared C query captures.
- `TSContext.plain_text()` reads spelling without copying provenance records
  for name/key analysis. Code emission still uses the original annotated source
  and metadata-preserving replacements. Original syntax trees are released
  before final parsing.
- Explicit repeated StripInfo layers retain sequential processing. Structural
  and custom output passes still run; StringObf helpers and LocalizeGlobals
  aliases receive final naming. No source pass, handler protection, CFF budget,
  Number/Meme strategy, target validation or compiler limit was disabled.

The unrelated correctness issue exposed by the tests is fixed: grammar comment
nodes inside quoted strings are literal data. StripInfo and dispatcher-annotation
cleanup preserve those strings, while still removing actual annotation comments.
Minify's existing token rules are retained.

## Validation

The shared CI manifest includes `run_vm_finalize_regression.py`: 102 exact-output
finalizer comparisons, 34 seeded comparisons with the former two-name-assignment
pipeline, full-walk/sparse binding and literal-capture equality, a dense 6,000-value
tree, numeric provenance retention, late helpers/aliases, repeated StripInfo and
marker-looking string literals. Direct finalization executes on Lua 5.1/5.3;
full measured high/max builds use Lua 5.3. Existing pass target restrictions
remain unchanged. Standard Rename/StripInfo/Minify, typing and VM-output-emitter
regressions are retained, including their existing runtime limits.

## Reproduction and remaining work

Archive `5118d82` to `temp-vm-finalize-baseline`, then run with the same Python
dependencies and otherwise idle machine:

```sh
python tools/compare_literal_mosaic.py --before temp-vm-finalize-baseline --unprofiled --runtime-repeats 1 --work-dir temp-vm-finalize-benchmark --output measured.json
python test/run_vm_finalize_regression.py
python test/run_ci.py
```

Both source and build random/hash seeds must be fixed for detailed profiling.
VM lowering, full Number/Meme expression generation, final parsing and Minify
remain real costs. A broader symbol IR or another string-generation abstraction
is deferred: shared final analysis already protects helpers without relying on
incomplete generation metadata. Further changes should use multiple real inputs
and seeds and demonstrate unchanged binding/literal/protection coverage.
