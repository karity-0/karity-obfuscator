# Verification

Local checks and Actions use `test/run_ci.py` and the same complete manifest.
Install `requirements-dev.txt` first. The existing full command still runs every
regression, the Lua 5.1 dependency audit, and the 18 Lua scripts.

```sh
# Fast single-pass and infrastructure checks
python test/run_ci.py --level quick

# Related checks, including staged/unstaged local source
python test/run_ci.py --changed HEAD --list --explain
python test/run_ci.py --changed origin/dev

# Explicit feature group, including cross-feature contracts
python test/run_ci.py --feature strings

# All checks, or one balanced partition
python test/run_ci.py
python test/run_ci.py --level full --shard 1/4
```

`--list` previews commands; `--explain` shows selection reasons.
`--keep-going` runs remaining checks after a failure and returns a failing exit
code. Reports go under ignored `local/verification/`. `--help` lists features.

## Coverage and selection

`test/verification.py` declares feature-to-suite relationships. A String Obf
change selects string, Mosaic, function/CFF cost, VM literal emitter, late
line/environment, packer, selection, preset and end-to-end checks. Explicit
ownership covers generated Lua dependencies that import discovery would miss.

Quick checks always run. Shared parser/pipeline/configuration changes, unknown
paths, and missing Git comparison history select full coverage. Changed test
files select their own suites and related features. Documentation-only changes
select quick checks. Renames inspect both old and new paths.

Every regression script, registered pass and built-in VM backend must declare
verification ownership; omissions fail early. Generic source passes also need
a PassContract. VM, packer and security passes retain their dedicated suites.
Selection is conservative, not a proof of every possible interaction. Full
checks remain required for main-target changes and manual Actions runs.

## Common cases and pass orders

`test/pass_contracts.py` shares byte/UTF-8, numeric domain/type, table effect
order, closure, error, short-circuit, vararg and nil-arity cases. Each supported
single pass is compared to native Lua; unsupported targets must be rejected.

Combination checks cover every ordered pair in the selected feature scope and
explicit coupled triples, including Flow → Function Obf → Number Obf. Each
order gets a small deterministic boundary case, rather than multiplying every
order by every input/seed/backend. Existing deep matrices are retained.
The same observable case crosses real VM output/integrity on every registered
backend and both Lua versions, plus Lua 5.3 packer output.

The harness reuses `tools/explore_vm_semantics.py` for isolated execution,
timeouts and seeded expression generation. Arbitrary bytes are observed as
ASCII byte values; return counts/nils and numeric types are explicit.

```sh
python test/run_pass_contract_regression.py --quick
python test/run_pass_contract_regression.py --feature strings
python test/run_pass_contract_regression.py --generated 2
python test/run_pass_contract_regression.py --replay local/verification/failures/CASE.json
```

Failures save input, target, pass order, configuration, seed and differences;
generated Lua is saved when available. Replay uses the recorded policy. Reduce
reproduced failures to small fixed regressions in their owning suites.

When adding a pass, update PASS_FEATURES and either PASSES in the shared
contracts or its dedicated suite mapping. Add boundary cases and new coupled
orders. When adding a backend, declare BACKEND_FEATURES; the common output
contract automatically discovers registered backends.

## Actions

Dev/future pushes and PRs select checks from the Git change range. Main pushes,
PRs targeting main, and manual workflow_dispatch runs use full coverage.
The three existing OS/Python environments remain.

Checks are balanced across at most four jobs per environment using approximate
historical suite costs. Each job runs shorter checks before large VM builds
and reports all failures. Small quick-only plans use one job per environment.
Cost estimates affect placement only; assertions and existing seeds remain.

Pip downloads/builds are cached, superseded runs of the same event/ref are
cancelled, and timing/replay artifacts are retained for seven days. Actual wall
time depends on runner speed, queues and dependency setup. Estimates describe
Linux test work, not a completion guarantee.
