# Anti Env

`anti_env` is an optional **source pre-pass** for standalone Lua and CE builds
that should refuse Roblox/executor-shaped environments. It deliberately rejects
real matching environments as well as imitations. It does not identify a tool
by name or prove that a host is genuine. No preset enables it automatically.

```bash
python main.py input.lua --passes anti_env,vm --vm-option backend=bare
```

The GUI lists **Anti Env** in source pre-passes. The generated checks
are ordinary input source for subsequent passes and all four VM backends.
`vm_output_passes` and `packer_output_passes` reject it: it belongs before source
compilation, rather than around an already finalized integrity-bearing runtime.
It uses common Lua 5.1/5.3 syntax without debug, native bitwise or dynamic-load
requirements. The tests use both native Lua targets and simulated environments;
they do not constitute an execution test inside Roblox Studio or an executor.

## Detection and variation

Every build keeps four independent core families:

| Family | Condition |
|---|---|
| Roblox core | `game` and `workspace` are table/userdata objects, and `typeof` is a function |
| Roblox runtime | Four typed signals among `typeof`, `Instance.new`, `Enum`, `task.spawn`, `task.wait` |
| Executor files | Four functions among `readfile`, `writefile`, `isfile`, `delfile`, `appendfile`, `listfiles` |
| Executor introspection | Three functions among `getgenv`, `getrenv`, `getgc`, `getconnections`, `hookfunction`, `hookmetamethod`, `checkcaller`, `identifyexecutor`, `getexecutorname` |

One to three additional families are selected per build: constructor namespaces
(`typeof`, `Instance.new`, `Vector3.new`, `CFrame.new`), executor debug extensions
(`getgc`, `debug.getconstants`, `debug.getprotos`), and executor namespace bridges
(`getgenv`, `identifyexecutor`, `syn.request`). All signals in a selected extra
family must match. Family order, signal order, counting expressions and native
fault forms vary. No single global is sufficient. Core families are retained
so random selection cannot remove all checks for a partial environment.

Names are checked by type without calling the discovered APIs. In particular,
there are no service requests, file operations, network calls or scheduling/
timing probes. [Roblox globals](https://create.roblox.com/docs/reference/engine/globals)
and the [task API](https://create.roblox.com/docs/reference/engine/libraries/task)
document the engine-facing names; executor names are candidate shape signals,
not a standard or a complete inventory of tools.

## Placement and limits

The prelude snapshots the current environment before the original source runs,
using `_ENV`, Lua 5.1 `getfenv`, or `_G` as available. It tries `rawget` first;
inherited fields use a protected ordinary lookup, including table- or
function-valued `__index`. Lookup errors contribute no signal. Inherited lookup
can itself be observed by a host; raw access alone cannot see proxy-only fields.
If no table environment can be recovered, detection is skipped.

An entry guard always precedes the original source. Up to three additional
guards are inserted at randomly selected source function-body entries. They
reuse the startup decision, so names intentionally created later by the guest
do not retroactively cause detection. This is a startup environment check,
not a monitor for later host changes. It adds one persistent chunk local and,
where guards are distributed, a captured reference in those functions.

On detection a private nil call, index or length operation raises a native
runtime error, without an explicit `error()` call or identifying diagnostic.
It remains catchable by an enclosing `pcall`; it does not terminate the host.
There is no arbitrary insertion between statements, across labels, or into
loops where execution counts and Lua scope could change. When `NO_OBF` spans
are present the whole pre-pass is skipped and the selection report records why.

A legitimate application exposing the same coherent API shapes can match these
rules, and an adapted host can hide or forge its environment. Enable the pass
only when rejecting those matching environments is intended.

Implementation: [anti_env.py](../../obfuscator/passes/anti_env.py).
Checks: `python test/run_anti_env_regression.py`.
