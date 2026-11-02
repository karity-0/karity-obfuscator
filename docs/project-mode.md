# Project Mode

Protect a Lua directory with per-file presets/backends. CLI and GUI share the same selection plan; each file uses the existing single-file pipeline.

```json
{
  "passes": ["vm"],
  "vm_output_passes": ["minify"],
  "project": {
    "root": "src",
    "entry": "main.lua",
    "output": "dist",
    "copy_resources": true,
    "backend_selection": {
      "mode": "weighted",
      "weights": {"bare": 3, "classic": 1}
    },
    "module_overrides": {"lib/math.lua": {"backend": "bare"}}
  }
}
```

```sh
python main.py --project project.karity.json --dry-run
python main.py --project project.karity.json --project-report report.json
```

`root` and `output` are relative to the configuration file. `entry` is optional: omit it or leave it empty for a module-only folder; it is never executed during builds. `include` defaults to `['**/*.lua']`; `exclude` defaults to `['**/.git/**']`. `copy_resources` is off by default; `resource_include` filters copied non-Lua files. `module_paths` defaults to `['?.lua','?/init.lua']` for advisory dependency analysis.

Preset/backend policies independently accept `{"mode":"fixed","value":"…"}` or `{"mode":"weighted","weights":{"…":1}}`. Presets use existing `builtin:fast|balanced|strong|maximum` names or the document's `profiles`; `custom` uses the common settings. Module overrides take priority. Existing capability-disabled options remain visible as warnings; required unsupported protections fail validation.

Selections use separate per-path streams. Set `project.seed` for repeatable choices across project locations; the default derives from the canonical root. Adding a file or editing one override preserves unrelated choices. Selection seeds do not make encrypted outputs byte-identical. GUI **Reroll** changes only this selection seed.

Modules must share a Lua version/environment and compatible explicit runtime ABI. Presets cannot silently switch part of a project to another runtime.

In the GUI, choose **Project**, open a project JSON or choose folders, then inspect the tree before building. Fixed/weighted controls and file-specific overrides update the preview. Building consumes that exact plan; edited sources/settings require refreshing it. Completed rows show actual VM usage, including **No VM** or mixed source-marker regions, plus passes, sizes, timing and dependencies. Existing source-level selection markers retain their behavior.

**Import Single File settings** copies that screen's source/output passes and switches the project preset to the copied settings. Selecting a backend alone does not enable the VM pass; empty source passes are warned and signature-only results are labeled explicitly.

All files build in a temporary directory before publication. Inputs stay unchanged, output paths are excluded from discovery, and failed builds leave the previous output intact. Rebuilds replace only an unchanged output directory owned by the same project; unrelated or edited output files are preserved by refusing replacement. Symlinks/junctions, path escapes and portable filename collisions are rejected. Shared `debug_dumps` paths are unsupported in project builds.

The output keeps relative paths and includes `karity-project-report.json`, separating planned configuration from actual results. Run the entry with the same working-directory/search-path setup as the original project. Dependencies are advisory: custom searchers, dynamic `require` and runtime environment changes retain Lua's original behavior and existing protection constraints; static analysis does not prove arbitrary loader compatibility.

Directory output is supported. Bundling and cross-module rewrites are deferred.
