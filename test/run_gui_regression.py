from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile
import time

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

import obfuscator_gui
from obfuscator.registry import VM_OPTION_DOCS, validate_config, validate_release_config
from obfuscator_gui import (
    Api,
    _complete_config,
    _load_profile_root,
    _normalize_preferences,
    _protection_levels,
    _resolved_profiles,
    _vm_option_meta,
)


def execution_regression():
    api = Api()

    def start(script, **extra):
        result = api.start_execution({"script": script, "config": {}, "target": "source", **extra})
        assert result["ok"], result
        return result["id"]

    def wait(run_id, predicate=lambda result: result["done"]):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = api.poll_execution(run_id)
            assert result["ok"], result
            if predicate(result):
                return result
            time.sleep(0.025)
        raise AssertionError(f"Execution timed out: {result}")

    def output(result, stream="stdout"):
        return "".join(event["text"] for event in result["events"] if event["stream"] == stream).replace("\r\n", "\n")

    try:
        run_id = start('print(STRING_OBF("한글"), NUMBER_OBF(42)); io.write("name? "); local line=io.read(); print(line); io.stderr:write("error stream\\n")')
        live = wait(run_id, lambda result: "name?" in output(result))
        assert not live["done"], live
        assert not api.start_execution({"script": "print(1)", "config": {}})["ok"]
        assert api.send_execution_input(run_id, "테스트")["ok"]
        done = wait(run_id)
        assert done["exit_code"] == 0, done
        assert output(done) == "한글\t42\nname? 테스트\n", done
        assert output(done, "stderr") == "error stream\n", done
        assert not api.poll_execution(run_id, done["cursor"])["events"]
        assert not api.send_execution_input(run_id, "late")["ok"]
        failed = wait(start('error("intentional failure")'))
        assert failed["exit_code"] != 0 and "intentional failure" in output(failed, "stderr")
        loop = start('while true do end')
        assert not api.stop_execution(run_id)["ok"]  # Old tokens cannot kill a new run.
        assert api.stop_execution(loop)["ok"]
        stopped = wait(loop)
        assert stopped["stopped"] and stopped["exit_code"] != 0
        fallback = wait(start('print(_VERSION)', config={"target": {"lua_version": "5.1"}}))
        assert fallback["exit_code"] == 0 and "Lua 5.1" in output(fallback), fallback
        assert not api.start_execution({"script": "print(1)", "config": {"lua_executable": "missing-karity-lua.exe"}})["ok"]
        assert not api.start_execution({"script": "   "})["ok"]
        with tempfile.TemporaryDirectory(prefix="karity-run-cwd-") as folder:
            Path(folder, "data.txt").write_text("relative-file", encoding="utf-8")
            relative = wait(start('print(assert(io.open("data.txt")):read("*a"))', source_path=str(Path(folder, "input.lua"))))
            assert relative["exit_code"] == 0 and output(relative) == "relative-file\n", relative
            library = Path(folder, "invalid library.dll")
            library.write_bytes(b"not a Lua library")
            failed_library = wait(start('print(1)', config={
                "lua_library": str(library), "lua_executable": "missing-karity-lua.exe",
            }))
            assert failed_library["exit_code"] != 0
            assert "cannot load lua_library" in output(failed_library, "stderr")
        flood = wait(start('io.write(string.rep("x", 400000))'))
        assert flood["truncated"] and len(output(flood)) <= 300000
        assert not Path(api._execution._run["folder"].name).exists(), "Execution snapshot leaked"
        closing = start('while true do end')
        snapshot = Path(api._execution._run["folder"].name)
        api._execution.close()
        assert api.poll_execution(closing)["done"] and not snapshot.exists()
    finally:
        api._execution.close()


def main() -> int:
    execution_regression()
    root, source = _load_profile_root()
    profiles = _resolved_profiles(root)
    if not source or not profiles:
        raise AssertionError("GUI did not discover project profiles")

    option_meta = _vm_option_meta()
    if {item["name"] for item in option_meta} != set(VM_OPTION_DOCS):
        raise AssertionError("GUI VM option metadata is out of sync with registry")

    levels = _protection_levels(profiles)
    if set(levels) != {"light", "balanced", "strong", "maximum"}:
        raise AssertionError("GUI protection levels are incomplete")
    for options in levels.values():
        if set(options) != set(VM_OPTION_DOCS):
            raise AssertionError("protection level omitted a VM option")

    for config in profiles.values():
        validate_config(config)
    shipped_profiles = _resolved_profiles(json.loads(obfuscator_gui.EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8")))
    for config in shipped_profiles.values():
        for context in ("passes", "vm_output_passes"):
            assert {"strip_info", "minify"} <= set(config[context])
        assert config["vm_options"]["backend"] == "karity"
        assert config["vm_options"]["blob_form"] == "random"
        assert config["vm_options"]["dispatcher_type"] == "mixed"
        assert not config["vm_options"]["runtime_trace"]
    for level, name in zip(("light", "balanced", "strong", "maximum"), ("dev", "fast-vm", "high", "max")):
        assert levels[level] == profiles[name]["vm_options"]
    assert [shipped_profiles[name]["vm_options"]["vm_count"] for name in ("dev", "fast-vm", "high", "max")] == [1, 1, 2, 3]
    assert shipped_profiles["dev"]["passes"] == ["strip_info", "minify", "vm"]
    assert {"anti_debug", "anti_decompile", "function_obf", "meme_strings"} <= set(shipped_profiles["fast-vm"]["passes"])
    assert "pack" not in shipped_profiles["high"]["passes"] and "pack" in shipped_profiles["max"]["passes"]
    for context in ("vm_output_passes", "packer_output_passes"):
        for name in ("high", "max"):
            assert shipped_profiles[name][context] == ["strip_info", "rename_obf", "minify"]
    for name in ("high", "max"):
        stages=shipped_profiles[name]['passes']
        assert stages.index('string_obf') < stages.index('function_obf') < stages.index('number_obf')
    if "max" in profiles:
        validate_release_config(profiles["max"])

    bootstrap = Api().get_bootstrap()
    assert set(bootstrap["profiles"]) <= set(bootstrap["state"]["config"]["_selection_profiles"])
    json.dumps(bootstrap)
    if bootstrap["preferences"]["theme"] not in obfuscator_gui.THEMES:
        raise AssertionError("GUI returned an unsupported theme preference")
    normalized = _normalize_preferences({
        "theme": "invalid", "density": "compact", "editor_font_size": 100,
        "motion": "reduced", "remember_sections": True,
        "sections": {"pipeline": False, "bad": "false"},
    })
    assert normalized == {
        "gui_version": "v2",
        "language": "ko",
        "theme": "system", "density": "compact", "editor_font_size": 18,
        "motion": "reduced", "remember_sections": True,
        "sections": {"pipeline": False},
    }
    assert _normalize_preferences({"gui_version": "invalid"})["gui_version"] == "v2"
    assert _normalize_preferences({"gui_version": "v1"})["gui_version"] == "v1"
    assert _normalize_preferences({"language": "en", "theme": "crystal"})["language"] == "en"
    assert _normalize_preferences({"language": "invalid"})["language"] == "ko"
    assert {"crystal", "ocean", "dracula", "mythic", "crimson"} <= set(bootstrap["themes"])
    assert not {"white", "pyobf-dark"} & set(bootstrap["themes"])
    assert _normalize_preferences({"theme": "white"})["theme"] == "light"
    assert _normalize_preferences({"theme": "pyobf-dark"})["theme"] == "dark"

    html = (ROOT_DIR / "gui" / "web" / "index.html").read_text(encoding="utf-8")
    javascript = (ROOT_DIR / "gui" / "web" / "app.js").read_text(encoding="utf-8")
    html_ids = set(re.findall(r'id="([^"]+)"', html))
    required_ids = set(re.findall(r"\$\('([^']+)'\)", javascript))
    missing_ids = required_ids - html_ids
    if missing_ids:
        raise AssertionError(f"GUI JavaScript references missing DOM ids: {sorted(missing_ids)}")

    smoke = _complete_config({
        "passes": ["vm"],
        "vm_output_passes": [],
        "packer_output_passes": [],
        "vm_options": levels["light"],
    })
    result = Api().run_obfuscation({
        "script": "local x=20+22; print(x)",
        "config": smoke,
        "release_check": False,
    })
    if not result.get("ok") or not result.get("output"):
        raise AssertionError(f"GUI backend smoke build failed: {result.get('error')}")
    if not result.get("profile", {}).get("passes"):
        raise AssertionError("GUI backend did not return build profiling")
    marker_result = Api().run_obfuscation({
        "script": 'print(STRING_OBF("marker"), NUMBER_OBF(42))',
        "config": {"passes": [], "signature": {"mode": "none"}},
    })
    assert marker_result["ok"], marker_result
    assert "STRING_OBF" not in marker_result["output"]
    assert "NUMBER_OBF" not in marker_result["output"]
    mov_config = _complete_config({"passes": ["vm"], "vm_options": {"backend": "mov"}})
    mov_result = Api().run_obfuscation({"script": "print(42)", "config": mov_config})
    assert mov_result["ok"], mov_result
    assert len(mov_result["warnings"]) == 1
    assert "fake_handlers" in mov_result["warnings"][0]

    from lua_runtime import lua_executable
    lua = lua_executable()
    with tempfile.TemporaryDirectory(prefix="karity-gui-") as temp:
        original_preferences_path = obfuscator_gui.PREFERENCES_PATH
        obfuscator_gui.PREFERENCES_PATH = Path(temp) / "preferences.json"
        try:
            saved_preferences = Api().save_preferences({
                "theme": "classic", "editor_font_size": 9,
                "gui_version": "v1",
                "language": "en",
                "sections": {"signature": False},
            })
            assert saved_preferences["ok"]
            persisted = json.loads(obfuscator_gui.PREFERENCES_PATH.read_text(encoding="utf-8"))
            assert persisted["theme"] == "classic"
            assert persisted["gui_version"] == "v1"
            assert persisted["language"] == "en"
            assert persisted["editor_font_size"] == 10
            assert persisted["sections"] == {"signature": False}
        finally:
            obfuscator_gui.PREFERENCES_PATH = original_preferences_path

        output_path = Path(temp) / "gui-smoke.lua"
        output_path.write_text(result["output"], encoding="utf-8")
        executed = subprocess.run([lua, str(output_path)], capture_output=True, timeout=120)
        marker_path = Path(temp) / "gui-markers.lua"
        marker_path.write_text(marker_result["output"], encoding="utf-8")
        marker_executed = subprocess.run([lua, str(marker_path)], capture_output=True, timeout=120)
        assert marker_executed.returncode == 0, marker_executed.stderr
        assert marker_executed.stdout.replace(b"\r\n", b"\n") == b"marker\t42\n"
    normalized_stdout = executed.stdout.replace(b"\r\n", b"\n")
    if (executed.returncode, normalized_stdout, executed.stderr) != (0, b"42\n", b""):
        raise AssertionError(
            "GUI output semantic mismatch: "
            f"{(executed.returncode, executed.stdout, executed.stderr)!r}"
        )

    print(
        f"gui-regression-ok profiles={len(profiles)} "
        f"vm_options={len(option_meta)} levels={len(levels)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
