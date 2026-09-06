from __future__ import annotations

from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

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


def main() -> int:
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
    if "max" in profiles:
        validate_release_config(profiles["max"])

    bootstrap = Api().get_bootstrap()
    json.dumps(bootstrap)
    if bootstrap["preferences"]["theme"] not in {"light", "dark", "deepdark", "system", "classic"}:
        raise AssertionError("GUI returned an unsupported theme preference")
    normalized = _normalize_preferences({
        "theme": "invalid", "density": "compact", "editor_font_size": 100,
        "motion": "reduced", "remember_sections": True,
        "sections": {"pipeline": False, "bad": "false"},
    })
    assert normalized == {
        "theme": "system", "density": "compact", "editor_font_size": 18,
        "motion": "reduced", "remember_sections": True,
        "sections": {"pipeline": False},
    }

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
    mov_config = _complete_config({"passes": ["vm"], "vm_options": {"backend": "mov"}})
    mov_result = Api().run_obfuscation({"script": "print(42)", "config": mov_config})
    assert mov_result["ok"], mov_result
    assert len(mov_result["warnings"]) == 1
    assert "fake_handlers" in mov_result["warnings"][0]

    lua_path = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    lua = str(lua_path) if lua_path.exists() else (
        shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"
    )
    with tempfile.TemporaryDirectory(prefix="karity-gui-") as temp:
        original_preferences_path = obfuscator_gui.PREFERENCES_PATH
        obfuscator_gui.PREFERENCES_PATH = Path(temp) / "preferences.json"
        try:
            saved_preferences = Api().save_preferences({
                "theme": "classic", "editor_font_size": 9,
                "sections": {"signature": False},
            })
            assert saved_preferences["ok"]
            persisted = json.loads(obfuscator_gui.PREFERENCES_PATH.read_text(encoding="utf-8"))
            assert persisted["theme"] == "classic"
            assert persisted["editor_font_size"] == 10
            assert persisted["sections"] == {"signature": False}
        finally:
            obfuscator_gui.PREFERENCES_PATH = original_preferences_path

        output_path = Path(temp) / "gui-smoke.lua"
        output_path.write_text(result["output"], encoding="utf-8")
        executed = subprocess.run([lua, str(output_path)], capture_output=True, timeout=120)
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
