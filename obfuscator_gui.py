from __future__ import annotations

import copy
import json
import re
import time
import traceback
from pathlib import Path

import webview

from obfuscator import Pipeline
from obfuscator.profiling import Profiler
from obfuscator.registry import (
    CONFIG_PASS_LISTS,
    PASS_DESCRIPTIONS,
    PASS_REGISTRY,
    VM_OPTION_DOCS,
    build_pipeline_from_config,
    get_pass_contexts,
    resolve_config_profile,
    validate_config,
    validate_release_config,
)


ROOT_DIR = Path(__file__).parent
WEB_DIR = ROOT_DIR / "gui" / "web"
CONFIG_PATH = ROOT_DIR / "obf_gui_config.json"
PROJECT_CONFIG_PATH = ROOT_DIR / "config.json"
EXAMPLE_CONFIG_PATH = ROOT_DIR / "config.example.json"

_OPTION_GROUPS = {
    "dispatcher_type": "Execution", "blob_form": "Execution", "vm_count": "Execution",
    "fake_handlers": "Handlers", "mutate_handlers": "Handlers",
    "junk_instructions": "Handlers", "junk_rate": "Handlers",
    "integrity_constants": "Integrity", "integrity_constant_rate": "Integrity",
    "graph_execution_rate": "Semantic routing", "cross_instruction_rate": "Semantic routing",
    "runtime_polymorphism_rate": "Runtime diversity", "runtime_trace": "Runtime diversity",
    "block_variant_rate": "Runtime diversity", "block_variant_count": "Runtime diversity",
    "block_variant_max_instructions": "Runtime diversity",
    "helper_variant_count": "Choke-point diversity",
    "helper_diversity_rate": "Choke-point diversity",
    "semantic_diversity_rate": "Choke-point diversity",
}

_OPTION_LABELS = {
    "dispatcher_type": "Dispatcher", "blob_form": "Blob representation", "vm_count": "VM count",
    "fake_handlers": "Fake handlers", "mutate_handlers": "Handler mutation",
    "junk_instructions": "Junk instructions", "junk_rate": "Junk rate",
    "integrity_constants": "Integrity constants",
    "integrity_constant_rate": "Integrity constant rate",
    "graph_execution_rate": "Graph execution rate",
    "cross_instruction_rate": "Cross-instruction rate",
    "runtime_polymorphism_rate": "Runtime polymorphism rate",
    "runtime_trace": "Runtime trace diagnostics", "block_variant_rate": "Block variant rate",
    "block_variant_count": "Block variants",
    "block_variant_max_instructions": "Block size limit",
    "helper_variant_count": "Helper variants", "helper_diversity_rate": "Helper diversity rate",
    "semantic_diversity_rate": "Semantic diversity rate",
}


def _default_vm_options() -> dict:
    return {name: copy.deepcopy(info["default"]) for name, info in VM_OPTION_DOCS.items()}


def _complete_config(config: dict) -> dict:
    result = copy.deepcopy(config)
    result.pop("_profile", None)
    for key in CONFIG_PASS_LISTS:
        result.setdefault(key, [])
    result["vm_options"] = {**_default_vm_options(), **result.get("vm_options", {})}
    result.setdefault("signature", {
        "mode": "default",
        "fake": {
            "sources": ["well_known", "generated"],
            "generator_patterns": [
                "Obfuscated using {name} obfuscator!",
                "Protected with {name} V{version}",
                "{name} Lua Protection\nBuild V{version}",
                "Secured by {name}\nVersion: {version}",
            ],
            "custom_pattern": "",
        },
        "custom": "",
    })
    return result


def _load_profile_root() -> tuple[dict, str]:
    for path in (PROJECT_CONFIG_PATH, EXAMPLE_CONFIG_PATH):
        if not path.exists():
            continue
        try:
            root = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(root.get("profiles"), dict) and root["profiles"]:
                return root, str(path)
        except Exception:
            continue
    return {"profile": "custom", "profiles": {}}, ""


def _resolved_profiles(root: dict) -> dict[str, dict]:
    profiles = {}
    for name in root.get("profiles", {}):
        try:
            profiles[name] = _complete_config(resolve_config_profile(root, name))
        except Exception:
            continue
    return profiles


def _protection_levels(profiles: dict[str, dict]) -> dict[str, dict]:
    defaults = _default_vm_options()
    light = {
        **defaults, "dispatcher_type": "ifelseif", "blob_form": "string", "vm_count": 1,
        "fake_handlers": False, "mutate_handlers": False, "junk_instructions": False,
        "junk_rate": 0.0, "integrity_constants": False, "integrity_constant_rate": 0.0,
        "graph_execution_rate": 0.05, "cross_instruction_rate": 0.05,
        "runtime_polymorphism_rate": 0.05, "block_variant_rate": 0.0,
        "helper_variant_count": 1, "helper_diversity_rate": 0.0,
        "semantic_diversity_rate": 0.05,
    }
    balanced = copy.deepcopy(profiles.get("fast-vm", {}).get("vm_options", defaults))
    strong = {
        **defaults, "dispatcher_type": "mixed", "blob_form": "random", "vm_count": 2,
        "fake_handlers": True, "mutate_handlers": True, "junk_instructions": True,
        "junk_rate": 0.2, "integrity_constants": True, "integrity_constant_rate": 0.25,
        "graph_execution_rate": 0.12, "cross_instruction_rate": 0.3,
        "runtime_polymorphism_rate": 0.25, "block_variant_rate": 0.12,
        "block_variant_count": 3, "block_variant_max_instructions": 8,
        "helper_variant_count": 3, "helper_diversity_rate": 0.5,
        "semantic_diversity_rate": 0.55,
    }
    maximum = copy.deepcopy(profiles.get("max", {}).get("vm_options", strong))
    return {"light": light, "balanced": balanced, "strong": strong, "maximum": maximum}


def _range_bounds(info: dict, default) -> tuple[float | int, float | int, float | int]:
    values = re.findall(r"-?\d+(?:\.\d+)?", str(info.get("range", "")))
    is_int = isinstance(default, int) and not isinstance(default, bool)
    if len(values) >= 2:
        low = int(float(values[0])) if is_int else float(values[0])
        high = int(float(values[1])) if is_int else float(values[1])
    elif is_int:
        low, high = 1, max(8, int(default))
    else:
        low, high = 0.0, 1.0
    return low, high, 1 if is_int else 0.01


def _vm_option_meta() -> list[dict]:
    result = []
    for name, info in VM_OPTION_DOCS.items():
        default = info["default"]
        item = {
            "name": name,
            "label": _OPTION_LABELS.get(name, name.replace("_", " ").title()),
            "description": info.get("description", ""),
            "default": default,
            "group": _OPTION_GROUPS.get(name, "Advanced"),
        }
        if isinstance(default, bool):
            item["kind"] = "boolean"
        elif "values" in info:
            item["kind"] = "select"
            item["values"] = [
                {"value": value, "label": value, "description": description}
                for value, description in info["values"] if not value.endswith("N")
            ]
            if name == "dispatcher_type":
                item["values"].extend(
                    {"value": value, "label": value, "description": "split dispatcher preset"}
                    for value in ("split4", "split6", "bsplit4", "bsplit6")
                )
        else:
            low, high, step = _range_bounds(info, default)
            item.update({
                "kind": "integer" if isinstance(default, int) else "number",
                "min": low, "max": high, "step": step,
            })
        result.append(item)
    return result


def _pass_meta() -> list[dict]:
    return [{
        "name": name, "label": info["label"], "group": info["group"],
        "description": PASS_DESCRIPTIONS.get(name, ""),
        "contexts": get_pass_contexts(name),
    } for name, info in PASS_REGISTRY.items()]


def _initial_state(profiles: dict[str, dict], default_profile: str | None) -> dict:
    selected = default_profile if default_profile in profiles else next(iter(profiles), None)
    level_for_profile = {"dev": "light", "fast-vm": "balanced", "max": "maximum"}
    return {
        "preset": selected or "custom",
        "protection_level": level_for_profile.get(selected, "custom"),
        "release_check": selected == "max",
        "config": copy.deepcopy(profiles.get(selected, _complete_config({}))),
    }


class Api:
    """Backend exposed to JavaScript through window.pywebview.api."""

    def __init__(self):
        self._restore_geometry: tuple[int, int, int, int] | None = None
        self._is_maximized = False

    def get_bootstrap(self):
        root, source = _load_profile_root()
        profiles = _resolved_profiles(root)
        levels = _protection_levels(profiles)
        state = _initial_state(profiles, root.get("profile"))
        if CONFIG_PATH.exists():
            try:
                saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                if isinstance(saved.get("config"), dict):
                    saved["config"] = _complete_config(saved["config"])
                    state = {**state, **saved}
                elif isinstance(saved, dict):
                    state = {"preset": "custom", "protection_level": "custom",
                             "release_check": False, "config": _complete_config(saved)}
            except Exception:
                pass
        return {
            "state": state, "profiles": profiles, "protection_levels": levels,
            "passes": _pass_meta(), "vm_options": _vm_option_meta(),
            "profile_source": source,
        }

    def save_config(self, state: dict):
        config = _complete_config(state.get("config", {}))
        validate_config(config)
        saved = {
            "preset": state.get("preset", "custom"),
            "protection_level": state.get("protection_level", "custom"),
            "release_check": bool(state.get("release_check", False)),
            "config": config,
        }
        CONFIG_PATH.write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ok": True, "path": str(CONFIG_PATH)}

    def pick_input_file(self):
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG, file_types=("Lua files (*.lua)", "All files (*.*)"))
        if not result:
            return None
        path = Path(result[0])
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            return {"error": f"파일 읽기 실패: {exc}"}
        return {"path": str(path), "name": path.name, "content": content}

    def pick_save_path(self, default_name: str):
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG, save_filename=default_name,
            file_types=("Lua files (*.lua)", "All files (*.*)"))
        if not result:
            return None
        return result if isinstance(result, str) else result[0]

    def run_obfuscation(self, payload: dict):
        script = payload.get("script", "")
        config = _complete_config(payload.get("config", {}))
        if not script.strip():
            return {"ok": False, "error": "입력 스크립트가 비어있습니다."}
        if not config["passes"]:
            return {"ok": False, "error": "선택된 패스가 없습니다."}
        try:
            validate_config(config)
            if payload.get("release_check"):
                validate_release_config(config)
            pipeline = build_pipeline_from_config(config, Pipeline)
            profiler = Profiler()
            start = time.perf_counter()
            output = pipeline.run(script, verbose=0, profiler=profiler)
            return {"ok": True, "output": output,
                    "elapsed": round(time.perf_counter() - start, 3),
                    "profile": profiler.as_dict()}
        except Exception:
            return {"ok": False, "error": traceback.format_exc()}

    def save_output(self, content: str, default_name: str = "obfuscated.lua"):
        path = self.pick_save_path(default_name)
        if not path:
            return {"ok": False, "error": "취소됨"}
        try:
            Path(path).write_text(content, encoding="utf-8")
            return {"ok": True, "path": path}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def window_minimize(self):
        webview.windows[0].minimize()

    def window_toggle_maximize(self):
        window = webview.windows[0]
        if self._is_maximized:
            if self._restore_geometry:
                x, y, width, height = self._restore_geometry
                window.resize(width, height)
                window.move(x, y)
            self._is_maximized = False
        else:
            self._restore_geometry = (window.x, window.y, window.width, window.height)
            screen = webview.screens[0]
            window.move(0, 0)
            window.resize(screen.width, screen.height)
            self._is_maximized = True

    def window_close(self):
        webview.windows[0].destroy()


def main():
    webview.create_window(
        "Karity Obfuscator", (WEB_DIR / "index.html").resolve().as_uri(),
        js_api=Api(), width=1440, height=900, min_size=(1040, 680),
        background_color="#070a12", frameless=True, easy_drag=False)
    webview.start(debug=False)


if __name__ == "__main__":
    main()
