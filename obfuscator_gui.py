from __future__ import annotations

import json
import time
import traceback
from pathlib import Path

import webview

from obfuscator import Pipeline
from obfuscator.registry import PASS_REGISTRY, build_pipeline_from_config


ROOT_DIR    = Path(__file__).parent
WEB_DIR     = ROOT_DIR / "gui" / "web"
CONFIG_PATH = ROOT_DIR / "obf_gui_config.json"

# GUI에 표시할 메인 파이프라인 패스 순서
MAIN_PASS_ORDER = [
    "remove_comment",
    "anti_debug",
    "string_encode",
    "string_obf",
    "boolean_obf",
    "number_obf",
    "table_obf",
    "function_obf",
    "rename_obf",
    "minify",
    "vm",
]

# VM output 재난독화에 의미 있는 패스 (vm 자체는 제외)
VM_OUTPUT_PASS_ORDER = [
    "string_encode",
    "string_obf",
    "boolean_obf",
    "number_obf",
    "table_obf",
    "function_obf",
    "rename_obf",
    "minify",
]

# VM 보호 강도 옵션 (vm_options에 매핑, 체크박스)
VM_PROTECTION_OPTIONS = [
    {"name": "fake_handlers",   "label": "Fake Handlers",   "default": True},
    {"name": "mutate_handlers", "label": "Handler Mutation (CFF/Opaque Predicate)", "default": True},
    {"name": "junk_instructions", "label": "Junk Instructions", "default": True},
]

# VM 보호 강도 옵션 (vm_options에 매핑, 슬라이더)
VM_PROTECTION_SLIDERS = [
    {
        "name": "junk_rate",
        "label": "Junk Instruction Rate",
        "default": 0.15,
        "min": 0.0,
        "max": 0.5,
        "step": 0.01,
    },
]


class Api:
    """JS 쪽에서 window.pywebview.api.* 로 호출하는 백엔드 API."""

    def __init__(self):
        # 윈도우 최대화/복원용 상태
        self._restore_geometry: tuple[int, int, int, int] | None = None
        self._is_maximized = False

    # ------------------------------------------------------------
    # 메타 정보
    # ------------------------------------------------------------
    def get_pass_meta(self):
        """패스 목록 + 라벨 + 그룹 정보를 JS에 전달."""
        def meta_for(name: str) -> dict:
            info = PASS_REGISTRY[name]
            return {"name": name, "label": info["label"], "group": info["group"]}

        return {
            "main_passes": [meta_for(n) for n in MAIN_PASS_ORDER],
            "vm_output_passes": [meta_for(n) for n in VM_OUTPUT_PASS_ORDER],
            "vm_protection_options": VM_PROTECTION_OPTIONS,
            "vm_protection_sliders": VM_PROTECTION_SLIDERS,
        }

    # ------------------------------------------------------------
    # 설정 저장 / 로드
    # ------------------------------------------------------------
    def load_config(self):
        if not CONFIG_PATH.exists():
            return {"passes": [], "vm_output_passes": [], "vm_options": {}}
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            config.setdefault("vm_options", {})
            return config
        except Exception:
            return {"passes": [], "vm_output_passes": [], "vm_options": {}}

    def save_config(self, config: dict):
        CONFIG_PATH.write_text(
            json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return {"ok": True, "path": str(CONFIG_PATH)}

    # ------------------------------------------------------------
    # 파일 선택
    # ------------------------------------------------------------
    def pick_input_file(self):
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("Lua files (*.lua)", "All files (*.*)"),
        )
        if not result:
            return None

        path = Path(result[0])
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return {"error": f"파일 읽기 실패: {e}"}

        return {
            "path": str(path),
            "name": path.name,
            "content": content,
        }

    def pick_save_path(self, default_name: str):
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("Lua files (*.lua)", "All files (*.*)"),
        )
        if not result:
            return None
        return result if isinstance(result, str) else result[0]

    # ------------------------------------------------------------
    # 난독화 실행
    # ------------------------------------------------------------
    def run_obfuscation(self, payload: dict):
        """
        payload:
            {
                "script": "...",          # 입력 스크립트 텍스트
                "passes": [...],
                "vm_output_passes": [...],
                "vm_options": {...}
            }
        """
        script = payload.get("script", "")
        config = {
            "passes": payload.get("passes", []),
            "vm_output_passes": payload.get("vm_output_passes", []),
            "vm_options": payload.get("vm_options", {}),
        }

        if not script.strip():
            return {"ok": False, "error": "입력 스크립트가 비어있습니다."}

        if not config["passes"]:
            return {"ok": False, "error": "선택된 패스가 없습니다."}

        try:
            pipeline = build_pipeline_from_config(config, Pipeline, show_header=False)

            start = time.perf_counter()
            output = pipeline.run(script, verbose=0)
            elapsed = time.perf_counter() - start

            return {
                "ok": True,
                "output": output,
                "elapsed": round(elapsed, 3),
            }
        except Exception:
            return {"ok": False, "error": traceback.format_exc()}

    # ------------------------------------------------------------
    # 결과 저장
    # ------------------------------------------------------------
    def save_output(self, content: str, default_name: str = "obfuscated.lua"):
        path = self.pick_save_path(default_name)
        if not path:
            return {"ok": False, "error": "취소됨"}

        try:
            Path(path).write_text(content, encoding="utf-8")
            return {"ok": True, "path": path}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------
    # 윈도우 컨트롤 (커스텀 타이틀바용)
    # ------------------------------------------------------------
    def window_minimize(self):
        webview.windows[0].minimize()

    def window_toggle_maximize(self):
        win = webview.windows[0]

        if self._is_maximized:
            # 최대화 해제 -> 저장해둔 크기/위치로 복원
            if self._restore_geometry:
                x, y, w, h = self._restore_geometry
                win.resize(w, h)
                win.move(x, y)
            self._is_maximized = False
        else:
            # 최대화 -> 현재 크기/위치 저장 후 화면 크기로 확장
            self._restore_geometry = (win.x, win.y, win.width, win.height)
            screen = webview.screens[0]
            win.move(0, 0)
            win.resize(screen.width, screen.height)
            self._is_maximized = True

    def window_close(self):
        webview.windows[0].destroy()


def main():
    api = Api()
    webview.create_window(
        "Lua Obfuscator",
        (WEB_DIR / "index.html").resolve().as_uri(),
        js_api=api,
        width=1200,
        height=800,
        min_size=(900, 600),
        background_color="#0a0e14",
        frameless=True,
        easy_drag=False,
    )
    webview.start(debug=False)


if __name__ == "__main__":
    main()