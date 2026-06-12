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
    "string_encode",
    "string_obf",
    "boolean_obf",
    "number_obf",
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
    "rename_obf",
    "minify",
]


class Api:
    """JS 쪽에서 window.pywebview.api.* 로 호출하는 백엔드 API."""

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
        }

    # ------------------------------------------------------------
    # 설정 저장 / 로드
    # ------------------------------------------------------------
    def load_config(self):
        if not CONFIG_PATH.exists():
            return {"passes": [], "vm_output_passes": []}
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {"passes": [], "vm_output_passes": []}

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
                "vm_output_passes": [...]
            }
        """
        script = payload.get("script", "")
        config = {
            "passes": payload.get("passes", []),
            "vm_output_passes": payload.get("vm_output_passes", []),
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


def main():
    api = Api()
    webview.create_window(
        "Lua Obfuscator",
        (WEB_DIR / "index.html").resolve().as_uri(),
        js_api=api,
        width=1200,
        height=800,
        min_size=(900, 600),
        background_color="#0d1117",
    )
    webview.start(debug=False)


if __name__ == "__main__":
    main()