"""
패스 레지스트리.

main.py / GUI / vm_pass.py 의 _obfuscate_vm_output 에서
모두 이 레지스트리를 통해 패스를 이름으로 선택하도록 통일한다.

패스 추가 시 여기 한 줄만 등록하면
- CLI (--passes)
- GUI (체크박스)
- VM output 재난독화 (vm_output_passes)
모두에서 자동으로 사용 가능해진다.
"""
from __future__ import annotations

from .passes import (
    StringEncodePass,
    StringObfuscationPass,
    NumberObfuscationPass,
    BooleanObfuscationPass,
    RenameObfuscationPass,
    RemoveCommentPass,
    MinifyPass,
    VMPass,
    AntiDebugPass,
    TableObfuscationPass,
)


PASS_REGISTRY: dict[str, dict] = {
    "remove_comment": {
        "cls": RemoveCommentPass,
        "label": "Remove Comment",
        "group": "pre",
    },
    "string_encode": {
        "cls": StringEncodePass,
        "label": "Encode String",
        "group": "base",
    },
    "string_obf": {
        "cls": StringObfuscationPass,
        "label": "String Obfuscation",
        "group": "base",
    },
    "boolean_obf": {
        "cls": BooleanObfuscationPass,
        "label": "Boolean Obfuscation",
        "group": "base",
    },
    "number_obf": {
        "cls": NumberObfuscationPass,
        "label": "Number Obfuscation",
        "group": "base",
    },
    "rename_obf": {
        "cls": RenameObfuscationPass,
        "label": "Rename Obfuscation",
        "group": "base",
    },
    "minify": {
        "cls": MinifyPass,
        "label": "Minify",
        "group": "post",
    },
    "vm": {
        "cls": VMPass,
        "label": "VM",
        "group": "post",
    },
    "anti_debug": {
        "cls": AntiDebugPass,
        "label": "Anti-Debug Wrapper",
        "group": "pre",
    },
    "table_obf": {
        "cls": TableObfuscationPass,
        "label": "Table Obfuscation",
        "group": "base",
    },
}


def get_pass_names(group: str | None = None) -> list[str]:
    """그룹별 패스 이름 목록. group=None이면 전체."""
    if group is None:
        return list(PASS_REGISTRY.keys())
    return [name for name, info in PASS_REGISTRY.items() if info["group"] == group]


def build_pipeline_from_config(config: dict, pipeline_cls, show_header: bool = True):
    """
    config 예시:
        {
            "passes": ["string_obf", "boolean_obf", "number_obf", "vm"],
            "vm_output_passes": ["string_obf", "minify"],  # 선택, VMPass에 전달됨
            "vm_options": {"fake_handlers": true, "mutate_handlers": true}  # 선택
        }
    """
    pipeline = pipeline_cls(show_header=show_header)
    vm_output_passes = config.get("vm_output_passes", [])
    vm_options = config.get("vm_options", {})

    for name in config.get("passes", []):
        info = PASS_REGISTRY.get(name)
        if info is None:
            continue

        cls = info["cls"]
        if cls is VMPass:
            pipeline.add(cls(vm_output_passes=vm_output_passes, vm_options=vm_options))
        else:
            pipeline.add(cls())

    return pipeline