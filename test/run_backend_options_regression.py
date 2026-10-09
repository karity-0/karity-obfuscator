from pathlib import Path
import copy
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.registry import (
    ConfigError, VM_OPTION_DOCS, config_warnings, resolve_config_profile,
    validate_config, validate_release_config,
)
from obfuscator.vm.backend import unsupported_vm_options
from obfuscator_gui import _vm_option_meta


def main():
    metadata = {item["name"]: item for item in _vm_option_meta()}
    for backend in ("karity", "classic", "default", "mov"):
        opts = {name: info["default"] for name, info in VM_OPTION_DOCS.items()}
        opts["backend"] = backend
        config = {"passes": ["vm"], "vm_options": opts}
        original = copy.deepcopy(config)
        validate_config(config)
        warnings = config_warnings(config)
        unsupported = unsupported_vm_options(backend)
        assert len(warnings) == bool(unsupported)
        for name in unsupported:
            assert name in warnings[0]
        for name in metadata:
            canonical = "karity" if backend == "default" else backend
            assert (canonical in metadata[name]["supported_backends"]) == (name not in unsupported)
        assert config == original
    assert "block_variant_count" in unsupported_vm_options("mov")
    assert "dispatcher_type" not in unsupported_vm_options("classic")
    assert "vm_count" not in unsupported_vm_options("mov")
    assert not config_warnings({"passes": [], "vm_options": {"backend": "mov", "fake_handlers": True}})
    assert not config_warnings({"passes": ["vm"], "vm_options": {"backend": "mov", "vm_count": 2}})
    for change in ({"graph_execution_rate": 2}, {"fake_handlers": "yes"}, {"typo_option": True}):
        try:
            validate_config({"passes": ["vm"], "vm_options": {"backend": "mov", **change}})
        except ConfigError:
            pass
        else:
            raise AssertionError(f"invalid unsupported option accepted: {change}")
    config = resolve_config_profile(json.loads((ROOT / "config.example.json").read_text()), "high")
    config["vm_options"]["backend"] = "mov"
    validate_release_config(config)
    config["vm_options"]["backend"] = "default"
    validate_release_config(config)
    assert not config_warnings(config)
    from obfuscator_gui import Api
    assert Api().get_bootstrap()["backend_aliases"] == {"default": "karity"}
    result = subprocess.run([
        sys.executable, str(ROOT / "main.py"), "--config", str(ROOT / "config.example.json"),
        "--profile", "high", "--vm-option", "backend=mov", "--release-check", "--print-config",
    ], capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["vm_options"]["backend"] == "mov"
    assert result.stderr.count("warning:") == 1, result.stderr
    assert "graph_execution_rate" in result.stderr and "fake_handlers" in result.stderr
    alias = subprocess.run([
        sys.executable, str(ROOT / "main.py"), "--config", str(ROOT / "config.example.json"),
        "--profile", "high", "--vm-option", "backend=default", "--release-check", "--print-config",
    ], capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert alias.returncode == 0 and not alias.stderr, alias.stderr
    assert json.loads(alias.stdout)["vm_options"]["backend"] == "default"
    # Required intent is checked identically before compilation and by lowering.
    for options in (
        {"backend": "mov", "requirements": {"graph_execution": "required"}},
        {"backend": "karity", "graph_execution_rate": 0,
         "requirements": {"graph_execution": "required"}},
        {"requirements": {"unknown": "required"}},
        {"requirements": {"graph_execution": "maybe"}},
        {"requirements": []},
    ):
        try:
            validate_config({"vm_options": options})
        except ConfigError:
            pass
        else:
            raise AssertionError(f"invalid requirement accepted: {options}")
    validate_config({"vm_options": {"requirements": {"graph_execution": "required"}}})

    # A registered backend supplies its own declared fallback implementation;
    # registration propagates to config, GUI and diagnostics without name branches.
    from obfuscator.vm.backends import register_backend, VMBackend
    from obfuscator.vm.backends.base import SHARED_OPTIONS
    from obfuscator.vm.protection import (BackendCapabilities, ProtectionRequest,
        RequirementLevel, resolve_capabilities)
    class TestBackend(VMBackend):
        name = "test_registered"
        description = "capability registry regression"
        capabilities = BackendCapabilities(name, frozenset({"test_graph"}), SHARED_OPTIONS,
                                           (("graph_execution", "test_graph"),))
    register_backend(TestBackend())
    validate_config({"vm_options": {"backend": "test_registered",
                                  "requirements": {"graph_execution": "required"}}})
    result = resolve_capabilities((ProtectionRequest("graph_execution", RequirementLevel.REQUIRED),),
                                  TestBackend.capabilities)
    assert result.is_active("test_graph") and result.fallbacks
    assert "fallback graph_execution -> test_graph" in result.dump()
    metadata = {item["name"]: item for item in _vm_option_meta()}
    assert "test_registered" in [item["value"] for item in metadata["backend"]["values"]]
    assert metadata["graph_execution_rate"]["resolution"]["test_registered"] == {
        "outcome": "fallback", "target": "test_graph"}
    assert "declared fallbacks" in config_warnings({"passes": ["vm"], "vm_options": {
        "backend": "test_registered", "graph_execution_rate": 1}})[0]
    print("backend-options-regression-ok metadata=3_backends alias=ok warnings=ok release=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
