"""Check import boundaries in fresh interpreters and retain public pass exports."""
from pathlib import Path
import subprocess
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]


def check(source, *, eager=False):
    source = textwrap.dedent(source)
    if eager and sys.version_info >= (3, 15):
        source = "import sys; sys.set_lazy_imports_filter(lambda *args: False)\n" + source
    subprocess.run([sys.executable, "-c", source], cwd=ROOT, check=True)


def main():
    check('''
        from obfuscator.registry import PASS_REGISTRY
        from obfuscator import passes
        from obfuscator.vm import VMPass
        for name, info in PASS_REGISTRY.items():
            cls = info["cls"]
            assert isinstance(cls, type), name
            assert info.get("cls") is cls, name
            assert cls is (VMPass if name == "vm" else getattr(passes, cls.__name__))
    ''')
    check('''
        from obfuscator import Pipeline, build_pipeline_from_config
        pipeline = build_pipeline_from_config({"passes": ["remove_comment"]}, Pipeline,
                                              show_header=False)
        assert pipeline.run('-- comment\\nprint(42)').strip() == 'print(42)'
    ''')
    if sys.version_info >= (3, 15):
        check('''
            from obfuscator import Pipeline, build_pipeline_from_config
            p = build_pipeline_from_config({"passes": ["remove_comment", "minify"]},
                                           Pipeline, show_header=False)
            assert p.run('-- comment\\nprint(42)').strip() == 'print(42)'
        ''', eager=True)
        check('''
            import sys
            import obfuscator
            assert "obfuscator.pipeline" not in sys.modules
            assert "obfuscator.registry" not in sys.modules
            from obfuscator.registry import PASS_REGISTRY, get_pass_names, validate_config
            assert "vm" in get_pass_names()
            assert PASS_REGISTRY["function_obf"]["group"] == "base"
            validate_config({"passes": ["remove_comment"]})
            from obfuscator import Pipeline, build_pipeline_from_config
            p = build_pipeline_from_config({"passes": ["remove_comment"]}, Pipeline,
                                           show_header=False)
            assert p.run('-- comment\\nprint(42)').strip() == 'print(42)'
            for prefix in ("luaparser", "tree_sitter", "obfuscator.vm.vm_pass",
                           "obfuscator.vm.backends.runtime_emitter",
                           "obfuscator.passes.function_obfuscation", "obfuscator.passes.packer"):
                assert not any(m.startswith(prefix) for m in sys.modules), prefix
            from obfuscator.passes import MinifyPass
            assert "obfuscator.passes.minify" in sys.modules
            assert p.add(MinifyPass()).run('print(42)').strip() == 'print(42)'
        ''')
        check('''
            import contextlib, io, runpy, sys
            for option in ("--help", "--version", "--list-passes"):
                sys.argv = ["main.py", option]
                with contextlib.redirect_stdout(io.StringIO()):
                    try:
                        runpy.run_path("main.py", run_name="__main__")
                    except SystemExit as exc:
                        assert exc.code == 0
                for prefix in ("luaparser", "tree_sitter", "obfuscator.pipeline",
                               "obfuscator.vm.vm_pass"):
                    assert not any(m.startswith(prefix) for m in sys.modules), prefix
        ''')
        check('''
            import sys
            import obfuscator_gui
            assert obfuscator_gui._vm_option_meta()
            for prefix in ("luaparser", "tree_sitter", "obfuscator.pipeline",
                           "obfuscator.vm.vm_pass", "obfuscator.vm.backends.runtime_emitter"):
                assert not any(m.startswith(prefix) for m in sys.modules), prefix
        ''')
    print("import-regression-ok exports, pipeline" +
          (", native lazy/eager loading" if sys.version_info >= (3, 15) else ", legacy imports"))


if __name__ == "__main__":
    main()
