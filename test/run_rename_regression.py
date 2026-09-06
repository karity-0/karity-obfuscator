"""Lexical naming and generated-runtime integration regressions."""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.names import NameAllocator, KEYWORDS
from obfuscator.passes.rename_ts import rename_script_ts
from obfuscator.passes.rename_obfuscation import RenameObfuscationPass
from obfuscator.passes.localize_globals import LocalizeGlobalsPass
from obfuscator.pipeline import Pipeline
from obfuscator import build_pipeline_from_config
from obfuscator.registry import validate_config, ConfigError
from obfuscator.names import RENAME_OPTIONS
from obfuscator.passes.anti_debug import AntiDebugPass
from obfuscator.passes.anti_decompile import AntiDecompilePass


def run(source):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "test.lua"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run([str(ROOT / "bin" / ("lua.exe" if os.name == "nt" else "lua")), str(path)], capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr
        return result.stdout


def main():
    cases = [
        'a=40; local long=2; print(a+long)',
        'x=7; print(x); local x=x+1; do local x=x+10; print(x) end; print(x)',
        'local x=1; local function f() return x end; local x=x+1; print(f(),x)',
        'local x=5; for x=x,x+1 do print(x) end; print(x)',
        'local x=3; for x,y in ipairs({x,4}) do print(x,y) end; print(x)',
        'local x=1; repeat local x=x+1; print(x); until x==2; print(x)',
        'local x=1; if x==1 then local x=2; print(x) elseif x==2 then local x=3 else local x=4 end; print(x)',
        'local function f(n) if n==0 then return 1 end return n*f(n-1) end; print(f(5))',
        'local f; function f(x) return x+1 end; print(f(4))',
        'local self=99; local t={value=2}; function t:f(x) return self.value+x end; print(t:f(3),self)',
        'local key="value"; local t={key=2,[key]=3}; print(t.key,t[key],"key")',
        'local x=1; ::x:: x=x+1; if x<3 then goto x end; print(x)',
        'local _ENV=setmetatable({value=8},{__index=_ENV}); local x=value; print(x)',
        'local function f(...) local a,b,c=...; return a,b,c end; print(f(1,nil,3))',
        'local type=function() return "local" end; print(type())',
    ]
    for source in cases:
        expected = run(source)
        for options in ({}, {"seed": 42}, {"readable": True}):
            renamed = rename_script_ts(source, **options)
            assert run(renamed) == expected, (source, renamed)
            assert renamed == rename_script_ts(source, **options)
        pipeline = Pipeline(show_header=False).add(RenameObfuscationPass()).add(LocalizeGlobalsPass())
        assert run(pipeline.run(source)) == expected, source
    source = 'a=7; local original=2; print(a+original)'
    for helper in (AntiDebugPass(), AntiDecompilePass()):
        pipeline = Pipeline(show_header=False).add(helper).add(RenameObfuscationPass())
        assert run(pipeline.run(source)) == run(source)
    config = {"passes": ["rename_obf"], "signature": {"mode": "none"},
              "rename_obf_options": {"readable": True, "seed": 3}}
    pipeline = build_pipeline_from_config(config, Pipeline)
    assert '_original_' in pipeline.run(source)
    assert RENAME_OPTIONS.get() == {}
    for invalid in ({"seed": True}, {"readable": 1}, {"typo": True}, []):
        try:
            validate_config({**config, "rename_obf_options": invalid})
        except ConfigError:
            pass
        else:
            raise AssertionError(invalid)
    assert '<const>' in rename_script_ts('local value <const> = 1; return value')
    allocator = NameAllocator({'a', 'b'})
    names = [allocator.allocate() for _ in range(10000)]
    assert len(set(names)) == len(names)
    assert not set(names) & (KEYWORDS | {'a', 'b', '_ENV', 'self'})
    assert all(re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', name) for name in names)
    assert list(map(len,names)) == sorted(map(len,names))
    source = 'local ' + ','.join('cold'+str(i) for i in range(60)) + '; local hot=1; print(' + '+'.join(['hot']*100) + ')'
    renamed = rename_script_ts(source)
    assert 'local a=1' in renamed, renamed
    assert len(renamed) < len(source)
    assert run(renamed) == run(source)
    assert rename_script_ts('local long=1; print(long)', seed=1) != rename_script_ts('local long=1; print(long)', seed=2)
    print('rename regression: OK (lexical scopes, frequency, seeds, helpers)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
