"""Scoped strategy activation, numerical semantics, provenance and style metrics."""
from pathlib import Path
import math
import json
import random
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.pipeline import Pipeline
from obfuscator.registry import build_pipeline_from_config, validate_config, ConfigError
from obfuscator.profiling import Profiler
from obfuscator.passes.literal_mosaic import LiteralMosaic, use_mosaic, ACTIVE, boundary
from obfuscator.passes.mosaic_metrics import DiversityMetrics, structural_fingerprint, expression_summary
from obfuscator.passes.numeric_provenance import CodeText, NumericTransport, join_code, number_origin, protected_number
from obfuscator.vm.backends.runtime_emitter import _obfuscate_vm_output

SOURCE='''local function f(x)
local text="hello world"
local function g() return text,x,nil,nil end
x=x+73
return g()
end
return f(2)
'''


def run(source,version='5.3'):
    return (Lua53 if version=='5.3' else Lua51)(unpack_returned_tuples=True).execute(source)


def pipeline(config,source=SOURCE):
    p=build_pipeline_from_config({**config,'signature':{'mode':'none'}},Pipeline)
    profiler=Profiler()
    random.seed(261011)
    result=p.run(source,profiler=profiler)
    return result,p,profiler.as_dict()['literal_mosaic']


def main():
    expected=run(SOURCE)
    for number in (False,True):
        for meme in (False,True):
            passes=['string_obf','function_obf']+(['number_obf'] if number else [])+(['meme_strings'] if meme else [])
            config={'passes':passes,'literal_mosaic':{'generated_meme_rate':1.0}}
            output,p,metrics=pipeline(config)
            assert run(output)==expected,(number,meme)
            counts=metrics['strategies']
            assert bool(counts.get('meme_generated',0))==meme,counts
            number_strategies=sum(v for k,v in counts.items() if k.startswith('number_'))
            assert bool(number_strategies)==number,counts
            assert '#"' not in output if not meme else '#"' in output
            assert 'KarityNumericOrigin' not in output
            if number:
                numeric=next(d for d in p._passes[-(2 if meme else 1)].last_profile if d['phase']=='number_origins')
                assert numeric['source_replacements']>0 and numeric['protected_generated_numbers']>0,numeric
            assert ACTIVE.get() is None
            # Metrics do not perturb the PRNG, emitted text or native behavior.
            random.seed(261011)
            again=build_pipeline_from_config({**config,'signature':{'mode':'none'}},Pipeline).run(SOURCE)
            assert output==again,(number,meme)
            print('mosaic-activation-ok',number,meme,metrics['expressions'],flush=True)

    for version in ('5.1','5.3'):
        lua=(Lua51 if version=='5.1' else Lua53)(unpack_returned_tuples=True)
        values=[0,1,-17,16777215,2147483647,1<<39,1.25,-0.0,1e300,math.inf,-math.inf,math.nan]
        if version=='5.3': values.extend([-(1<<63),(1<<63)-1])
        for number,meme in ((False,False),(True,False),(False,True),(True,True)):
            service=LiteralMosaic((['number_obf'] if number else [])+(['meme_strings'] if meme else []),
                lua_version=version,options={'style':'exotic','cost':'medium','generated_meme_rate':1.0},
                metrics=DiversityMetrics(True))
            random.seed(1801)
            for value in values:
                expr=service.number(value,context='test_constant')
                actual=lua.eval(expr)
                if isinstance(value,float) and math.isnan(value): assert math.isnan(actual),expr
                else: assert actual==value,(version,value,expr,actual)
                if value==0.0 and isinstance(value,float):
                    # Lupa's Lua 5.1 binding can convert an integral double to
                    # Python int, losing its zero sign. Observe it inside Lua.
                    reciprocal=lua.eval('1.0/('+expr+')')
                    assert math.copysign(1,reciprocal)==math.copysign(1,value),expr
                if version=='5.3':
                    assert lua.eval('math.type('+expr+')')==('integer' if isinstance(value,int) else 'float'),expr
                if version=='5.1': assert not any(op in expr for op in ('//','<<','>>','~','&','|')),expr
            print('mosaic-native-ok',version,number,meme,flush=True)

    # Random arithmetic residuals near INT64 limits must never turn into
    # overflowed decimal floats. Cover multiple seeds and both cost extremes.
    lua=Lua53()
    for seed in range(24):
        random.seed(seed)
        service=LiteralMosaic(['number_obf','meme_strings'],
            options={'style':'exotic','cost':'high','generated_meme_rate':0.5})
        for value in (-(1<<63),-(1<<63)+1,(1<<63)-1,(1<<53)+1):
            expression=service.number(value)
            assert lua.eval(expression)==value,expression
            assert lua.eval('math.type('+expression+')')=='integer',expression

    selected='''--@MEME_STRINGS_START
--@NUMBER_OBF_START
local function selected() return "inside",73 end
--@NUMBER_OBF_END
--@MEME_STRINGS_END
local function outside() return "outside",91 end
return selected(),outside()
'''
    config={'passes':['string_obf','function_obf','number_obf','meme_strings'],
            'selection_modes':{'number_obf':'marked','meme_strings':'marked'},
            'literal_mosaic':{'generated_meme_rate':1.0}}
    output,p,metrics=pipeline(config,selected)
    assert run(output)==run(selected)
    assert metrics['strategies']['meme_generated']>0
    assert all(not name.startswith('number_') or count>0 for name,count in metrics['strategies'].items())
    # Every generated-expression tag belongs to the selected declaration;
    # plain reconstruction constants outside remain unprotected by Mosaic.
    assert any('/mosaic:' in o for _,_,o in output.origins)
    assert any(o=='string_constant' for _,_,o in output.origins)

    parent=LiteralMosaic(['number_obf','meme_strings'],options={'generated_meme_rate':1.0},metrics=DiversityMetrics(True))
    with use_mosaic(parent):
        runtime,_=_obfuscate_vm_output('local function f()return 73 end;return f()', ['function_obf'])
        assert '#"' not in runtime
        assert not parent.metrics.strategies
        with use_mosaic(boundary(['meme_strings'],phase='packer_output')):
            generated=ACTIVE.get().number(73)
            assert '#"' in generated
            assert protected_number(generated,0,len(generated))
        assert ACTIVE.get() is parent
    assert ACTIVE.get() is None

    # Output pipelines use their own full lists, including literal stages
    # scheduled after legacy FunctionObf. Neither source flags nor a literal
    # stage being outside the legacy subpipeline may leak into this decision.
    from obfuscator.passes.packer import _obfuscate_packer_output
    for phase,emit in (('vm_output',lambda src,names:_obfuscate_vm_output(src,names)[0]),
                       ('packer_output',_obfuscate_packer_output)):
        for number,meme in ((False,False),(True,False),(False,True),(True,True)):
            parent=LiteralMosaic(['number_obf','meme_strings'],
                options={'generated_meme_rate':1.0},metrics=DiversityMetrics(True))
            names=['function_obf']+(['meme_strings'] if meme else [])+(['number_obf'] if number else [])
            random.seed(7201)
            with use_mosaic(parent):
                output=emit('local function f(x)x=x+1;if x>2 then x=x+73 end;return x,nil end;return f(2)',names)
            assert run(output)==(76,None),(phase,number,meme)
            counts=parent.metrics.strategies
            assert bool(counts.get('meme_generated',0))==meme,counts
            assert bool(sum(v for k,v in counts.items() if k.startswith('number_')))==number,counts
            assert set(parent.metrics.phases)<=set([phase]),parent.metrics.phases

    # OFF really bypasses the optional engines, including float formatting.
    with patch('obfuscator.passes.number_expressions.NumberExpressionEngine._fmt_float',side_effect=AssertionError('disabled NumberObf')):
        with patch('obfuscator.passes.meme_expressions.MemeExpressionEngine.float_zero',side_effect=AssertionError('disabled MemeStrings')):
            assert run('return '+LiteralMosaic().number(1.25))==1.25
    for invalid in (True,1<<63,-(1<<63)-1):
        try: LiteralMosaic(['number_obf','meme_strings']).number(invalid)
        except (ValueError,TypeError): pass
        else: raise AssertionError(invalid)
    try:
        with use_mosaic(parent):
            raise RuntimeError('scope unwinding')
    except RuntimeError: pass
    assert ACTIVE.get() is None

    text=CodeText('ab123cd',[(2,5)],origins=[(2,5,'function_constant/mosaic:number_bounded')])
    moved=join_code(('xx',text[1:6]))
    assert protected_number(moved,3,6)
    assert number_origin(moved,3,6).startswith('function_constant/mosaic:')
    from obfuscator.passes.number_expressions import NumberExpressionEngine
    from obfuscator.passes.ts_utils import parse, _build_b2c
    assert list(_build_b2c('A😄B한',9))==[0,1,1,1,1,2,3,3,3,4]
    unicode_source='local text="🍤한글\u202ewrong way\u202c";return "done"'
    unicode_ctx=parse(unicode_source)
    assert unicode_ctx.b2c.itemsize<=8
    literals=[n for n in unicode_ctx.walk() if n.type=='string']
    assert {unicode_ctx.text(n) for n in literals}=={'"done"','"🍤한글\u202ewrong way\u202c"'}
    for node in literals:
        assert unicode_source[unicode_ctx.cs(node):unicode_ctx.ce(node)+1]==unicode_ctx.text(node)
    plain='local function f()return (10+20)+2 end;return f()'
    start=plain.index('(10+20)')
    tagged=CodeText(plain,[(start,start+7)],origins=[(start,start+7,'string_constant/mosaic:number_bounded')])
    ctx=parse(tagged)
    function=next(n for n in ctx.walk() if n.type=='function_declaration')
    transport=NumericTransport(tagged,NumberExpressionEngine())
    edits=transport.source_edits(ctx,function)
    assert len(edits)==2,edits  # one whole generated expression + source 2
    encoded=plain
    for a,b,text in sorted(edits,reverse=True): encoded=encoded[:a]+text+encoded[b:]
    decoded=transport.finish(encoded)
    assert run(decoded)==32 and len(decoded.protected)==1
    try: transport.finish('--[[KarityNumericOrigin:99999:begin]] return 2')
    except RuntimeError: pass
    else: raise AssertionError('unregistered marker accepted')
    a=structural_fingerprint('(a+b)~c')[0]
    assert a==structural_fingerprint('(x+y)~z')[0]
    assert a!=structural_fingerprint('(a<<b)-c')[0]
    for budget in (0,1,3):
        service=LiteralMosaic(['number_obf','meme_strings'],options={'style':'exotic','max_operations':budget})
        for value in (0,73,10000):
            expr=service.number(value,hot=True)
            assert expression_summary(expr)[2]<=budget,(expr,budget)
            assert run('return '+expr)==value
    for version in ('5.1','5.3'):
        lua=(Lua51 if version=='5.1' else Lua53)()
        service=LiteralMosaic(['number_obf'],lua_version=version,
            options={'style':'exotic'},metrics=DiversityMetrics(True))
        expressions=[]
        for seed in range(160):
            random.seed(seed)
            value=(-1 if seed%2 else 1)*(37 if seed%3 else (1<<50)+seed)
            expression=service.number(value,hot=True)
            expressions.append(expression)
            assert lua.eval(expression)==value,(version,seed,expression)
            assert expression_summary(expression)[2]<=3,expression
            if version=='5.3': assert lua.eval('math.type('+expression+')')=='integer',expression
        combined=' '.join(expressions)
        assert '*' in combined and '%' in combined
        if version=='5.3': assert all(op in combined for op in ('//','&','|','~','<<','>>')),combined
        else: assert '/' in combined and not any(op in combined for op in ('//','&','|','~','<<','>>'))
    for invalid in ({'style':'unknown'},{'max_operations':True},{'cost':'unlimited'}, {'generated_meme_rate':2}):
        try: validate_config({'literal_mosaic':invalid})
        except ConfigError: pass
        else: raise AssertionError(invalid)
    with tempfile.TemporaryDirectory(prefix='karity-mosaic-cli-') as directory:
        directory=Path(directory)
        config=directory/'config.json'
        config.write_text(json.dumps({'passes':['function_obf','number_obf','meme_strings'],
            'signature':{'mode':'none'},'literal_mosaic':{'generated_meme_rate':1.0}}))
        source=directory/'source.lua'
        source.write_text('local function f(x)x=x+1;if x>2 then x=x+73 end;return x,nil end;return f(2)')
        for name in ('number_obf','meme_strings'):
            output,report=directory/(name+'.lua'),directory/(name+'.json')
            result=subprocess.run([sys.executable,str(ROOT/'main.py'),str(source),'-c',str(config),
                '-o',str(output),'--passes','function_obf,'+name,'--seed','7201',
                '--profile-report',str(report)],capture_output=True,cwd=ROOT)
            assert result.returncode==0,result.stderr
            assert run(output.read_text(encoding='utf-8'))==(76,None)
            strategies=json.loads(report.read_text(encoding='utf-8'))['literal_mosaic']['strategies']
            assert bool(strategies.get('meme_generated',0))==(name=='meme_strings'),strategies
            assert bool(sum(v for k,v in strategies.items() if k.startswith('number_')))==(name=='number_obf'),strategies
    print('literal-mosaic-regression-ok activation, scopes, native types, costs, metrics and provenance')


if __name__=='__main__':main()
