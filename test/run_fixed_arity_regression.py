"""Fixed CALL arities: native/original/candidate values, roots and guards."""
from pathlib import Path
import argparse,random,sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test'),str(ROOT/'tools')]
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from profile_vm_runtime import execute
from run_vm_backend_regression import options
from run_source_protection_regression import run


SETUP='''trace={};weak=setmetatable({},{__mode='v'})
function maker()local o={};weak[1]=o;return o end
function drop1(x)x=nil;collectgarbage('collect');collectgarbage('collect');assert(weak[1]==nil,'argument retained')end
function drop2(a,x)a=nil;x=nil;collectgarbage('collect');collectgarbage('collect');assert(weak[1]==nil,'second argument retained')end
function drop3(a,x,c)a=nil;x=nil;c=nil;collectgarbage('collect');collectgarbage('collect');assert(weak[1]==nil,'third argument retained')end
for n=0,4 do _G['external'..n]=function(...)
 local t={};for i=1,select('#',...)do t[i]=tostring(select(i,...))end
 trace[#trace+1]=n..':'..select('#',...)..':'..table.concat(t,',')
 return 10+n,nil,false,30+n,nil
end end
'''.replace('\n',' ')


def matrix_source():
    lines=['local function check(...)local t={n=select("#",...),...};return t end']
    args=('', 'nil','nil,false','"arg",nil,false')
    for n,arguments in enumerate(args):
        for results in range(4):
            call=f'external{n}({arguments})'
            if not results:lines.append(call)
            else:
                names=','.join(f'x{i}' for i in range(1,results+1))
                predicate=f'x1=={10+n}'+(' and x2==nil' if results>=2 else '')+(' and x3==false' if results>=3 else '')
                lines.append(f'do local {names}={call};assert({predicate}) end')
    for results in range(4):
        call='external4(1,nil,3,nil)'
        lines.append(('do local '+','.join('v'+str(i) for i in range(results))+'='+call+';assert(v0==14) end') if results else call)
    for n,arguments in enumerate(args):
        lines.append(f"do local function tail()return external{n}({arguments})end;local t=check(tail());assert(t.n==5 and t[1]=={10+n} and t[5]==nil)end")
    lines.extend(['''local t=check(external3('open',nil,false));assert(t.n==5 and t[2]==nil and t[3]==false and t[5]==nil)
local function open(...)return external4(...)end
local t=check(open(1,nil,3,nil));assert(t.n==5 and t[1]==14 and t[5]==nil)
local a,b,c,d,e=external3('wide',nil,false);assert(a==13 and b==nil and c==false and d==33 and e==nil)
local function inside(a,b,c)return a,b,c end
local a,b,c=inside(7,nil,false);assert(a==7 and b==nil and c==false)
local function none()end;local function one()return nil end
local function two()return false,nil end
assert(select('#',none())==0 and select('#',one())==1 and select('#',two())==2)
local function mark(x)trace[#trace+1]='mark'..x;return x end
local function identity(...)return ...end
local a,b,c=identity(mark(1),mark(2),mark(3));assert(a==1 and b==2 and c==3)
local held;local function get()return held end
local function mutate(a,b,c)held=c;return get(),b,a end
local a,b,c=mutate(9,nil,false);assert(a==false and b==nil and c==9 and get()==false)
local object=setmetatable({},{__call=function(self,...)return select('#',...),...end})
local n,a,b,c=object(1,nil,false);assert(n==3 and a==1 and b==nil and c==false)
local up=0;local function rec(n)if n==0 then return up end;up=up+1;return rec(n-1)end
assert(rec(12)==12)
local ok,e=pcall(function()external0();error('expected',0)end);assert(not ok and e=='expected')
local ok,e=xpcall(function()error('xpcall',0)end,function(e)return e end);assert(not ok and e=='xpcall')
print(table.concat(trace,'|'),up)'''])
    return '\n'.join(lines)


def build(source,version,backend,enabled,extra=None,passes=()):
    random.seed(519);config=options(backend);config.update(extra or {})
    vm=VMPass(target=TargetProfile(version,backend),vm_options=config,vm_output_passes=list(passes))
    if enabled:return vm.run(source)
    with patch('obfuscator.vm.call_arity.classic_calls',lambda source,*a,**kw:source):
        return vm.run(source)


def security_checks(version,backend):
    lines=['PANICFN=function()KARITY_PANIC()end']
    for n in range(4):
        call='host('+','.join(('7','nil','false')[:n])+')'
        lines.append(('local '+','.join('r'+str(i) for i in range(n))+'=' if n else '')+call)
        lines.append('MARKER=MARKER+1')
    lines.append('probe()')
    source='\n'.join(lines)
    observations=[]
    for enabled in (False,True):
        output=build(source,version,backend,enabled,passes=('strip_info','rename_obf','minify'))
        rows=[]
        for event in ('api','panic','hook','callable'):
            for index in range(1,5):
                mutation=("pcall(PANICFN)" if event=='panic' else
                          "debug.sethook(function()end,'',100)" if event=='hook' else
                          "string.byte=function()return 0 end")
                setup=(f'MARKER=0;PROBED=false;local n=0;host=function(...)n=n+1;if n=={index} then {mutation} end;return 7,nil,false end;'
                       'probe=function()PROBED=true end')
                if event=='callable':setup+=';local f=host;host=setmetatable({},{__call=function(_,...)return f(...)end})'
                call=b'local ok=pcall(assert((loadstring or load)(source)));debug.sethook();return ok,MARKER,PROBED'
                result=run(version,output,setup.encode(),call)
                assert result[0] is False and result[2] is False,(version,backend,event,index,result)
                rows.append(result)
        observations.append(rows)
    assert observations[0]==observations[1],(version,backend,'guard timing changed',observations)
    print('fixed-arity-guards-ok',version,backend,flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--lua',nargs='+',default=['5.1','5.3'])
    parser.add_argument('--backends',nargs='+',default=['classic','mov','karity','bare'])
    parser.add_argument('--security-only',action='store_true');args=parser.parse_args()
    source=matrix_source()
    lifetime=('drop1((maker()));drop2(nil,(maker()));drop3(nil,(maker()),false);'
              'local function tail()return drop1((maker()))end;tail();print("roots-ok")')
    for version in args.lua:
        for backend in args.backends:
            if args.security_only:
                security_checks(version,backend);continue
            # Bare already uses direct Lua calls; its existing temporary roots
            # are released after CALL rather than during the native callee.
            roots=("local function f()external0((maker()))end;f();collectgarbage('collect');"
                   "collectgarbage('collect');assert(weak[1]==nil);print('roots-ok')") if backend=='bare' else lifetime
            for name,code in (('matrix',source),('lifetime',roots)):
                expected=execute(SETUP+code,version)[0]
                for enabled in (False,True):
                    output=build(code,version,backend,enabled)
                    actual=execute(SETUP+output,version)[0]
                    assert actual==expected,(version,backend,name,enabled,actual,expected)
                print('fixed-arity-ok',version,backend,name,flush=True)
            for synthesis in ((False,) if backend=='bare' else (False,True)):
                config={'integrity_constants':True,'integrity_constant_rate':1.0}
                if backend!='bare':
                    config.update(opcode_synthesis=synthesis,synthesis_policy='protection',vm_count=2)
                if backend in ('classic','karity'):
                    config.update(opcode_fusion=not synthesis,mutate_handlers=True)
                if backend=='karity':
                    config.update(graph_execution_rate=.4,cross_instruction_rate=.5,
                        runtime_polymorphism_rate=.5,argument_virtualization=True,
                        upvalue_virtualization=True,table_virtualization=True,
                        semantic_state_threading=True,branch_virtualization=True)
                protected_source=source+'\n'+roots if backend in ('classic','mov') else source
                expected=execute(SETUP+protected_source,version)[0]
                for enabled in (False,True):
                    output=build(protected_source,version,backend,enabled,config,('strip_info','rename_obf','minify'))
                    try:actual=execute(SETUP+output,version)[0]
                    except Exception as error:
                        # Legacy 5.1 CFF can retain an old native result packet.
                        # Still compare its values/effects against native Lua;
                        # the optimized combined case must pass the strict GC
                        # oracle below, rather than inherit that retention.
                        if (enabled or version!='5.1' or backend!='classic'
                                or 'argument retained' not in str(error)):raise
                        baseline=build(source,version,backend,False,config,('strip_info','rename_obf','minify'))
                        assert execute(SETUP+baseline,version)[0]==execute(SETUP+source,version)[0]
                        print('fixed-arity-baseline-gc-retention',version,backend,synthesis,flush=True)
                        continue
                    assert actual==expected,(version,backend,synthesis,enabled)
                print('fixed-arity-protected-ok',version,backend,synthesis,flush=True)
            if backend in ('classic','mov'):
                passes=('strip_info','function_obf','rename_obf','localize_globals',
                        'table_obf','string_encode','minify')
                for code in (source,lifetime):
                    output=build(code,version,backend,True,passes=passes)
                    assert execute(SETUP+output,version)[0]==execute(SETUP+code,version)[0]
                print('fixed-arity-output-passes-ok',version,backend,flush=True)
            security_checks(version,backend)
    return 0


if __name__=='__main__':raise SystemExit(main())
