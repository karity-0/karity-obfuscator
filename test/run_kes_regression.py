"""KES syntax/native equivalence and VM-only intrinsic contracts."""
from pathlib import Path
import random
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'test'))
from obfuscator.kes import KESError, INTRINSICS, lower_source
from obfuscator.pipeline import Pipeline
from obfuscator.vm.vm_pass import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from tools.explore_vm_semantics import execute,settings


def generated_cases():
    """Independent Python evaluator supplies the oracle for lazy expressions."""
    lines=['local trace={};local function tap(id,value)trace[#trace+1]=id;return value,99 end',
           'local function emit(id,value)print(id,type(value),tostring(value),table.concat(trace,","));trace={} end']
    expected=[];identity=0
    truth=lambda value:value is not None and value is not False
    def spell(value):
        if value is None:return 'nil'
        if type(value) is bool:return 'true' if value else 'false'
        return str(value)
    for seed in range(12):
        rng=random.Random(7139+seed)
        def make(depth):
            nonlocal identity
            if depth==0:
                identity+=1
                return ('tap',identity,rng.choice((None,False,True,0,1,-2,7)))
            op=rng.choice(('coalesce','ternary','and','or'))
            return (op,*(make(depth-1) for _ in range(3 if op=='ternary' else 2)))
        def evaluate(node,trace):
            op=node[0]
            if op=='tap':trace.append(node[1]);return node[2]
            left=evaluate(node[1],trace)
            if op=='ternary':return evaluate(node[2] if truth(left) else node[3],trace)
            if op=='coalesce':return evaluate(node[2],trace) if left is None else left
            if op=='and':return evaluate(node[2],trace) if truth(left) else left
            return left if truth(left) else evaluate(node[2],trace)
        def emit(node):
            op=node[0]
            if op=='tap':return f'tap({node[1]},{spell(node[2])})'
            children=[emit(c) for c in node[1:]]
            return '('+(children[0]+' ? '+children[1]+' : '+children[2] if op=='ternary' else children[0]+' '+('??' if op=='coalesce' else op)+' '+children[1])+')'
        for _ in range(24):
            node=make(3);trace=[];value=evaluate(node,trace);case=len(expected)+1
            kind='nil' if value is None else 'boolean' if type(value) is bool else 'number'
            expected.append(f'{case}\t{kind}\t{spell(value)}\t'+','.join(map(str,trace))+'\n')
            lines.append(f'emit({case},{emit(node)})')
    return '\n'.join(lines),''.join(expected)


def main():
    source=(ROOT/'test/fixtures/kes_syntax.lua').read_text(encoding='utf-8')
    with tempfile.TemporaryDirectory(prefix='karity-kes-') as folder:
        work=Path(folder)
        def run(code,version,tag):
            path=work/(tag+'.lua');path.write_text(code,encoding='utf-8')
            r=execute(path,version)
            assert r['returncode']==0,(tag,r)
            return r['stdout']
        for version in (() if '--intrinsics-only' in sys.argv else ('5.1','5.3')):
            generated,expected=generated_cases()
            assert run(lower_source(generated,version).source,version,'generated-'+version)==expected
            lowered=lower_source(source,version)
            assert lowered.ranges
            assert run(lowered.source,version,'syntax-'+version)=='kes-syntax-ok\t1265\t8\t3\n'
            # Independent Lua equivalent for lazy selection and effect order.
            kes='local t={};local n=0;local function bump()n+=1;return n end;for i=1,5 do if i==2 then continue end;t[#t+1]=(i%2==1 ? false : bump()) ?? 9 end;print(#t,n,t[1],t[2],t[3],t[4])'
            lua='local t={};local n=0;local function bump()n=n+1;return n end;for i=1,5 do if i~=2 then local v;if i%2==1 then v=false else v=bump() end;if v==nil then v=9 end;t[#t+1]=v end end;print(#t,n,t[1],t[2],t[3],t[4])'
            assert run(lower_source(kes,version).source,version,'oracle-kes')==run(lua,version,'oracle-lua')
            if version=='5.3':assert run(lower_source('local n=17;n//=3;print(n)').source,version,'floor')=='5\n'
            else:
                assert run(lower_source('local goto=1;goto+=2;print(goto)','5.1').source,'5.1','goto-name')=='3\n'
            for backend in ('classic','karity','mov'):
                random.seed(124)
                vm=VMPass(vm_options=settings(backend,'minimal',124),target=TargetProfile(lua_version=version,backend=backend))
                output=vm.run(source)
                assert run(output,version,'vm-syntax-'+backend)==run(lowered.source,version,'native-syntax')
                print('kes-syntax-vm-ok',version,backend,flush=True)

        invalid=[('local t={};t.x//=2','5.1'),('local x=1__0','5.3'),('local x=0b102','5.3'),
                 ('local x=0x_FF','5.3'),('continue','5.3'),('local x=a?.[1]','5.3'),
                 ('local n=1_000;for','5.3'),
                 ('local x=KARITY_GET_VM_ID','5.3'),('local KARITY_ABORT=1','5.3'),
                 ('KARITY_GET_VM_ID(1)','5.3'),('KARITY_ASSERT()','5.3'),
                 ('local function f(KARITY_PANIC) end','5.3'),('t.KARITY_ABORT()','5.3')]
        for code,version in invalid:
            try:lower_source(code,version)
            except KESError as error:assert error.line==1 and error.column>0
            else:raise AssertionError(('expected KES error',code))
        for newline in ('\n','\r','\r\n','\n\r'):
            try:lower_source('local s="🌸"'+newline+'local x=1__0')
            except KESError as error:assert (error.line,error.column)==(2,10)
            else:raise AssertionError('missing numeric separator diagnostic')
        plain='-- ?? += continue\nlocal s=[=[0b10 ?. ??=]=];local x=1;print(s,x)\n'
        assert lower_source(plain).source==plain
        plain='local function continue(x) return x end; print(continue(4))'
        assert lower_source(plain).source==plain
        plain="local n=0;local function continue(v)n=n+(type(v)=='table' and v[1] or tonumber(v)) end;continue '3';continue {4};print(n)"
        assert lower_source(plain).source is plain
        for version in ('5.1','5.3'):
            assert run(plain,version,'continue-shorthand')=='7\n'
        # Adding the intrinsic catalog must not reserve failure handlers or
        # perturb alias multiplicity for ordinary source programs.
        from obfuscator.vm.ir.operations import INTRINSIC_OPERATIONS
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                random.seed(124)
                vm=VMPass(vm_options=settings(backend,'minimal',124),target=TargetProfile(lua_version=version,backend=backend))
                output=vm.run('print("plain-ok")')
                assert 'VM execution failed' not in output
                aliases=vm.last_protection_plan.functions[vm.last_semantic_ir.root.id]['alias_requirements']
                assert all(not (dict(entry['operations']).keys() & INTRINSIC_OPERATIONS) for entry in aliases)
                assert run(output,version,'plain-'+backend)=='plain-ok\n'
        vm=VMPass(vm_options=settings('classic','minimal',124))
        assert run(vm.run('goto skip; KARITY_ABORT(); ::skip:: print("dead-ok")'),'5.3','dead-intrinsic')=='dead-ok\n'
        try:Pipeline(show_header=False).run('KARITY_ABORT()')
        except KESError as error:assert 'actual VM' in str(error)
        else:raise AssertionError('intrinsic silently activated VM')

        info='''local __kes_intrinsic_0=123
local ordinary={['KARITY_ABORT']=function()return 12 end}
assert(__kes_intrinsic_0==123 and ordinary['KARITY_ABORT']()==12)
local function read()
local h=KARITY_GET_SCRIPT_HASH();local c=KARITY_GET_VM_COUNT()
local id=KARITY_GET_VM_ID();local layout=KARITY_GET_LAYOUT_HASH()
local length=KARITY_GET_CODE_LENGTH()
KARITY_ASSERT(type(h)=='number' and h>=0 and h<4294967296)
KARITY_ASSERT(c>=1 and id>=0 and id<c)
KARITY_ASSERT(layout>=0 and layout<4294967296 and length>0)
local a,b=KARITY_GET_VM_COUNT();assert(a==c and b==nil)
assert(select('#',KARITY_GET_VM_COUNT())==1)
return h,c,id,layout,length
end
local h,c,id,l,n=read();local h2,c2,id2,l2,n2=read()
assert(h==h2 and c==c2 and id==id2 and l==l2 and n==n2)
local function tail()return KARITY_GET_VM_COUNT() end
assert(select('#',tail())==1 and tail()==c)
local calls=0
local function once()calls=calls+1;return true,nil end
assert(select('#',KARITY_ASSERT(once()))==0 and calls==1)
local weak=setmetatable({}, {__mode='v'})
local function condition_object()local object={};weak[1]=object;return object end
KARITY_ASSERT(condition_object())
collectgarbage('collect');collectgarbage('collect')
assert(weak[1]==nil,'assert condition retained')
print('info-ok')
'''
        abort='''local function good()return 7 end
local function bad()KARITY_ABORT() end
local function never()KARITY_UNREACHABLE() end
local function check(v)KARITY_ASSERT(v);return 9 end
assert(not pcall(bad));assert(good()==7)
assert(not pcall(never));assert(check(0)==9)
assert(not xpcall(bad,function(e)return 'caught' end));assert(good()==7)
assert(not pcall(check,false));assert(not pcall(check,nil));assert(good()==7)
local co=coroutine.create(bad);assert(not coroutine.resume(co));assert(good()==7)
local original_error=error;error=function()return 'ignored' end
local abort_ok=pcall(bad);local assert_ok=pcall(check,false);error=original_error
assert(not abort_ok and not assert_ok)
print('abort-ok')
'''
        panic='''return function()return 7 end,function()KARITY_PANIC() end,
function()local ok=pcall(function()KARITY_PANIC() end);return ok end,
function()return coroutine.yield('paused') end,function(a,b)return a+b+b end
'''
        harness=work/'panic-harness.lua'
        harness.write_text('''local path=arg[1]
local function instance()local chunk=assert(loadfile(path));return chunk() end
local good,panic,caught,wait=instance()
local co=coroutine.create(wait);local ok,v=coroutine.resume(co);assert(ok and v=='paused')
assert(good()==7);assert(not pcall(panic));assert(not pcall(good));assert(not coroutine.resume(co,4))
local fresh,_,inner=instance();assert(fresh()==7);assert(not pcall(inner));assert(not pcall(fresh))
local nextgood=instance();assert(nextgood()==7)
local xgood,xpanic=instance();local ok,msg=xpcall(xpanic,function(e)return 'caught' end)
assert(not ok and msg=='caught');assert(not pcall(xgood))
local cgood,cpanic=instance();local pco=coroutine.create(cpanic)
assert(not coroutine.resume(pco));assert(not pcall(cgood))
local _,mpanic,_,_,apply=instance();local additions=0;local object
object=setmetatable({}, {__add=function()
  additions=additions+1;if additions==1 then pcall(mpanic) end;return object
end})
assert(not pcall(apply,object,object));assert(additions==1)
local egood,epanic=instance();local original_error=error;error=function()return 'ignored' end
local accepted=pcall(epanic);error=original_error;assert(not accepted and not pcall(egood))
print('panic-ok')
''',encoding='utf-8')
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                for mode in ('minimal','protected'):
                    opts=settings(backend,mode,124)
                    for label,code in (('info',info),('abort',abort),('panic',panic)):
                        random.seed(124)
                        vm=VMPass(vm_options=opts,target=TargetProfile(lua_version=version,backend=backend))
                        output=vm.run(code)
                        ir=vm._backend.last_source_ir
                        ops={i.operation for f in ir.functions() for b in f.blocks for i in b.instructions}
                        if label=='info':assert {'GET_SCRIPT_HASH','GET_VM_COUNT','GET_VM_ID','GET_LAYOUT','GET_CODE_LENGTH','VM_ASSERT'}<=ops
                        if label=='panic':assert 'VM_PANIC' in ops
                        if label=='panic':
                            path=work/'panic.lua';path.write_text(output,encoding='utf-8')
                            result=execute(path,version,harness=harness)
                            assert result['returncode']==0 and result['stdout']=='panic-ok\n',(version,backend,mode,result)
                        else:assert run(output,version,label)==label+'-ok\n'
                    print('kes-intrinsics-ok',version,backend,mode,flush=True)
    print('kes-regression-ok')
    return 0


if __name__=='__main__':raise SystemExit(main())
