"""Encoded integer arithmetic must preserve native Lua effects and wrapping."""
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lupa.lua53 import LuaRuntime
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.toolchain import LuaToolchain

OPTIONS = {'backend':'karity', 'fake_handlers':False, 'mutate_handlers':False,
           'junk_instructions':False, 'graph_execution_rate':0, 'cross_instruction_rate':0,
           'runtime_polymorphism_rate':0, 'block_variant_rate':0,
           'helper_variant_count':1, 'helper_diversity_rate':0, 'semantic_diversity_rate':0,
           'blob_form':'string'}

SOURCE = r'''
local words={0,1,-1,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff,0x100000001}
local function multiply(a,b) local c=a*b;return c,math.type(c) end
for i=1,#words do for j=1,#words do print(i,j,multiply(words[i],words[j])) end end
local function square(x) x=x*x;return x end
assert(square(0x100000001)==0x200000001)
local x=11;local function read()return x end;x=x*17;assert(read()==187)
local function operands(a,b) local p=a+b;return p*p end
assert(operands(7,9)==256)
local calls={};local mt={__mul=function(a,b)calls[#calls+1]='mul';return 19 end}
local value=setmetatable({},mt);assert(value*value==19 and #calls==1)
assert(select(2,multiply(2.5,4))=='float')
assert(select(2,multiply('2','3'))=='float')
local n=0.0*-2;assert(n==0 and 1/n==-math.huge)
print('encoded-operations-ok')
'''


def execute(source):
    with tempfile.TemporaryDirectory() as folder:
        path=Path(folder)/'case.lua';path.write_text(source,encoding='utf-8',newline='\n')
        result=subprocess.run([LuaToolchain().lua(),str(path)],capture_output=True,timeout=60)
        assert result.returncode==0,result.stderr[-1600:]
        return result.stdout


class EncodedOperationsTests(unittest.TestCase):
    def test_masked_integer_circuits_against_native_int64(self):
        source=(ROOT/'obfuscator/vm/runtimes/karity_integer.lua').read_text(encoding='utf-8')
        lua=LuaRuntime()
        probe=lua.execute('local _RX,_RZ={},17;local function _rmix(x)return (x~(x>>17))*-7046029254386353131 end;'+source+r'''
return function(a,b,c,d)
  local x,y=_eadd(a,b,c,d);assert(x~y==(a~b)+(c~d),'add')
  x,y=_esub(a,b,c,d);assert(x~y==(a~b)-(c~d),'sub')
  x,y=_emul(a,b,c,d);assert(x~y==(a~b)*(c~d),'mul')
  x,y=_eult(a,b,c,d);assert((x~y)==(((a~b)~math.mininteger)<((c~d)~math.mininteger) and 1 or 0),'ult')
  x,y=_eshift(a,b,c,d,false);assert(x~y==(a~b)<<(c~d),'shl')
  x,y=_eshift(a,b,c,d,true);assert(x~y==(a~b)>>(c~d),'shr')
  if (c~d)~=0 then
    x,y=_edivmod(a,b,c,d,false);assert(x~y==(a~b)//(c~d),'idiv')
    x,y=_edivmod(a,b,c,d,true);assert(x~y==(a~b)%(c~d),'mod')
  end
  assert(_eaffine(a,b,c,d)==c*(a~b)+d,'affine')
end''')
        rng=random.Random(1620)
        def signed(x):return (x+(1<<63))%(1<<64)-(1<<63)
        values=(0,1,-1,-64,63,64,65,-65,-(1<<63),(1<<63)-1)
        for a in values:
            for b in values:
                m,n=(signed(rng.getrandbits(64)) for _ in range(2))
                probe(signed(a^m),m,signed(b^n),n)
        for _ in range(160):probe(*(signed(rng.getrandbits(64)) for _ in range(4)))
        accessor_probe=lua.execute('local boxes={{get=function()error("accessor was probed")end}};'+source+
                                  'return function()assert(_ebit_snapshot(1)==nil)end')
        accessor_probe()

    def test_default_policy_and_general_path_elision(self):
        from obfuscator.vm.vm_pass import VMBuildPipeline
        for backend in ('karity','classic','mov','bare'):
            for version in ('5.1','5.3'):
                pipeline=VMBuildPipeline(target=TargetProfile(version,backend))
                for option in ('encoded_bitwise','distributed_integrity'):
                    self.assertEqual(backend=='karity' and version=='5.3',bool(pipeline.vm_options.get(option)))
        for option in ('encoded_bitwise','distributed_integrity'):
            pipeline=VMBuildPipeline(vm_options={option:False})
            self.assertIs(pipeline.vm_options[option],False)
        source='local a,b=17,39;local c=a~b;c=(c<<-2)|b;print(c,c//-7,c%-7,c<a,c==b,c<=b,a*b,-a,~b)'
        random.seed(1621)
        vm=VMPass(vm_options={**OPTIONS,'opcode_splitting':False,'opcode_fusion':False},vm_output_passes=['minify'])
        output=vm.run(source)
        self.assertEqual(execute(source),execute(output))
        data=vm.last_lowered_ir.backend_data
        self.assertTrue(data['integer_proof_events'])
        self.assertTrue(all(event['outcome']=='elided' for event in data['integer_proof_events']))
        removed=set(data['runtime_emission']['removed_helpers'])
        self.assertTrue({'_arith2','_arith1','_arith2r','_arith1r'}<=removed,removed)
        random.seed(1621)
        dynamic='local function f(a,b)return a+b,a~b,a//b end;print(f(17,3))'
        vm=VMPass(vm_options={**OPTIONS,'opcode_splitting':False,'opcode_fusion':False},vm_output_passes=['minify'])
        output=vm.run(dynamic)
        self.assertEqual(execute(dynamic),execute(output))
        self.assertTrue(any(e['outcome']=='retained' for e in vm.last_lowered_ir.backend_data['integer_proof_events']))
        self.assertNotIn('_arith2r',vm.last_lowered_ir.backend_data['runtime_emission']['removed_helpers'])
        from obfuscator.vm.backends import get_backend
        lowered=vm.last_lowered_ir
        saved=lowered.backend_data['integer_aliases']
        vop=next(e['vop'] for e in lowered.backend_data['integer_proof_events'] if e['outcome']=='retained')
        lowered.backend_data['integer_aliases']=(saved[0]|{vop},)
        with self.assertRaisesRegex(ValueError,'whole-program proofs'):
            get_backend('karity').validate_lowered(lowered)
        lowered.backend_data['integer_aliases']=saved

    def test_extended_operations_in_actual_runtime(self):
        source=r'''
local words={0,1,-1,63,64,-65,0x7fffffffffffffff,0x8000000000000000,0x123456789abcdef}
local function work(a,b)
  local x,y=a<<b,a>>b
  local q,r=0,0
  if b~=0 then q=a//b;r=a%b end
  return x,y,q,r,a<b,a<=b,a==b,math.type(q)
end
for i=1,#words do for j=1,#words do print(i,j,work(words[i],words[j])) end end
print(work(17.0,3.0));print(work('17','3'))
local calls={};local mt={}
for _,name in ipairs({'__shl','__shr','__idiv','__mod'}) do
  mt[name]=function(a,b)calls[#calls+1]=name;return 7 end
end
local t=setmetatable({},mt)
assert(t<<3==7 and t>>3==7 and t//3==7 and t%3==7)
print(table.concat(calls,','))
for _,modulo in ipairs({false,true}) do
  local ok,err=pcall(function()if modulo then return words[1]%0 else return words[1]//0 end end)
  assert(not ok and tostring(err):find(modulo and "n%%0" or 'divide by zero'))
end
local x=17;local function see()return x end
x=x<<2;assert(see()==68);x=x//-7;assert(see()==-10);x=x%-3;assert(see()==-1)
x='17';x=x|3;assert(see()==19);x=~x;assert(see()==-20)
local co=coroutine.create(function(a) a=~a;coroutine.yield(a,nil);a=(a<<-3)~7;return a,nil end)
local ok,a,b=coroutine.resume(co,17);assert(ok and a==~17 and b==nil)
ok,a,b=coroutine.resume(co);assert(ok and a==((~17)<<-3)~7 and b==nil)
print('extended-operations-ok')
'''
        expected=execute(source)
        for seed,extra in ((1622,{'opcode_splitting':False,'opcode_fusion':False}),
                (1623,{'graph_execution_rate':.6,'cross_instruction_rate':1,
                       'block_variant_rate':.2,'semantic_state_threading':True,
                       'upvalue_virtualization':True,
                       'helper_variant_count':3,'helper_diversity_rate':1,'vm_count':2}),
                (1624,{'opcode_synthesis':True,'synthesis_policy':'protection'})):
            random.seed(seed)
            vm=VMPass(vm_options={**OPTIONS,**extra},vm_output_passes=['minify'])
            self.assertEqual(expected,execute(vm.run(source)),seed)

    def test_multiply_uses_encoded_operands_and_handles_aliases(self):
        template=(ROOT/'obfuscator/vm/vm.lua').read_text(encoding='utf-8')
        body=template[template.index('    local function _elinear2('):template.index('    local function _elinear1(')]
        lua=LuaRuntime()
        probe=lua.execute('''local boxes,_PD,regs,_RS,_RE,_RT={},{},{},{},{},{}
local params={};local writes=0
local function _rpositions(i)return i,i,i,i end
local function _rpos(_,i)return i end
local function _pending_finish()error('unexpected pending')end
local function _rparams(i,epoch)return params[i][1],params[i][2],params[i][3]end
local function _rnext()return 17 end
local function _rstore(i,value,epoch,kind)
  writes=writes+1;regs[i],_RS[i],_RE[i],_RT[i]=value,0,epoch,kind
end
''' + body + '''return function(a,b,la,lb,li,ra,rb,ri,oa,ob,oi,dst)
params[1]={la,lb,li};params[2]={ra,rb,ri};params[3]={oa,ob,oi}
regs[1],_RS[1],_RE[1],_RT[1]=la*a+lb-93,93,7,1
regs[2],_RS[2],_RE[2],_RT[2]=ra*b+rb+51,-51,8,1
local expected=a*b
assert(_elinear2(dst,1,2,0))
local p=params[dst];assert((regs[dst]-p[2])*p[3]==expected)
return writes
end''')
        rng=random.Random(1600)
        def signed(x):return (x+(1<<63))%(1<<64)-(1<<63)
        for index in range(256):
            coeffs=[rng.getrandbits(64)|1 for _ in range(3)]
            values=[rng.getrandbits(64) for _ in range(5)]
            a,b,lb,rb,ob=map(signed,values)
            la,ra,oa=coeffs
            args=[a,b,signed(la),lb,signed(pow(la,-1,1<<64)),
                  signed(ra),rb,signed(pow(ra,-1,1<<64)),
                  signed(oa),ob,signed(pow(oa,-1,1<<64))]
            for dst in (1,2,3):
                probe(*args,dst)

    def test_native_emitted_arithmetic_and_fallbacks(self):
        expected=execute(SOURCE)
        for seed,extra in ((1600,{}),(1601,{'graph_execution_rate':.4,
                'semantic_state_threading':True,'cross_instruction_rate':1,
                'helper_variant_count':3,'helper_diversity_rate':1,
                'runtime_polymorphism_rate':.4}),
                (1602,{'opcode_synthesis':True,'synthesis_policy':'protection'})):
            random.seed(seed)
            vm=VMPass(target=TargetProfile('5.3','karity'),
                      vm_options={**OPTIONS,**extra},vm_output_passes=['minify'])
            output=vm.run(SOURCE)
            self.assertEqual(expected,execute(output),seed)
            state=vm.last_lowered_ir.backend_data['karity_state']
            if not extra.get('opcode_synthesis'):
                self.assertTrue(any(t.operation=='MUL' and t.encoded_fast_path
                                    for f in state.functions for t in f.transitions),seed)


    def test_selected_boolean_regions_and_native_boundaries(self):
        source = r"""
local function work(a,b)
  a=a~b;a=~a;a=a&b;a=a|b;a=a~b
  return a
end
for i=1,32 do print(work(i*17,0x123456789abcdef)) end
local function closed(a,b)
  a=a~b;a=~a;a=a&b;a=a|b;a=a~b
  return function()return a end
end
assert(closed(17,39)()==work(17,39))
assert(work(17.0,39.0)==work(17,39))
local calls=0;local mt={}
mt.__bxor=function(a,b)calls=calls+1;return 19 end
local t=setmetatable({},mt)
assert(work(t,39)==work(19~39,39) or calls==1)
print('boolean-region-ok',calls)
"""
        # Metamethod operands return an integer after their first operation;
        # subsequent steps still obey the exact source operator order.
        expected=execute(source)
        for seed,extra in ((1603,{}),(1604,{'helper_variant_count':3,'helper_diversity_rate':1,
                'runtime_polymorphism_rate':.4,'cross_instruction_rate':1,
                'upvalue_virtualization':True,
                'semantic_state_threading':True,'vm_count':2})):
            random.seed(seed)
            vm=VMPass(target=TargetProfile('5.3','karity'), vm_options={
                **OPTIONS,**extra,'encoded_bitwise':True,
                'opcode_splitting':False,'opcode_fusion':False},vm_output_passes=['minify'])
            output=vm.run(source)
            self.assertEqual(expected,execute(output),seed)
            state=vm.last_lowered_ir.backend_data['karity_state']
            self.assertTrue(any(state.bitwise_aliases),seed)
            self.assertTrue(any(t.pending_guard==('all-inputs-integer-kind','selected-bitwise-region')
                                for f in state.functions for t in f.transitions))


    def test_boolean_packets_are_reused_in_emitted_runtime(self):
        from unittest.mock import patch
        from obfuscator.vm.backends import karity_integer
        original=karity_integer.prepare_runtime
        def instrument(source,lowered):
            source=original(source,lowered)
            old='if packet and packet[1]==false then return packet[2],packet[3] end'
            assert source.count(old)==1
            source=source.replace(old,"if packet and packet[1]==false then _G.__bit_reuses=(_G.__bit_reuses or 0)+1;return packet[2],packet[3] end")
            return source
        source='local function f(a) a=~a;a=~a;a=~a;a=~a;a=~a;return a end;for i=1,30 do assert(f(i)==-(i+1)) end;assert((_G.__bit_reuses or 0)>0);print("packets-reused")'
        random.seed(1610)
        with patch.object(karity_integer,'prepare_runtime',instrument):
            vm=VMPass(target=TargetProfile('5.3','karity'),vm_options={
                **OPTIONS,'encoded_bitwise':True,'opcode_splitting':False,'opcode_fusion':False},
                vm_output_passes=['minify'])
            output=vm.run(source)
        self.assertIn(b'packets-reused',execute(output))


    def test_boolean_packet_consumed_by_active_graph(self):
        from unittest.mock import patch
        from obfuscator.vm.protection import ProtectionPlanner
        original=ProtectionPlanner.build
        def plan_with_boolean_regions(planner,ir):
            plan=original(planner,ir)
            for function in ir.functions():
                for block in function.blocks:
                    for instruction in block.instructions:
                        if instruction.operation in {'BIT_AND','BIT_OR','BIT_XOR','BIT_NOT'}:
                            plan.instructions[instruction.id]['graph_family']=0
            return plan
        source='local function f(a,b)a=~a;a=~a;a=~a;a=~a;a=~a;return a*b end;for i=1,30 do assert(f(i,3)==-(i+1)*3) end;print("boolean-graph-ok")'
        random.seed(1612)
        with patch.object(ProtectionPlanner,'build',plan_with_boolean_regions):
            vm=VMPass(target=TargetProfile('5.3','karity'),vm_options={
                **OPTIONS,'encoded_bitwise':True,'opcode_splitting':False,'opcode_fusion':False,
                'graph_execution_rate':1,'semantic_state_threading':True,
                'helper_variant_count':3,'helper_diversity_rate':1},vm_output_passes=['minify'])
            output=vm.run(source)
        state=vm.last_lowered_ir.backend_data['karity_state']
        self.assertTrue(any(state.bitwise_aliases))
        self.assertTrue(any(t.operation=='MUL' and t.graph_descriptors and t.graph_descriptors[0][0]>0
                            for f in state.functions for t in f.transitions))
        self.assertEqual(execute(source),execute(output))


if __name__=='__main__':unittest.main()
