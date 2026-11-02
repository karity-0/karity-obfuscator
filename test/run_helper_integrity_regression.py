"""External helper manifests and checks of actual execution references."""
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator.vm.helper_integrity import install
from obfuscator.vm.backends.runtime_emitter import _dump_function_stripped
from obfuscator.toolchain import LuaToolchain
from obfuscator import Pipeline, build_pipeline_from_config


def native(script, *arguments):
    with tempfile.TemporaryDirectory() as folder:
        path=Path(folder)/'runner.lua';path.write_text(script,encoding='utf-8',newline='\n')
        return subprocess.run([LuaToolchain().lua(),str(path),*map(str,arguments)],
                              capture_output=True,timeout=60)


class HelperIntegrityTests(unittest.TestCase):
    def test_candidate_shortlist_keeps_shadowing_and_rejects_escaping_references(self):
        from obfuscator.vm.helper_integrity import _candidates
        from obfuscator.passes.ts_utils import parse
        source='''return function(manifest,...)
local function escaped(x)return x end;local alias=escaped
do local function same(x)return x end;same(1) end
do local function same(x)return x end;same(2) end
local function changed(x)return x end;changed=function(x)return x end;changed(3)
local forward;function forward(x)return x end;forward(4)
local function third(x,y)return x~y end;third(1,2)
local function unused(x)return x end
local function unusedEmpty(x)end
return alias
end'''
        ctx=parse(source);candidates=_candidates(ctx)
        self.assertEqual(['same','same','third'],[binding.original for binding,_ in candidates])
        self.assertNotEqual(candidates[0][1].id,candidates[1][1].id)
        self.assertEqual([], _candidates(parse('local function unused(x)return x end')))
        with self.assertRaises(ValueError):_candidates(parse('local ='))

    def test_manifest_tracks_nested_prototypes_and_rejects_structure_changes(self):
        from lupa.lua53 import LuaRuntime
        lua=LuaRuntime(encoding=None,unpack_returned_tuples=True)
        source='''return function(manifest,...)
local function a(x,y)return x~y end
local function b(x)return x end
local functions={function()return function()return 7 end end}
local function make(n)return function()return a(b(n),3) end end
return make(17),functions[1]()
end'''
        output,plan=install(source)
        factory=lua.execute(output.encode())
        dump=lua.eval(b'string.dump')(factory,True)
        manifest=plan.manifest(output,dump)
        first,second=factory(manifest.encode())
        self.assertEqual((18,7),(first(),second()))
        changed=output.replace('return function(manifest,...)',
            'return function(manifest,...) local extra=function()return 1 end;',1)
        with self.assertRaisesRegex(ValueError,'correspondence'):
            plan.manifest(changed,dump)
        changed=output.replace(f'{plan.bank}[{plan.slots[0]}]=',f'{plan.bank}[99999]=',1)
        with self.assertRaisesRegex(ValueError,'target assignment'):
            plan.manifest(changed,dump)

    def test_function_output_keeps_real_helpers_without_runtime_annotations(self):
        from obfuscator.vm.helper_integrity import preserve_function_targets
        from obfuscator.vm.backends.runtime_emitter import _obfuscate_vm_output
        source='''return function(manifest,...)
local text="--[[VM_INTEGRITY_HELPER]]"
local function a(x,y)return x~y end
local function b(x)return x end
return function(n)return a(b(n),3),text end
end'''
        random.seed(1606)
        marked=preserve_function_targets(source)
        transformed,_=_obfuscate_vm_output(marked,['function_obf'])
        # An identical literal is still data; only build-time comments vanish.
        self.assertIn('"--[[VM_INTEGRITY_HELPER]]"',transformed)
        from obfuscator.passes.ts_utils import parse
        from obfuscator.passes.function_obfuscation import _ancestor_nodes
        ctx=parse(transformed)
        self.assertFalse(any(n.type=='comment' and ctx.text(n)=='--[[VM_INTEGRITY_HELPER]]'
            and not any(p.type=='string' for p in _ancestor_nodes(n)) for n in ctx.walk()))
        output,plan=install(transformed)
        manifest=plan.manifest(output,_dump_function_stripped(output,''))
        result=native('local f=assert(loadfile(arg[1]))()(arg[2]);local n,s=f(17);assert(n==18 and s=="--[[VM_INTEGRITY_HELPER]]")',
            self._factory_file(output),manifest)
        self.assertEqual(0,result.returncode,result.stderr)

    def _factory_file(self,source):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        path=Path(folder.name)/'factory.lua';path.write_text(source,encoding='utf8')
        return path

    def test_standalone_cross_checks_reject_each_reference(self):
        # The long loop is generator-owned fixture code, ensuring every sparse
        # checker gets a turn without requiring debug hooks or old VM guards.
        source='''return function(manifest,...)
local function xor(a,b)return a~b end
local function identity(a)return a end
local function work()
local n=0
while n<1200 do n=n+1;'''+('n=n+0;'*180)+'''
end
return xor(identity(17),3)
end
return work
end'''
        random.seed(1606)
        transformed,plan=install(source)
        dumped=_dump_function_stripped(transformed,'')
        manifest=plan.manifest(transformed,dumped)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'factory.lua';path.write_text(transformed,encoding='utf-8',newline='\n')
            checks='''local factory=assert(loadfile(arg[1]))()
local manifest=arg[2]
local function create()
 local work=factory(manifest);assert(work()==18)
 local bank
 for i=1,255 do local name,value=debug.getupvalue(work,i)
  if not name then break end
  if name==arg[3] then bank=value end
 end
 assert(bank,'actual execution bank was not captured')
 return work,bank
end
'''
            for slot in plan.slots:
                result=native(checks+f'''local work,bank=create()
bank[{slot}]=function()return 18 end
local ok,message=pcall(work);assert(not ok and message==nil)
print('reference-rejected')''',path,manifest,plan.bank)
                self.assertEqual(0,result.returncode,result.stderr)
            # A replacement with identical bytecode still has a new identity.
            slot=plan.slots[0]
            result=native(checks+f'''local work,bank=create()
local replacement=assert(load(string.dump(bank[{slot}],true)))
assert(string.dump(replacement,true)==string.dump(bank[{slot}],true))
bank[{slot}]=replacement
assert(not pcall(work));print('same-code-rejected')''',path,manifest,plan.bank)
            self.assertEqual(0,result.returncode,result.stderr)
            result=native(checks+'''local work,bank=create()
setmetatable(bank,{__index=function()return function()return 18 end end})
assert(not pcall(work));print('bank-metatable-rejected')''',path,manifest,plan.bank)
            self.assertEqual(0,result.returncode,result.stderr)
            wrong=('0' if manifest[0]!='0' else '1')+manifest[1:]
            result=native('local f=assert(loadfile(arg[1]))();assert(not pcall(f,arg[2]))',path,wrong)
            self.assertEqual(0,result.returncode,result.stderr)

    def test_standard_64_bit_size_t_dumps(self):
        from lupa.lua53 import LuaRuntime
        lua=LuaRuntime(encoding=None)
        source='return function(manifest,...) local long="'+('a'*300)+'";local function a(x,y)return x~y end;local function b(x)return x end;return function()return a(b(17),3),long end end'
        transformed,plan=install(source)
        factory=lua.execute(transformed.encode())
        dump=lua.eval(b'string.dump')(factory,True)
        self.assertEqual(8,dump[13])
        manifest=plan.manifest(transformed,dump)
        work=factory(manifest.encode())
        self.assertEqual((18,b'a'*300),work())

    def test_real_vm_module_and_packer(self):
        source=('local function bitwork(x)x=~x;x=~x;x=~x;x=~x;x=~x;return x end;assert(bitwork(17)==-18);'
                +(ROOT/'test/fixtures/vm_chunk_interface.lua').read_text(encoding='utf-8'))
        harness=ROOT/'test/fixtures/vm_chunk_interface_harness.lua'
        expected=subprocess.run([LuaToolchain().lua(),str(harness),str(ROOT/'test/fixtures/vm_chunk_interface.lua')],capture_output=True,check=True).stdout
        for index,passes in enumerate((['vm'],['vm','pack'])):
            random.seed(1607+index)
            config={'passes':passes,'signature':{'mode':'none'},
                    'vm_output_passes':['strip_info','rename_obf','string_encode','meme_strings','number_obf','minify'],
                    'literal_mosaic':{'style':'exotic','cost':'high','max_operations':20,
                        'output_cost':{'hot_operations':3,'cold_operations':12}},
                    'packer_output_passes':['minify'], 'vm_options':{
                        'backend':'karity','distributed_integrity':True,'encoded_bitwise':True,
                        'vm_count':2,'fake_handlers':False,'mutate_handlers':False,
                        'junk_instructions':False,'graph_execution_rate':.2 if index==0 else 0,'cross_instruction_rate':.5,
                        'opcode_splitting':False,'opcode_fusion':False,
                        'helper_variant_count':3,'helper_diversity_rate':1,
                        'semantic_state_threading':True,'dispatcher_target_hiding':True,
                        'argument_virtualization':True,'upvalue_virtualization':True,
                        'table_virtualization':True,'branch_virtualization':True,
                        'integrity_constants':True,'integrity_constant_rate':1}}
            from obfuscator.profiling import Profiler
            profiler=Profiler()
            output=build_pipeline_from_config(config,Pipeline,show_header=False).run(source,profiler=profiler)
            self.assertTrue(any(d.get('phase')=='distributed_integrity'
                for record in profiler.records for d in record.details))
            with tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'module.lua';path.write_text(output,encoding='utf-8',newline='\n')
                result=subprocess.run([LuaToolchain().lua(),str(harness),str(path)],capture_output=True,timeout=60)
                self.assertEqual(0,result.returncode,result.stderr[-1800:])
                self.assertEqual(expected,result.stdout)

    def test_options_reject_wrong_target_and_values(self):
        from obfuscator.registry import validate_config, ConfigError, config_warnings
        for option in ('encoded_bitwise','distributed_integrity'):
            with self.assertRaises(ConfigError):
                validate_config({'passes':['vm'],'vm_options':{option:'true'}})
            with self.assertRaises(ConfigError):
                validate_config({'passes':['vm'],'target':{'lua_version':'5.1'},'vm_options':{option:True}})
            self.assertTrue(config_warnings({'passes':['vm'],'vm_options':{'backend':'classic',option:True}}))


if __name__=='__main__':unittest.main()
