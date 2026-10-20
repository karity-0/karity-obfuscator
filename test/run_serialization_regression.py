"""Compact handler ABI: exact operands, metadata, constants and integrity."""
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm.backends import handler_codec as codec
from obfuscator.vm.backends.handler_ir import HandlerFunction, HandlerInstruction, HandlerUpvalue
from obfuscator.vm.backends.handler_layout import PhysicalFunction, PhysicalInstruction
from obfuscator.vm.vm_variants import make_instr_layout


def reader_source(version, *, compressed=False, layout=None):
    path = ROOT / ('obfuscator/vm/vm.lua' if version == '5.3' else 'obfuscator/vm/runtimes/lua51/vm.lua')
    source = path.read_text(encoding='utf-8')
    if compressed:
        from obfuscator.vm.synthesis.storage import prepare_reader,MAGIC
        source=prepare_reader(source,MAGIC,layout or codec.DEFAULT_INSTR_LAYOUT)
    primitives = source.split('--<<TARGET_READER_PRIMITIVES>>', 1)[1].split('--<<ENDTARGET_READER_PRIMITIVES>>', 1)[0]
    proto = source.split('local function read_proto(r, acc_state)', 1)[1].split('--<<TARGET_INTEGRITY_MIX>>', 1)[0]
    # Isolate storage decoding from instruction/key masking. Complete protected
    # VM execution is exercised below and by the backend/word regressions.
    xor = source.split('--<<TARGET_INSTRUCTION_XOR>>', 1)[1].split('--<<ENDTARGET_INSTRUCTION_XOR>>', 1)[0]
    helpers = '''local function _ksm(i) return 0 end
    local function _kss(s) return s end
    local _SH_A,_SH_B,_SH_C,_SH_V=32,23,14,40
    local _MASK_OV=0xFF000000007F
    local CTAG_NIL,CTAG_BOOL,CTAG_INT,CTAG_FLOAT,CTAG_STR,CTAG_IEXPR=0,1,2,3,4,5
    local CK_NIL,CK_BOOL,CK_INT,CK_FLOAT,CK_STR,CK_IEXPR=0,1,2,3,4,5
    '''
    return primitives + xor + helpers + 'local function read_proto(r, acc_state)' + proto


def harness(version, layout=None, *, compressed=False):
    source = reader_source(version,compressed=compressed,layout=layout)
    if layout:
        from obfuscator.vm.vm_variants import apply_instr_layout
        source = apply_instr_layout(source, layout)
    source += '''return function(blob,kind,n)
        local r=make_reader(blob)
        if kind=="uint" then return r.uint() end
        if kind=="metadata" then return r.metadata(n,false) end
        if kind=="storage" then
            local get=r.scode(n);local result={}
            for i=1,n do result[i]=get(i) end
            return result
        end
        r.header()
        local seed=r.u16();local layout_hash=r.u32();local vm_count=r.u16()
        for i=1,r.uint() do
            local tag=r.u8()
            if tag==1 then r.u8() elseif tag==2 then r.i64()
            elseif tag==3 then r.f64() elseif tag==4 then r.str()
            elseif tag==5 then
                r.u64();for j=1,r.u8() do if r.u8()==1 then r.u32() end end
            end
        end
        return read_proto(r,{seed,0}),seed,layout_hash,vm_count
    end'''
    runtime = (Lua51 if version == '5.1' else Lua53)(encoding=None)
    return runtime.execute(source.encode())


def fixture():
    def make(name, count, dense_av, dense_graph):
        code = []
        for index in range(count):
            avalanche = (1, 2) if dense_av else ()
            graph = ((0 if index==0 else 8, 0xFFFFFFFF-index, 0xFFFFFFFE-index, 0xFFFF, 0 if index==0 else 3),) if dense_graph or index in (0, 130, count-1) else ()
            raw = HandlerInstruction(0, index % 256, 511-index % 128, 256+index % 128)
            code.append(PhysicalInstruction(raw, 32767-index, avalanche, graph, index))
        source = HandlerFunction(name, 0, 1, 4, [i.instruction for i in code],
                                 [None, False, True, -2**63, 2**63-1, -0.0, 1.25,
                                  b'', b'\0\xff'+('中文😀'*30).encode(), -2147483647],
                                 [HandlerUpvalue(1, 0)], [])
        return PhysicalFunction(source, 0, code, [[1, count]], {9}, False, [])
    root = make('root', 200, True, False)
    child = make('child', 150, False, True)
    leaf_source = HandlerFunction('leaf', 0, 0, 2, [], [], [], [])
    leaf = PhysicalFunction(leaf_source, 0, [], [], set(), False, [])
    child.children = [leaf]
    child.source.protos = [leaf.source]
    root.children = [child]
    root.source.protos = [child.source]
    return root


class Serialization(unittest.TestCase):
    def test_synthesis_words_restore_every_bit_across_layouts(self):
        from obfuscator.vm.synthesis.storage import restore,_pack,read_words
        for seed in range(100):
            random.seed(seed);layout=make_instr_layout()
            fields=[random.getrandbits(26) for _ in range(4)]
            words=b''.join(restore(fields[i%4],random.getrandbits(22),layout).to_bytes(6,'little') for i in range(200))
            packed,blocks=_pack(words,((2,96),(101,96)),layout)
            self.assertTrue(blocks)
            self.assertEqual(words,read_words(codec.BinReader(packed),200,layout=layout))
            if seed<4:
                expected=[int.from_bytes(words[i:i+6],'little') for i in range(0,len(words),6)]
                for version in ('5.1','5.3'):
                    actual=harness(version,layout,compressed=True)(packed,b'storage',200)
                    self.assertEqual(expected,list(actual.values()))

    def test_synthesis_dictionary_rejects_malformed_input(self):
        from obfuscator.vm.synthesis.storage import read_words
        prefix=b'\1\1'+bytes(4)+b'\1\1\3'
        valid=prefix+(b'\1'+bytes(3))*3
        readers=[harness(version,compressed=True) for version in ('5.1','5.3')]
        malformed=(b'\2',b'\1\0',b'\1\1\0\0\0\4',
            prefix[:-2]+b'\0\3',prefix[:-1]+b'\2',prefix[:-1]+b'\4',
            prefix+b'\0'+bytes(3),prefix+b'\1\0\0\x40',valid[:-1])
        for data in malformed:
            with self.assertRaises(ValueError):read_words(codec.BinReader(data),3)
            for reader in readers:
                with self.assertRaises(Exception):reader(data,b'storage',3)

    def test_synthesis_storage_nested_protos_rng_and_integrity(self):
        from types import SimpleNamespace
        function=fixture()
        function.code=[PhysicalInstruction(HandlerInstruction(0,i%4,128+i%4,256+i%4),
            i%32768,(i%255,),((8,1000+i,0xABCDEF00+i,0x1234,3),),i) for i in range(2000)]
        function.synthesis=tuple(SimpleNamespace(start=i,recipe=SimpleNamespace(steps=range(4))) for i in range(0,2000,4))
        for version in ('5.1','5.3'):
            random.seed(174);layout=make_instr_layout();state=random.getstate()
            legacy=codec.serialize(function,layout=layout,compact_synthesis=False);expected_rng=random.getstate()
            random.setstate(state);stats={};compact=codec.serialize(function,layout=layout,stats=stats)
            self.assertEqual(expected_rng,random.getstate())
            self.assertEqual(b'KVM\3',compact[:4]);self.assertLess(len(compact),len(legacy))
            def snapshot(value):
                if hasattr(value,'items'):return sorted([(key,snapshot(v)) for key,v in value.items()],key=lambda row:repr(row[0]))
                return value
            before=harness(version,layout)(legacy,b'proto',0)[0]
            after=harness(version,layout,compressed=True)(compact,b'proto',0)[0]
            self.assertEqual(snapshot(before),snapshot(after))
            # Sparse/dense metadata and appended MOV data retain their offsets
            # through the format-aware integrity walker.
            patched_legacy=codec.patch_integrity_sources(legacy+b'MOV-extension',123,456)
            patched_compact=codec.patch_integrity_sources(compact+b'MOV-extension',123,456)
            self.assertTrue(patched_compact.endswith(b'MOV-extension'))
            before=harness(version,layout)(patched_legacy,b'proto',0)[0]
            after=harness(version,layout,compressed=True)(patched_compact,b'proto',0)[0]
            self.assertEqual(snapshot(before),snapshot(after))

    def test_uint32_boundaries_and_native_readers(self):
        probes = {0:b'\0', 127:b'\x7f', 128:b'\x80\x01', 16383:b'\xff\x7f',
                  16384:b'\x80\x80\x01', 0xFFFFFFFF:b'\xff\xff\xff\xff\x0f'}
        readers = [harness(version) for version in ('5.1', '5.3')]
        for value, encoded in probes.items():
            writer = codec.Writer(); writer.uint(value)
            self.assertEqual(encoded, writer.data())
            self.assertEqual(value, codec.BinReader(encoded).uint())
            for read in readers:
                self.assertEqual(value, read(encoded, b'uint', 0))
        for value in (-1, 2**32, True):
            with self.assertRaises(ValueError): codec.Writer().uint(value)

    def test_malformed_values_fail_boundedly_on_both_targets(self):
        readers = [harness(version) for version in ('5.1', '5.3')]
        for encoded in (b'', b'\x80', b'\x80\0', b'\xff'*5, b'\x80'*5+b'\0', b'\xff'*4+b'\x10'):
            with self.assertRaises(ValueError): codec.BinReader(encoded).uint()
            for read in readers:
                with self.assertRaises(Exception): read(encoded, b'uint', 0)
        for encoded in (b'\x03', b'\x02\x02', b'\x02\x01\0\x01\x04', b'\x02\x01\x03\x01\x04'):
            with self.assertRaises(ValueError): codec._skip_metadata(codec.BinReader(encoded), 2, 1)
            for read in readers:
                with self.assertRaises(Exception): read(encoded, b'metadata', 2)

    def test_metadata_modes_choose_actual_encoded_size(self):
        for values, mode in (([()]*200,0), ([(0,)]*200,1),
                             ([(1,)]+[()]*129+[(2,)]+[()]*68+[(3,)],2),
                             ([(),(7,),()],1)):
            writer=codec.Writer();codec._write_metadata(writer,values,'avalanche')
            self.assertEqual(mode,writer.data()[0])
            reader=codec.BinReader(writer.data());codec._skip_metadata(reader,len(values),1)
            self.assertEqual(len(writer.data()),reader._pos)
            for version in ('5.1','5.3'):
                decoded=harness(version)(writer.data(),b'metadata',len(values))
                for index,slots in enumerate(values,1):
                    self.assertEqual(list(slots),list(decoded[index].values()) if decoded[index] else [])

    def test_all_fields_nested_prototypes_and_binary_constants(self):
        function=fixture()
        for seed in range(6):
            random.seed(seed);layout=make_instr_layout();stats={}
            blob=codec.serialize(function,layout=layout,stats=stats)
            self.assertEqual(len(blob),sum(stats['section_bytes'].values()))
            self.assertEqual(6*350,stats['section_bytes']['instructions'])
            self.assertEqual({'avalanche:dense','avalanche:absent','graph_sites:sparse',
                              'graph_sites:dense','graph_sites:absent'},set(stats['metadata_modes']))
            for version in ('5.1','5.3'):
                decoded,_,_,_=harness(version,layout)(blob,b'proto',0)
                def check(expected,actual):
                    self.assertEqual(len(expected.code),len(actual[b'code']))
                    for index,item in enumerate(expected.code,1):
                        word=int(actual[b'code'][index])
                        for name,width,value in (('A',8,item.instruction.a),('B',9,item.instruction.b),
                                                 ('C',9,item.instruction.c),('V',8,item.vop>>7)):
                            self.assertEqual(value,(word>>layout[name])&((1<<width)-1))
                        self.assertEqual(item.vop&127,word&127)
                        av=actual[b'avalanche'][index]
                        self.assertEqual(list(item.avalanche),list(av.values()) if av else [])
                        sites=actual[b'graph_sites'][index]
                        for j,descriptor in enumerate(item.graph_sites,1):
                            self.assertEqual(list(descriptor),list(sites[j].values()))
                    if expected.source.constants:
                        from obfuscator.vm.string_storage import decode
                        self.assertEqual(b'',decode(actual[b'constants'][8][2]))
                        self.assertEqual(expected.source.constants[8],decode(actual[b'constants'][9][2]))
                        self.assertEqual([1,len(expected.code)],list(actual[b'block_routes'][1].values()))
                        self.assertEqual(1,actual[b'upvalues'][1][b'instack'])
                    for i,child in enumerate(expected.children,1):check(child,actual[b'protos'][i])
                check(function,decoded)

    def test_integrity_patch_preserves_metadata_and_appended_extension(self):
        random.seed(441)
        function=fixture();blob=codec.serialize(function)+b'MOV\x0bextension'
        changed=codec.patch_integrity_sources(blob,0xFEDCBA98,0xFFFFFFFF)
        self.assertEqual(len(blob),len(changed))
        self.assertTrue(changed.endswith(b'MOV\x0bextension'))
        read=harness('5.3')
        before,seed,layout_hash,vm_count=read(blob,b'proto',0)
        after,_,_,_=read(changed,b'proto',0)
        for original,patched in ((before,after),(before[b'protos'][1],after[b'protos'][1])):
            self.assertEqual(list(original[b'code'].values()),list(patched[b'code'].values()))
            for name in (b'avalanche', b'graph_sites', b'block_routes'):
                for index,value in original[name].items():
                    if name==b'graph_sites':
                        self.assertEqual([list(v.values()) for v in value.values()],
                                         [list(v.values()) for v in patched[name][index].values()])
                    else:self.assertEqual(list(value.values()),list(patched[name][index].values()))
            encoded=patched[b'constants'][10][2]
            program=[(item[1],item[2]) for item in patched[b'constants'][10][3].values()]
            sources=codec._integrity_sources(seed,{'layout_hash':layout_hash,'vm_count':vm_count,
                                                   'script_hash':0xFEDCBA98,'line_state':0xFFFFFFFF},len(patched[b'code']),0)
            self.assertEqual(-2147483647,encoded ^ codec._eval_integrity_program(program,sources))
        with self.assertRaisesRegex(ValueError,'unsupported'):
            codec.patch_integrity_sources(b'KVM\x01'+blob[4:],1,2)
        with self.assertRaises(ValueError):codec.patch_integrity_sources(blob[:30],1,2)

    def test_six_byte_words_retain_all_random_layouts_and_padding(self):
        raw=HandlerInstruction(0,255,511,511)
        for seed in range(100):
            random.seed(seed);layout=make_instr_layout()
            writer=codec.Writer(layout);writer.instr(raw,127,255)
            self.assertEqual(6,len(writer.data()))
            word=int.from_bytes(writer.data(),'little')
            used=127
            for name,width in (('A',8),('B',9),('C',9),('V',8)):
                self.assertEqual((1<<width)-1,(word>>layout[name])&((1<<width)-1))
                used|=((1<<width)-1)<<layout[name]
            self.assertEqual(41,used.bit_count())
        with self.assertRaises(ValueError):codec.Writer({'A':48,'B':23,'C':14,'V':40})

    def test_protected_vm_round_trips_all_backends_and_targets(self):
        from obfuscator.vm.targets.profile import TargetProfile
        from obfuscator.vm.vm_pass import VMPass
        from run_blob_form_regression import execute
        source='''local function make(n)
            return function(...) n=n+1; return n,... end
        end
        local f=make(7)
        local a,b,c=f(false,nil)
        assert(a==8 and b==false and c==nil and select("#",f(3,nil))==3)
        local n=0;for i=1,12 do n=n+i*3 end
        assert(n==234)
        local co=coroutine.create(function() coroutine.yield("yield");return "done" end)
        assert(select(2,coroutine.resume(co))=="yield")
        assert(select(2,coroutine.resume(co))=="done")
        assert(not pcall(function() error("expected",0) end))
        assert(#("中文😀"..string.char(0,255))==12)
        print("compact-serialization-ok")'''
        options={'vm_count':2,'fake_handlers':False,'mutate_handlers':False,'junk_instructions':True,
                 'junk_rate':0.05,'integrity_constants':True,'integrity_constant_rate':1.0,
                 'graph_execution_rate':1.0,'cross_instruction_rate':1.0,'block_variant_rate':1.0,
                 'block_variant_count':2,'runtime_polymorphism_rate':0.3,'blob_form':'string',
                 'dispatcher_target_hiding':True,'semantic_state_threading':True,
                 'argument_virtualization':True,'upvalue_virtualization':True,'table_virtualization':True,
                 'branch_virtualization':True}
        for version in ('5.1','5.3'):
            expected=execute(version,source)
            for backend in ('classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    random.seed(7714)
                    vm=VMPass(target=TargetProfile(version,backend),vm_options=options,
                              vm_output_passes=['rename_obf','minify'])
                    output=vm.run(source)
                    self.assertEqual(expected,execute(version,output))
                    stats=next(row for row in vm.last_profile if row['phase']=='serialize_blob')
                    self.assertEqual(2,stats['format_version'])
                    self.assertEqual(6,stats['instruction_width'])
                    self.assertEqual(stats['bytes'],sum(stats['section_bytes'].values()))


if __name__=='__main__':unittest.main()
