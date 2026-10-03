"""Target word widths, binary64 storage, and crossing instruction fields."""
from pathlib import Path
from dataclasses import replace
import math
import random
import re
import struct
import sys
from types import SimpleNamespace
import zlib
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.runtime_hooks import replace_hook
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass
from obfuscator.vm.kae_blob import encrypt_blob


def main():
    source = '--<<TARGET_TEST>>old--<<ENDTARGET_TEST>>'
    assert 'new' in replace_hook(source, 'TEST', 'new')
    for bad in ('', source + source, source.replace('ENDTARGET', 'MISSING')):
        try:
            replace_hook(bad, 'TEST', 'new')
        except ValueError:
            pass
        else:
            raise AssertionError('missing or duplicated target hook accepted')
    try:
        from lupa.lua51 import LuaRuntime
    except ImportError:
        print('lua51-word skipped: Lupa Lua 5.1 unavailable')
        return 0
    lua = LuaRuntime(encoding=None)
    lua.globals()[b'loadstring'] = None
    lua.globals()[b'load'] = None
    folder = ROOT / 'obfuscator/vm/targets'
    prelude = ''.join('local '+name+'=(function() '+(folder/file).read_text(encoding='utf-8')+
                      ' end)();' for name, file in
                      [('I','int64.lua')])
    prelude += ('local _legacy_is_private,_legacy_private_number,_legacy_private_marker='
                'I.isint,I.number,I.private_marker;'
                'local _native_type=type;'
                'local _PRIVATE_WORD_MARKER=_legacy_private_marker;')
    shim = lua.execute((prelude + 'return (function() ' +
                        (folder/'lua51_shim.lua').read_text(encoding='utf-8')+' end)()').encode())
    native_rekey=lua.eval(b'''function(value,op,variant,shift)
        local scale=2^shift
        return value-(value%128)-(math.floor(value/scale)%256)*scale+
               op+variant*scale
    end''')
    rng = random.Random(5812)
    for shift in range(7, 41):
        for _ in range(20):
            raw = rng.getrandbits(48)
            op, variant = rng.randrange(128), rng.randrange(256)
            actual = int(native_rekey(raw,op,variant,shift))
            expected = (raw & ~(127 | (255 << shift))) | op | (variant << shift)
            assert actual == expected, (shift, raw, actual, expected)
    signed_number=lua.eval(b'''function(lo,hi)
        if hi>=2147483648 then
            return -((4294967295-hi)*4294967296+(4294967296-lo))
        end
        return hi*4294967296+lo
    end''')
    encode = lua.table_from({i: (i*7+3)%16 for i in range(16)})
    decode = lua.table_from({(i*7+3)%16: i for i in range(16)})
    values = [0., -0., math.inf, -math.inf, 2.**-1074, 2.**-1022]
    values += [struct.unpack('<d', rng.getrandbits(64).to_bytes(8, 'little'))[0] for _ in range(500)]
    for value in [-1,-(1<<63),(1<<63)-1,1<<53,(1<<53)+1,0]:
        bits=value & ((1<<64)-1)
        assert signed_number(bits & 0xffffffff,bits >> 32) == float(value)
    source = 'local x=0;for i=1,4 do x=x+i end;assert(x==10);assert(1/(-#"")==-math.huge);local a,b=1.25,2.5;assert(a<b);assert(-a==-1.25)'
    # One layout has variant entirely above bit 32; the other straddles it.
    layouts = ({'A':7,'C':15,'B':24,'V':40}, {'V':28,'A':40,'C':7,'B':16})
    runtime_sources=[]
    translated_sources=[]
    from obfuscator.vm.targets.lua51 import Lua51Target
    def native_regions(source,name):
        marker_names=(('51_NATIVE_51_PRIVATE_MIX','51_PRIVATE_MIX','PRIVATE_MIX')
                      if name=='PRIVATE_MIX' else
                      (f'51_NATIVE_{name}',name))
        for marker_name in marker_names:
            start=f'--<<TARGET_{marker_name}>>'
            end=f'--<<ENDTARGET_{marker_name}>>'
            if start in source:
                return re.findall(re.escape(start)+r'(.*?)'+re.escape(end),source,re.S)
        return []
    def native_region(source,name):
        regions=native_regions(source,name)
        assert regions,name
        return regions[0]
    prepared_runtime=Lua51Target().prepare_runtime(
        Lua51Target().runtime_template('vm.lua'),
        SimpleNamespace(backend='karity',backend_data={}),
    )
    frame_helpers=prepared_runtime.split('local function _frame_encode',1)[1].split(
        'local _AR=',1)[0]
    assert '_frame_encode' in prepared_runtime
    assert all(name in frame_helpers for name in ('_frame_decode','_frame_state'))
    frame_restore=prepared_runtime.split('local _fm',1)[1].split(
        'local _va',1)[0]
    assert '_frame_decode(_fr[__VM_FR_PC__],_fm)' in frame_restore
    assert '_frame_state(_fr[__VM_FR_STATE__],_fm)' in frame_restore
    assert not any(operator in frame_restore for operator in ('<<','>>','&','|','~'))
    frame_build=prepared_runtime.split('local function _frame(a,c,parent)',1)[1].split(
        '    local function _leave',1)[0]
    assert '_pmod(_pband(' in frame_build and '_frame_encode(pc,m)' in frame_build
    assert not any(operator in frame_build for operator in ('<<','>>','&','|','~'))
    frame_cross=prepared_runtime.split('local function _cross(delta)',1)[1].split(
        '    _carry=function',1)[0]
    assert '_pxor' in frame_cross and '_plow(old,256)' in frame_cross
    assert not any(operator in frame_cross for operator in ('<<','>>','&','|','~'))
    def target_region(name):
        return prepared_runtime.split(f'--<<TARGET_{name}>>',1)[1].split(
            f'--<<ENDTARGET_{name}>>',1)[0]
    karity_exec_state=target_region('KARITY_EXEC_STATE')
    assert all(name in karity_exec_state for name in (
        '_c_xor','_c_and','_c_or','_c_not','_c_shl','_c_shr'))
    assert not any(operator in karity_exec_state for operator in ('<<','>>','&','|','~'))
    argument_packet=target_region('ARGUMENT_PACKET')
    argument_tokens={
        '__VM_AP_MARK__':'11','__VM_AP_SEED__':'12',
        '__VM_AP_COUNT__':'13','__VM_AP_DATA__':'14',
        '__VM_ARG_MASK__':'19088743','__VM_ARG_KEY__':'2309737967',
        '__VM_ARG_PAD__':'270544960','__VM_ARG_TAG__':'1432778632',
    }
    for token,value in argument_tokens.items():
        argument_packet=argument_packet.replace(token,value)
    argument_api=lua.execute((prelude+'local _native_type=type\n'+
        target_region('INSTRUCTION_XOR')+'local _PRIVATE_WORD_MARKER={}\n'+
        prepared_runtime.split('--<<TARGET_51_PRIVATE_MIX>>',1)[1].split(
            '--<<ENDTARGET_51_PRIVATE_MIX>>',1)[0]+
        'local _AY=true;local _PN={hi=0,lo=0,_private_word=_PRIVATE_WORD_MARKER};local _IT={seed=0,layout=0};local _ksd=0\n'+
        argument_packet+'''return {
state=function(phi,plo,seed,layout,ksd)
    _PN={hi=phi,lo=plo,_private_word=_PRIVATE_WORD_MARKER};_IT.seed=seed;_IT.layout=layout;_ksd=ksd
end,
pack=function(values,n,fhi,flo) return _apack(values,n,{hi=fhi,lo=flo,_private_word=_PRIVATE_WORD_MARKER}) end,
count=_acount,get=_aget,seed=_aseed,key=_akey,wordkey=_aword_key}
''').encode())
    word_key=argument_api[b'wordkey']
    assert word_key(lua.table_from({1:0,2:27}))==b'0:27'
    assert word_key(lua.table_from({1:4294967295,2:27}))==b'4294967295:27'
    assert word_key(lua.table_from({1:0,2:27}))!=word_key(
        lua.table_from({1:4294967295,2:27}))
    assert argument_api[b'get'](lua.table_from({1:False}),1) is False
    assert argument_api[b'get'](None,1) is None
    common_get=(ROOT/'obfuscator/vm/vm.lua').read_text(encoding='utf-8').split(
        'local function _aget(q,i)',1)[1].split('--<<ENDTARGET_ARGUMENT_PACKET>>',1)[0]
    for token,value in argument_tokens.items():
        common_get=common_get.replace(token,value)
    common_get=lua.execute(('local function _aget(q,i)'+common_get+'return _aget').encode())
    assert common_get(lua.table_from({1:False}),1) is False
    assert common_get(None,1) is None
    classic=(ROOT/'obfuscator/vm/runtimes/classic_exec.lua').read_text(encoding='utf-8')
    classic_get=classic.split('local function _aget(q,i)',1)[1].split('--<<ENDTARGET_USER_STATEMENT>>',1)[0]
    classic_get=lua.execute(('local function _aget(q,i)'+classic_get+'return _aget').encode())
    assert classic_get(lua.table_from({1:False}),1) is False
    assert classic_get(None,1) is None
    mask64=(1<<64)-1
    def private_mix(value):
        value^=value>>30;value=(value*0xbf58476d1ce4e5b9)&mask64
        value^=value>>27;value=(value*0x94d049bb133111eb)&mask64
        return (value^(value>>31))&mask64
    for counter in range(1,201):
        private=rng.getrandbits(64);flow=rng.getrandbits(64)
        state_seed=rng.randrange(65536);layout=rng.getrandbits(32);ksd=rng.getrandbits(32)
        count=rng.randrange(17)
        values={index:(None if index%4==0 else index*17) for index in range(1,count+1)}
        values={index:value for index,value in values.items() if value is not None}
        argument_api[b'state'](private>>32,private&0xffffffff,state_seed,layout,ksd)
        packet=argument_api[b'pack'](lua.table_from(values),count,flow>>32,flow&0xffffffff)
        assert int(argument_api[b'count'](packet))==count
        for index in range(1,count+1):
            assert argument_api[b'get'](packet,index)==values.get(index)
        seed=private_mix(private^state_seed^flow^count^((counter<<21)&mask64))
        actual_seed=argument_api[b'seed'](packet)
        actual=(int(actual_seed[1])<<32)|int(actual_seed[2])
        assert actual==seed,(counter,actual,seed)
        if count:
            key_value=private_mix(seed^((count*0x9e3779b97f4a7c15)&mask64)^2309737967)
            expected_key=f'{key_value>>32}:{key_value&0xffffffff}'.encode()
            assert argument_api[b'key'](actual_seed,count)==expected_key
    original_lower_source=Lua51Target.lower_source
    def restore_target_markers(source):
        def demote(match):
            name=match.group('name')
            if name.startswith('51_'):
                name=name[3:]
            return f"--<<{match.group('end') or ''}TARGET_{name}>>"
        return re.sub(
            r'--<<(?P<end>END)?TARGET_51_NATIVE_(?P<name>[A-Z0-9_]+)>>',
            demote,source,
        )
    def capture_lower_source(self,runtime_source):
        runtime_sources.append(restore_target_markers(runtime_source))
        translated=original_lower_source(self,runtime_source)
        translated_sources.append(translated)
        return translated
    with patch.object(Lua51Target,'lower_source',capture_lower_source):
        for layout in layouts:
            for backend in ('classic','karity','mov'):
                random.seed(123)
                with patch('obfuscator.vm.backends.runtime_layout.make_instr_layout', return_value=layout):
                    vm = VMPass(target=TargetProfile('5.1',backend,disabled_capabilities={'text_chunk_load'}), vm_options={
                        'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False})
                    output = vm.run(source)
                lua.execute(output.encode())
                print('lua51-word-layout-ok',backend,layout['V'],flush=True)
    assert len(runtime_sources)==len(translated_sources)==6
    register_map_count=0
    for runtime_source,translated_source in zip(runtime_sources,translated_sources):
        assert 'local B=(function()' not in translated_source
        assert 'local N=(function()' not in translated_source
        for api in ('math','string','table','type','tostring','tonumber','select',
                    'error','rawget','rawset','debug','len','concat','div','pow'):
            assert f'_target51.{api}' not in translated_source
        assert '_target51.integer_number' not in translated_source
        assert '_target51.source_value' not in translated_source
        assert '_target51.invoke' not in translated_source
        assert '_target51.getfenv' not in translated_source
        if native_regions(runtime_source,'REGISTER_MAP'):
            register_map_count+=1
            register_map=native_region(runtime_source,'REGISTER_MAP')
            assert '_target51' not in register_map
            assert '&0x3FF' not in register_map and register_map.count('%1024')==7
        blob_base=native_region(runtime_source,'BLOB_BASE')
        reader_primitives=native_region(runtime_source,'READER_PRIMITIVES')
        assert '_target51' not in blob_base+reader_primitives
        assert '>>' not in blob_base and '&0xFF' not in blob_base
        assert re.search(r'return\s+\w+\+\w+\*256\+\w+\*65536\+\w+\*16777216',reader_primitives)
        storage_regions=''.join(
            region for name in ('WORD_READ','SIGNED_READ','FLOAT_READ','INTEGRITY_DECODE',
                                'INTEGER_DIGITS','FLOAT_DIGITS','FLOAT_RESULT')
            for region in native_regions(runtime_source,name))
        assert '_target51' not in storage_regions
        word_reader=native_region(runtime_source,'WORD_READ')
        integrity_decode=native_region(runtime_source,'INTEGRITY_DECODE')
        assert 'I.' not in word_reader+integrity_decode
        integrity_expression=native_region(runtime_source,'INTEGRITY_EXPRESSION')
        integrity_mix=native_region(runtime_source,'INTEGRITY_MIX')
        assert '_target51' not in integrity_expression
        assert '_target51' not in integrity_mix
        assert '_imul32' in integrity_mix and '_ixor(a,b)' in integrity_expression
        instruction_reader=runtime_source.split('--<<TARGET_INSTRUCTION_READ>>',1)[1].split('--<<ENDTARGET_INSTRUCTION_READ>>',1)[0]
        instruction_xor=runtime_source.split('--<<TARGET_INSTRUCTION_XOR>>',1)[1].split('--<<ENDTARGET_INSTRUCTION_XOR>>',1)[0]
        instruction_fields=runtime_source.split('--<<TARGET_INSTRUCTION_FIELDS>>',1)[1].split('--<<ENDTARGET_INSTRUCTION_FIELDS>>',1)[0]
        instruction_rekey=runtime_source.split('--<<TARGET_WORD_REKEY>>',1)[1].split('--<<ENDTARGET_WORD_REKEY>>',1)[0]
        instruction_decode=runtime_source.split('--<<TARGET_INSTRUCTION_DECODE>>',1)[1].split('--<<ENDTARGET_INSTRUCTION_DECODE>>',1)[0]
        keystream=runtime_source.split('--<<KSTREAM>>',1)[1].split('--<<ENDKSTREAM>>',1)[0]
        instruction_regions=(instruction_reader+instruction_xor+instruction_fields+
                             instruction_rekey+instruction_decode+keystream)
        assert '_target51' not in instruction_regions
        assert 'hi%65536' in instruction_reader and '_imul48' in keystream
        assert re.search(r'p\.[A-Za-z_][A-Za-z0-9_]*\[i\]=_ixor\(raw64,_ksm\(i\)\)',runtime_source)
        assert not re.search(r'\((?:_dw|_ei|ei)>>\d+\)&0x',runtime_source)
        translated_instruction_regions=''.join(
            region for name in ('INSTRUCTION_READ','INSTRUCTION_XOR','INSTRUCTION_FIELDS',
                                'WORD_REKEY','INSTRUCTION_DECODE','INSTRUCTION_KEYSTREAM',
                                'STRING_KEYSTREAM')
            for region in native_regions(runtime_source,name))
        assert '_target51' not in translated_instruction_regions
        string_keystream=native_region(runtime_source,'STRING_KEYSTREAM')
        assert '_target51' not in string_keystream and 'I.' not in string_keystream
        assert '_ikey48(_ksd)' in string_keystream and '%256' in string_keystream
        translated_storage_regions=storage_regions
        assert '_target51' not in translated_storage_regions
        assert 'I.' not in translated_storage_regions
        assert '_ifield48' in translated_source
        state_key=native_region(runtime_source,'INSTRUCTION_STATE_KEY')
        assert '_target51' not in state_key and 'value.hi%65536' in state_key
        private_mix=native_region(runtime_source,'PRIVATE_MIX')
        assert '_target51' not in private_mix and '_pmul64' in private_mix
        mix_body=private_mix.split('local function _pmix',1)[1]
        assert not any(operation in mix_body for operation in ('I.mul','I.shr','I.bxor'))
        limb_mix=private_mix.split('local function _pmix_words',1)[1].split('local function _pmix(',1)[0]
        assert 'I.' not in limb_mix
        assert '_pint' in private_mix and '_pxor' in private_mix
        source_value=native_region(runtime_source,'SOURCE_VALUE')
        assert '_target51' not in source_value and 'I.' not in source_value
        assert '_private_number(v)' in source_value and '_legacy_private_number' in source_value
        user_regions=(native_regions(runtime_source,'USER_EXPRESSION')+
                      native_regions(runtime_source,'USER_STATEMENT'))
        assert user_regions
        assert all('_target51' not in region and 'I.' not in region
                   for region in user_regions)
        if native_regions(runtime_source,'ARGUMENT_PACKET'):
            argument_packet=native_region(runtime_source,'ARGUMENT_PACKET')
            assert '_target51' not in argument_packet
            assert 'I.make' not in argument_packet
            assert '_aword_key' in argument_packet and '_pmul64' in argument_packet
        proto_regions=[]
        for name in ('PROTO_CODE','PROTO_METADATA','PROTO_CHILDREN'):
            proto_regions.extend(native_regions(runtime_source,name))
        if proto_regions:
            assert len(proto_regions)==3
            proto_reader=''.join(proto_regions)
            assert '_target51' not in proto_reader and 'I.' not in proto_reader
            assert '_ixor(enc_op,acc%128)' in proto_reader
        constant_regions=''.join(
            region for name in ('CONSTANT_RESOLVER','FAKE_CONSTANT_SKIP')
            for region in native_regions(runtime_source,name))
        assert '_target51' not in constant_regions and 'I.' not in constant_regions
        assert '--<<TARGET_INTEGRITY_DECODE>>' in constant_regions
        tamper=native_region(runtime_source,'TAMPER')
        assert '_target51' not in tamper and 'I.' not in tamper
        assert '_imul32' in tamper and '_ixor' in tamper
        private_graphs=native_regions(runtime_source,'PRIVATE_GRAPH')
        if private_graphs:
            assert len(private_graphs)==48
            assert all('_target51' not in region and '_p' in region
                       for region in private_graphs)
        private_expressions=native_regions(runtime_source,'PRIVATE_EXPRESSION')
        if private_expressions:
            assert all('_target51' not in region for region in private_expressions)
            assert any('_p' in region for region in private_expressions)
        if '--<<TARGET_CLASSIC_EXEC_NATIVE>>' in translated_source:
            classic_exec = translated_source.split('--<<TARGET_CLASSIC_EXEC_NATIVE>>',1)[1].split(
                '--<<ENDTARGET_CLASSIC_EXEC_NATIVE>>',1)[0]
            classic_code = '\n'.join(
                line for line in classic_exec.splitlines()
                if not line.lstrip().startswith('--')
            )
            assert '_target51.' not in classic_code and 'I.' not in classic_code
            assert not any(token in classic_code for token in ('<<','>>','//','&','|'))
    assert register_map_count
    # The following isolated full-width storage probes feed legacy ``I``
    # words deliberately.  Karity's shared storage bridge accepts that test
    # representation; native Classic is separately executed above with its
    # tagged-pair-only contract.
    translated_source=translated_sources[1]
    inspection_source=runtime_sources[1]
    instruction_xor=inspection_source.split('--<<TARGET_INSTRUCTION_XOR>>',1)[1].split(
        '--<<ENDTARGET_INSTRUCTION_XOR>>',1)[0]
    private_mix=inspection_source.split('--<<TARGET_PRIVATE_MIX>>',1)[1].split(
        '--<<ENDTARGET_PRIVATE_MIX>>',1)[0]
    from obfuscator.vm.vm_obfuscation import apply_dispatch_target_hiding
    dispatch_fixture = (
        'exec=function() --<<TARGET_KARITY_EXEC_STATE>>\n'
        '--[[VM_DISPATCH_ENTRY]] while true do '
        'if op==7 then return 1 end end end'
    )
    exact_dispatch = apply_dispatch_target_hiding(
        dispatch_fixture, native_state=True,
    )
    dispatch_helper = ('_MJ._DM=' + exact_dispatch.split('_MJ._DM=',1)[1].split(
        '--[[VM_DISPATCH_ENTRY]]',1)[0])
    assert '_peq(_MJ._DV,_pxor(' in exact_dispatch
    dispatch_state = lua.execute((instruction_xor+'''
local _native_type=type
local _PRIVATE_WORD_MARKER={}
'''+private_mix+'''
local _MJ={}
local _S,_XF,_PR,_SS,_MG={[611]=0},{[1]=0},{[1]=0},{[1]=0},{[1]=0}
local _st,pc,_ksd=0,0,0
'''+dispatch_helper+'''return function(hi,lo)
    _S[611]=_pnew(hi,lo)
    _MJ._ds(7)
    return _MJ._DD.hi,_MJ._DD.lo,_MJ._DV.hi,_MJ._DV.lo,
           _peq(_MJ._DV,_pxor(7,_MJ._DD))
end''').encode())
    for _ in range(100):
        state=rng.getrandbits(64)
        dhi,dlo,vhi,vlo,match=dispatch_state(state>>32,state&0xffffffff)
        assert (int(dhi)<<32)|int(dlo)==state
        assert (int(vhi)<<32)|int(vlo)==state^7
        assert match is True
    # Exercise the actual register epoch expression at full width, including
    # signed split-register slots and both coupled/uncoupled state routes.
    from obfuscator.vm.targets.lua51 import _translate_preserving_native_hooks
    register_next=prepared_runtime.split('local function _rnext(slot,salt)',1)[1].split(
        '--<<TARGET_REGISTER_MAP>>',1)[0]
    register_next=_translate_preserving_native_hooks(
        'local function _rnext(slot,salt)'+register_next)
    assert '_target51' not in register_next
    next_epoch=lua.execute((prelude+instruction_xor+'''
local _native_type=type
local _PRIVATE_WORD_MARKER={}
local function _is_private_word(value)
    return type(value)=='table' and value._private_word==_PRIVATE_WORD_MARKER
end
'''+private_mix+'''
local _RX,_SS={},{}
local _RZ,_SY
local _rmix=_pmix
'''+register_next+'''return function(hi,lo,zhi,zlo,shi,slo,slot,thi,tlo,coupled)
    _RX[1]={hi=hi,lo=lo,_private_word=_PRIVATE_WORD_MARKER}
    _RZ={hi=zhi,lo=zlo,_private_word=_PRIVATE_WORD_MARKER}
    _SS[1]={hi=shi,lo=slo,_private_word=_PRIVATE_WORD_MARKER}
    _SY=coupled
    local result=_rnext(slot,{hi=thi,lo=tlo,_private_word=_PRIVATE_WORD_MARKER})
    return result.hi,result.lo,_RX[1].hi,_RX[1].lo
end''').encode())
    for case in range(200):
        counter,key,state,salt=(rng.getrandbits(64) for _ in range(4))
        slot=rng.choice((-7,0,1,255,1023))
        coupled=case%2==0
        args=[part for value in (counter,key,state) for part in (value>>32,value&0xffffffff)]
        hi,lo,chi,clo=next_epoch(*args,slot,salt>>32,salt&0xffffffff,coupled)
        expected_counter=(counter-7046029254386353131+slot+salt)&mask64
        assert (int(chi)<<32)|int(clo)==expected_counter
        expected=expected_counter^key^(state if coupled else 0)
        expected^=expected>>30
        expected=(expected*0xbf58476d1ce4e5b9)&mask64
        expected^=expected>>27
        expected=(expected*0x94d049bb133111eb)&mask64
        expected^=expected>>31
        assert (int(hi)<<32)|int(lo)==expected
    # Use the template's storage/rotation/restore expressions, with random
    # full-width odd affine coefficients and independently calculated inverses.
    def private_expressions_of(name):
        body=prepared_runtime.split(f'local function {name}(',1)[1].split(
            'local function ',1)[0]
        return re.findall(r'--<<TARGET_PRIVATE_EXPRESSION>>(.*?)'
                          r'--<<ENDTARGET_PRIVATE_EXPRESSION>>',body,re.S)
    from obfuscator.vm.targets.lua51_syntax import translate_private_graph
    def expression(source):
        return translate_private_graph('return '+source).removeprefix('return ')
    table_store=private_expressions_of('_tset')
    table_get=private_expressions_of('_tget')
    table_expose=private_expressions_of('_texpose')
    assert (len(table_store),len(table_get),len(table_expose))==(2,1,1)
    table_roundtrip=lua.execute((prelude+instruction_xor+private_mix+'''return function(vhi,vlo,shi,slo)
        local v,share=I.make(vhi,vlo),I.make(shi,slo)
        local left='''+expression(table_store[1])+'''
        local right=share
        local read='''+expression(table_get[0])+'''
        local x=left
        local exposed='''+expression(table_expose[0])+'''
        return read.hi,read.lo,exposed.hi,exposed.lo
    end''').encode())
    for _ in range(200):
        payload,share=rng.getrandbits(64),rng.getrandbits(64)
        hi,lo,ehi,elo=table_roundtrip(payload>>32,payload&0xffffffff,share>>32,share&0xffffffff)
        assert (int(hi)<<32)|int(lo)==payload
        assert (int(ehi)<<32)|int(elo)==payload
    upvalue=private_expressions_of('get_upvalue')
    assert len(upvalue)==8
    decode_upvalue=upvalue[7].replace('__VM_UV_LEFT__','1').replace('__VM_UV_RIGHT__','2')
    upvalue_roundtrip=lua.execute((prelude+instruction_xor+private_mix+'''return function(words)
        local function word(i)return I.make(words[i*2-1],words[i*2])end
        local payload,bias,share=word(1),word(3),word(4)
        local pair={word(2),word(5)}
        local encoded='''+expression(upvalue[3])+'''
        local q={'''+expression(upvalue[5])+''',share}
        local result='''+expression(decode_upvalue)+'''
        return result.hi,result.lo
    end''').encode())
    for _ in range(200):
        payload,scale,bias,share=(rng.getrandbits(64) for _ in range(4))
        scale|=1
        words=(payload,scale,bias,share,pow(scale,-1,1<<64))
        hi,lo=upvalue_roundtrip(lua.table_from([part for word in words for part in (word>>32,word&0xffffffff)]))
        assert (int(hi)<<32)|int(lo)==payload
    pending_body=prepared_runtime.split('_pending_finish=function(dst)',1)[1].split(
        'local function _defer2r',1)[0]
    pending=re.findall(r'--<<TARGET_PRIVATE_EXPRESSION>>(.*?)'
                       r'--<<ENDTARGET_PRIVATE_EXPRESSION>>',pending_body,re.S)
    assert len(pending)==5
    pending=[expression(body.replace('__VM_PENDING_ADD__','12')) for body in pending]
    finish=lua.execute((prelude+instruction_xor+private_mix+'''return function(words,kind)
        local q={kind}
        for i=2,7 do q[i]=I.make(words[(i-2)*2+1],words[(i-2)*2+2]) end
        local encoded='''+pending[0]+'''
        if kind==11 then encoded='''+pending[1]+'''
        else local right='''+pending[2]+'''
             encoded='''+pending[3]+''' end
        local result='''+pending[4]+'''
        return result.hi,result.lo
    end''').encode())
    for _ in range(200):
        pending_values=[rng.getrandbits(64) for _ in range(6)]
        words=lua.table_from([part for value in pending_values for part in (value>>32,value&0xffffffff)])
        left,right=pending_values[0]+pending_values[1],pending_values[2]+pending_values[3]
        for kind,expected in ((11,-left),(12,left+right),(13,left-right)):
            hi,lo=finish(words,kind)
            assert (int(hi)<<32)|int(lo)==(expected+pending_values[5])&mask64
    store=private_expressions_of('_rstore')
    restore=private_expressions_of('rget')
    rotate=private_expressions_of('_rrotate')
    split_store=private_expressions_of('_split_set')
    split_restore=private_expressions_of('_split_get')
    assert (len(store),len(restore),len(rotate),len(split_store),len(split_restore))==(2,1,5,3,1)
    affine=lua.execute((prelude+instruction_xor+private_mix+'''
return function(words)
    local function word(i)return I.make(words[i*2-1],words[i*2])end
    local payload,a,b,share,new_a,new_b,old_inv,inv,delta=
        word(1),word(2),word(3),word(4),word(5),word(6),word(7),word(8),word(9)
    local encoded='''+expression(split_store[0])+'''
    local regs,_RS={},{};local p1,p2=1,1
    regs[p1]='''+expression(store[1])+''';_RS[p2]=share
    local old_b=b
    local alpha='''+expression(rotate[0])+'''
    local beta='''+expression(rotate[1])+'''
    regs[p1]='''+expression(rotate[3])+'''
    _RS[p2]='''+expression(rotate[4])+'''
    b=new_b
    local result='''+expression(restore[0])+'''
    local _split_share=share
    local _split_tmp='''+expression(split_store[2])+'''
    b=old_b;inv=old_inv
    local split='''+expression(split_restore[0])+'''
    return result.hi,result.lo,split.hi,split.lo
end''').encode())
    for _ in range(200):
        payload,a,b,share,new_a,new_b,delta=(rng.getrandbits(64) for _ in range(7))
        a|=1;new_a|=1
        words=(payload,a,b,share,new_a,new_b,pow(a,-1,1<<64),pow(new_a,-1,1<<64),delta)
        limbs=[part for word in words for part in (word>>32,word&0xffffffff)]
        hi,lo,shi,slo=affine(lua.table_from(limbs))
        assert (int(hi)<<32)|int(lo)==payload
        assert (int(shi)<<32)|int(slo)==payload
    mix=lua.execute((prelude+instruction_xor+private_mix+'''return function(hi,lo)
    local result=_pmix(I.make(hi,lo))
    return result.hi,result.lo
end''').encode())
    mix_values=[0,1,mask64,1<<63,(1<<32)-1]
    from obfuscator.vm.targets.lua51_syntax import translate_private_low
    low_cases = (
        ('(a~b)&0x3FF', lambda a,b: (a^b)&1023),
        ('a&18446744073709551615', lambda a,b: a),
        ('(a>>16)&1', lambda a,b: (a>>16)&1),
        ('(a~b)&-1', lambda a,b: a^b),
        ('(a&1023)|1', lambda a,b: (a&1023)|1),
        ('(a+b)|b', lambda a,b: (a+b)|b),
        ('(a-b)~b', lambda a,b: (a-b)^b),
        ('(-a)&(~b)', lambda a,b: (-a)&(~b)),
        ('~(a+b-18446744073709551615)', lambda a,b: ~(a+b-mask64)),
        ('a*b', lambda a,b: a*b),
        ('(a+b)*(a-b)', lambda a,b: (a+b)*(a-b)),
    )
    def shift64(a, count, right):
        if count >= 1 << 63:
            count -= 1 << 64
        if right:
            count = -count
        if abs(count) >= 64:
            return 0
        return ((a << count) & mask64) if count >= 0 else a >> -count
    for count in (-65,-64,-33,-32,-31,-1,0,1,16,31,32,33,63,64,65):
        for operator in ('<<', '>>'):
            low_cases += ((f'a{operator}({count})',
                           lambda a,b,n=count,right=operator=='>>': shift64(a,n,right)),)
    low_cases += (('a<<b', lambda a,b: shift64(a,b,False)),
                  ('a>>b', lambda a,b: shift64(a,b,True)))
    for modulus in (1, 2, 1024, 1 << 32):
        for expression, reference in low_cases:
            translated = translate_private_low(expression, modulus)
            projected = lua.execute((prelude+instruction_xor+private_mix+'''return function(ahi,alo,bhi,blo)
                local a,b=I.make(ahi,alo),I.make(bhi,blo)
                return '''+translated+' end').encode())
            samples = [(mask64, count & mask64) for count in (-64,-32,-1,0,1,32,64)]
            samples += [(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(100)]
            for a,b in samples:
                actual=projected(a>>32,a&0xffffffff,b>>32,b&0xffffffff)
                assert actual == reference(a,b)%modulus, (expression,modulus,a,b,actual)
    projected = translate_private_low('((-(a+b)~(~b))&0x3FF)|1', 1024)
    assert not any(name in projected for name in ('_pxor', '_pband', '_pbor', '_pneg', '_pnot', '_padd'))
    no_alloc = lua.execute((prelude+instruction_xor+private_mix+'''return function()
        local a,b=I.make(4294967295,1023),I.make(2147483648,7)
        I.make=function() error('unexpected private word allocation') end
        return '''+projected+' end').encode())
    assert no_alloc() == ((-(1023+7)^(~7))&1023)|1
    for expression, expected in (('a*b', 7161), ('a>>16', 0xFFFF0000),
                                 ('a<<31', 0x80000000), ('a<<b', 130944),
                                 ('a<<(-16)', 0xFFFF0000)):
        projected = translate_private_low(expression, 1 << 32)
        no_alloc = lua.execute((prelude+instruction_xor+private_mix+'''return function()
            local a,b=I.make(4294967295,1023),I.make(0,7)
            I.make=function() error('unexpected private word allocation') end
            return '''+projected+' end').encode())
        assert no_alloc() == expected, expression
    # Projection must not duplicate calls while expanding OR or arithmetic.
    single_eval = translate_private_low('(left()|right())-left()', 1024)
    calls = lua.execute((prelude+instruction_xor+private_mix+'''local n=0
        local function left() n=n+1;return 7 end
        local function right() n=n+1;return 8 end
        local value='''+single_eval+'''
        return value,n''').encode())
    assert calls == (8,3)
    for invalid in (0, 3, (1 << 32)+1, 1 << 33):
        try:
            translate_private_low('a', invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid low modulus accepted')
    # The limb entry point must execute without the int64 module or shim.
    limb_mix=lua.execute((instruction_xor+private_mix+'return _pmix_words').encode())
    mix_values.extend(rng.getrandbits(64) for _ in range(200))
    for value in mix_values:
        expected=value
        expected^=expected>>30
        expected=(expected*0xbf58476d1ce4e5b9)&mask64
        expected^=expected>>27
        expected=(expected*0x94d049bb133111eb)&mask64
        expected^=expected>>31
        actual_hi,actual_lo=mix(value>>32,value&0xffffffff)
        actual=(int(actual_hi)<<32)|int(actual_lo)
        assert actual==expected,(value,actual,expected)
        native_hi,native_lo=limb_mix(value>>32,value&0xffffffff)
        assert (int(native_hi)<<32)|int(native_lo)==expected
    assert not any(operation in private_mix for operation in
                   ('I.add','I.sub','I.mul','I.band','I.bor','I.bxor',
                    'I.shl','I.shr','I.neg','I.bnot','I.parse','I.from'))
    # Private 64-bit construction is now a single target-runtime boundary.
    # The pair-storage migration must change this factory and the identified
    # late-generated escape sites together, rather than restoring scattered
    # generic integer allocations inside every arithmetic primitive.
    factories = re.findall(
        r'local function _p(?:new|isword)\([^)]*\).*?\nend', private_mix,
        flags=re.S,
    )
    assert len(factories) == 2
    private_body = private_mix
    for factory in factories:
        private_body = private_body.replace(factory, '')
    assert 'I.make' not in private_body and 'I.isint' not in private_body
    assert any('_private_word=_PRIVATE_WORD_MARKER' in factory for factory in factories)
    private_api=lua.execute((prelude+instruction_xor+private_mix+'''local ops={
add=_padd,sub=_psub,mul=_pmul,band=_pband,bor=_pbor,bxor=_pxor,
neg=_pneg,bnot=_pnot,shl=_pshl,shr=_pshr}
return {
call=function(name,ahi,alo,bhi,blo)
    local a=I.make(ahi,alo);local result
    if name=='neg' or name=='bnot' then result=ops[name](a)
    elseif name=='shl' or name=='shr' then result=ops[name](a,blo)
    else result=ops[name](a,I.make(bhi,blo)) end
    return result.hi,result.lo
end,
int=function(text)local result=_pint(text);return result.hi,result.lo end,
tag=function(text)local result=_pint(text);return result._private_word==I.private_marker,I.isint(result) end,
eq=function(ahi,alo,bhi,blo)return _peq(I.make(ahi,alo),I.make(bhi,blo)) end,
low=function(hi,lo,modulus)return _plow(I.make(hi,lo),modulus) end,
mod=function(hi,lo,modulus)return _pmod(I.make(hi,lo),modulus) end}
''').encode())
    def private_result(name,a,b=None):
        hi,lo=private_api[b'call'](name,a>>32,a&0xffffffff,0,b)
        return (int(hi)<<32)|int(lo)
    for _ in range(100):
        a,b=rng.getrandbits(64),rng.getrandbits(64)
        for name,expected in ((b'add',a+b),(b'sub',a-b),(b'mul',a*b),
                              (b'band',a&b),(b'bor',a|b),(b'bxor',a^b)):
            hi,lo=private_api[b'call'](name,a>>32,a&0xffffffff,b>>32,b&0xffffffff)
            actual=(int(hi)<<32)|int(lo)
            assert actual==expected&mask64,(name,a,b,actual,expected&mask64)
        assert private_api[b'eq'](a>>32,a&0xffffffff,a>>32,a&0xffffffff)
        assert not private_api[b'eq'](a>>32,a&0xffffffff,b>>32,b&0xffffffff) or a==b
        for modulus in (2,4,16,1024):
            assert private_api[b'low'](a>>32,a&0xffffffff,modulus)==a%modulus
        signed=a if a<(1<<63) else a-(1<<64)
        for modulus in (2,3,4,7,19):
            assert private_api[b'mod'](a>>32,a&0xffffffff,modulus)==signed%modulus
        assert private_result(b'neg',a)==(-a)&mask64
        assert private_result(b'bnot',a)==(~a)&mask64
        shift=rng.randrange(-80,81)
        expected=((a<<shift)&mask64 if 0<=shift<64 else
                  a>>-shift if -64<shift<0 else 0)
        assert private_result(b'shl',a,shift)==expected
        expected=(a>>shift if 0<=shift<64 else
                  (a<<-shift)&mask64 if -64<shift<0 else 0)
        assert private_result(b'shr',a,shift)==expected
    for value in (0,1,(1<<64)-1,0x9e3779b97f4a7c15):
        hi,lo=private_api[b'int'](str(value).encode())
        assert (int(hi)<<32)|int(lo)==value
    assert private_api[b'tag'](b'123456789')==(True,True)
    crc_region=inspection_source.split('--<<TARGET_CRC>>',1)[1].split(
        '--<<ENDTARGET_CRC>>',1)[0]
    assert '_target51' not in crc_region,crc_region[:2000]
    crc_name=re.search(
        r'local function ([A-Za-z_][A-Za-z0-9_]*)\([A-Za-z_][A-Za-z0-9_]*\)',
        crc_region).group(1)
    crc_table=re.search(r'if not ([A-Za-z_][A-Za-z0-9_]*) then',crc_region).group(1)
    crc32=lua.execute((instruction_xor+f'local {crc_table}\n'+crc_region+
                       f'return {crc_name}').encode())
    crc_values=[b'',b'Karity',bytes(range(256))]
    crc_values.extend(rng.randbytes(rng.randrange(1024)) for _ in range(197))
    for value in crc_values:
        actual=int(crc32(value));expected=zlib.crc32(value)
        assert actual==expected,(len(value),actual,expected)
    cipher_region=inspection_source.split('--<<TARGET_BLOB_CIPHER>>',1)[1].split(
        '--<<ENDTARGET_BLOB_CIPHER>>',1)[0]
    assert '_target51' not in cipher_region and 'I.' not in cipher_region
    decrypt_name=re.findall(
        r'local function ([A-Za-z_][A-Za-z0-9_]*)\('
        r'[A-Za-z_][A-Za-z0-9_]*,[A-Za-z_][A-Za-z0-9_]*\)',cipher_region)[-1]
    unpack_name=re.search(r'string\.char\(([A-Za-z_][A-Za-z0-9_]*)\(',cipher_region).group(1)
    decrypt=lua.execute((instruction_xor+
        f'local function {unpack_name}(values,first,last) return unpack(values,first,last) end\n'+
        cipher_region+f'return {decrypt_name}').encode())
    for _ in range(100):
        value=rng.randbytes(rng.randrange(2048))
        key='karityObfuscator/'+''.join(rng.choice('0123456789abcdef') for _ in range(24))
        nonce,ciphertext=encrypt_blob(value,key,nonce=rng.randbytes(8))
        assert decrypt(nonce+ciphertext,key.encode())==value
    integrity_expression=inspection_source.split('--<<TARGET_INTEGRITY_EXPRESSION>>',1)[1].split(
        '--<<ENDTARGET_INTEGRITY_EXPRESSION>>',1)[0]
    integrity_mix=inspection_source.split('--<<TARGET_INTEGRITY_MIX>>',1)[1].split(
        '--<<ENDTARGET_INTEGRITY_MIX>>',1)[0]
    state_fields=re.findall(r'_iu32\(_IT\.([A-Za-z_][A-Za-z0-9_]*)\)',integrity_expression)
    vm_field=re.search(r'_iu32\(proto\.([A-Za-z_][A-Za-z0-9_]*)\)',integrity_expression).group(1)
    code_field=re.search(r'#proto\.([A-Za-z_][A-Za-z0-9_]*)',integrity_expression).group(1)
    assert len(state_fields)==5 and len(set(state_fields))==5
    state_assignments=';'.join(
        f'_IT.{field}=I.make(state[{index*2+1}],state[{index*2+2}])'
        for index,field in enumerate(state_fields))
    eval_integrity=lua.execute((prelude+instruction_xor+'local _IT={}\n'+
        integrity_mix+integrity_expression+f'''return function(prog,state,vm_id,code_count)
    {state_assignments}
    local code={{}};for i=1,code_count do code[i]=false end
    local proto={{{vm_field}=vm_id,{code_field}=code}}
    return _ieval(prog,proto),_imix(proto)
end''').encode())
    push_ops=(1,2,3,4,5,6,10,11)
    state=[rng.getrandbits(32) for _ in range(10)]
    state_lows={2:state[1],3:state[3],4:state[5],10:state[7],11:state[9]}
    for _ in range(200):
        operations=[]
        first=rng.choice(push_ops)
        operations.append((first,rng.getrandbits(32)) if first==1 else (first,))
        expected_stack=[]
        for step in range(rng.randint(1,16)):
            push=rng.choice(push_ops)
            operations.append((push,rng.getrandbits(32)) if push==1 else (push,))
            operations.append((rng.choice((7,8,9,12)),))
        vm_id,code_count=rng.randrange(256),rng.randrange(1,128)
        for operation in operations:
            op=operation[0]
            if op==1: expected_stack.append(operation[1]&0xffffffff)
            elif op in state_lows: expected_stack.append(state_lows[op]&0xffffffff)
            elif op==5: expected_stack.append(vm_id)
            elif op==6: expected_stack.append(code_count)
            else:
                b=expected_stack.pop();a=expected_stack.pop()
                if op==7 or op not in (8,9): value=a^b
                elif op==8: value=a+b
                else: value=a*(b|1)
                expected_stack.append(value&0xffffffff)
        lua_operations=lua.table_from({index+1:lua.table_from(
            {field+1:value for field,value in enumerate(operation)})
            for index,operation in enumerate(operations)})
        lua_state=lua.table_from({index+1:value for index,value in enumerate(state)})
        actual,mix_actual=eval_integrity(lua_operations,lua_state,vm_id,code_count)
        actual=int(actual);mix_actual=int(mix_actual)
        assert actual==expected_stack[-1],(operations,actual,expected_stack[-1])
        mix_expected=(state[1]^((state[3]&0xffff)<<11)^state[5]^
                      ((vm_id&0xff)<<23)^((code_count&0xffff)*0x45d9f3b))&0xffffffff
        assert mix_actual==mix_expected,(mix_actual,mix_expected)
    mov_source=next(source for source in runtime_sources
                    if '--<<TARGET_MOV_FLOAT_STORAGE>>' in source)
    float_storage=mov_source.split('--<<TARGET_MOV_FLOAT_STORAGE>>',1)[1].split(
        '--<<ENDTARGET_MOV_FLOAT_STORAGE>>',1)[0]
    assert '_target51' not in float_storage and 'string.pack' not in float_storage
    roundtrip=lua.execute((float_storage+'''local encode,decode={},{}
for i=0,15 do encode[i]=(i*7+3)%16;decode[(i*7+3)%16]=i end
return function(value)
    local result=_mov_f64_from_digits(_mov_f64_digits(value,encode),decode,0)
    return result,result==0 and 1/result<0
end''').encode())
    # Observe zero signs through their binary64 bytes; NaN payloads are
    # deliberately canonicalized by the target storage representation.
    for value in values:
        if math.isnan(value):
            continue
        result,negative_zero=roundtrip(value)
        if value==0:
            assert negative_zero==(math.copysign(1,value)<0)
            continue
        actual=struct.pack('<d',result)
        expected=struct.pack('<d',value)
        assert actual==expected,(value,actual.hex(),expected.hex())
    # Common IR integer literals may be integrity encoded even on a binary64
    # target. Their encrypted payload is a word, not a rounded user number.
    original = Lua51Target.build_ir
    def integer_ir(self, bytecode):
        ir = original(self, bytecode)
        def visit(function):
            values = tuple(replace(v,literal=int(v.literal))
                           if isinstance(v.literal,float) and v.literal.is_integer() else v
                           for v in function.values)
            return replace(function,values=values,
                           children=tuple(visit(child) for child in function.children))
        return replace(ir,root=visit(ir.root))
    for backend in ('classic','karity','mov'):
        random.seed(123)
        with patch.object(Lua51Target,'build_ir',integer_ir):
            vm = VMPass(target=TargetProfile('5.1',backend,disabled_capabilities={'text_chunk_load'}),vm_options={
                'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False,
                'integrity_constants':True,'integrity_constant_rate':1.0})
            output = vm.run('large_positive=4503599627370495;large_negative=-4503599627370495')
        lua.execute(output.encode())
        assert lua.globals()[b'large_positive'] == 4503599627370495
        assert lua.globals()[b'large_negative'] == -4503599627370495
        print('lua51-encoded-constant-ok',backend,flush=True)
    print('lua51-word-ok rekey=680 binary64=506 register-epochs=200 register-affine=200 private-mix=205 private-ops=100 argument-packets=200 integrity-u32=200 crc32=200 cipher=100 native-instructions=6 checked hooks')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
