"""Lua 5.1 generated API, control-field and executor capture boundaries."""
from pathlib import Path
import random
import re
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.lua51 import Lua51Target
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass
from obfuscator.passes.minify import MinifyPass
from obfuscator.passes.remove_comment import RemoveCommentPass


def main():
    from lupa.lua51 import LuaRuntime
    from obfuscator.vm.vm_obfuscation import _inline_fetch_decode
    from obfuscator.vm.backends.runtime_emitter import (
        _compile_call_route_func, _compile_control_graph_func,
        _compile_occurrence_graph_func, _compile_loop_ir_func,
        _compile_semantic_ir_func,
    )
    graph_compilers = (
        _compile_call_route_func,
        _compile_control_graph_func,
        lambda **options: _compile_occurrence_graph_func(917331, **options),
        *(lambda kind=kind, **options: _compile_loop_ir_func(kind, **options)
          for kind in ('FORLOOP', 'FORPREP', 'TFORLOOP')),
        lambda **options: _compile_semantic_ir_func('IDIV', **options),
    )
    for index, compile_graph in enumerate(graph_compilers):
        random.seed(5840 + index)
        native_graph = compile_graph(native_control=True)
        random.seed(5840 + index)
        legacy_graph = compile_graph(native_control=False)
        assert 'do local ' in native_graph and 'goto ' not in native_graph
        assert not re.search(r'::[A-Za-z_]\w*::', native_graph)
        assert re.search(r'\breturn [A-Za-z_]\w*\(\)', native_graph)
        assert 'goto ' in legacy_graph and '::' in legacy_graph

    lua = LuaRuntime(encoding=None)
    fetch_template = ('--<<TARGET_KARITY_EXEC_STATE>>\n'
                      '--<<FETCH>>\nold fetch\n--<<ENDFETCH>>')
    for variant in range(3):
        fetch = _inline_fetch_decode(fetch_template, variant)
        marker = '--<<TARGET_51_KARITY_FETCH>>'
        end_marker = '--<<ENDTARGET_51_KARITY_FETCH>>'
        assert marker in fetch and end_marker in fetch
        fetch_body = fetch.split(marker, 1)[1].split(end_marker, 1)[0]
        assert not any(token in fetch_body for token in ('<<', '>>', '//', '&', '|'))
        decode = lua.execute(('''return function(word)
            local _SH_C,_SH_B,_SH_A,_SH_V=11,20,30,40
            local _S,_XF={},{}
            local _cd,pc={[1]=word},1
            local _avd,_gsd={},{}
            local function _av_read() end
            local function _route_step() end
            local function _ss_step() end
            local function _pxor() return 0 end
            local function _ikey48(value) return value end
            local function _ksm() return 0 end
            local function _ixor(value,mask)
                assert(mask==0); return value
            end
            local function _ifield48(value,shift,width)
                return math.floor(value/2^shift)%width
            end
            '''+fetch_body+'''
            return op,A,B,C,Bx,sBx
        end''').encode())
        fetch_rng = random.Random(5841 + variant)
        for word in (0, 1, (1 << 48) - 1,
                     *(fetch_rng.getrandbits(48) for _ in range(40))):
            bx=(word >> 11) & 0x3ffff
            assert decode(word) == (
                (word & 0x7f) | (((word >> 40) & 0xff) << 7),
                (word >> 30) & 0xff, (word >> 20) & 0x1ff,
                (word >> 11) & 0x1ff, bx, bx - 131071,
            )
    from obfuscator.vm.backends.runtime_emitter import _semantic_source
    native_idiv = _semantic_source(
        "IDIV", "a", "b", "unused", native_user_arithmetic=True,
    )
    assert "//" not in native_idiv and "_target51." not in native_idiv
    assert "math.floor(a/b)" in native_idiv
    floor_div = lua.execute(
        ("return function(a,b) " + native_idiv + " return r end").encode()
    )
    assert floor_div(3, 2) == 1
    assert floor_div(-3, 2) == -2
    assert floor_div(3, -2) == -2
    assert floor_div(-4, 2) == -2
    legacy_idiv = _semantic_source("IDIV", "a", "b", "unused")
    assert "a//b" in legacy_idiv

    marker_source = (
        "-- ordinary comment\n--<<TARGET_51_NATIVE_51_MOV_NATIVE>>\nlocal x=1\n"
        "--<<ENDTARGET_51_NATIVE_51_MOV_NATIVE>>\n"
        "--<<TARGET_51_NATIVE_51_PRIVATE_MIX>>\nlocal y=2\n"
        "--<<ENDTARGET_51_NATIVE_51_PRIVATE_MIX>>\n"
    )
    for comment_pass in (MinifyPass(), RemoveCommentPass()):
        lowered_marker_source = comment_pass.run(marker_source)
        assert "--<<TARGET_51_NATIVE_51_MOV_NATIVE>>" in lowered_marker_source
        assert "--<<ENDTARGET_51_NATIVE_51_MOV_NATIVE>>" in lowered_marker_source
        assert "--<<TARGET_51_NATIVE_51_PRIVATE_MIX>>" in lowered_marker_source
        assert "--<<ENDTARGET_51_NATIVE_51_PRIVATE_MIX>>" in lowered_marker_source
        assert "ordinary comment" not in lowered_marker_source
        lua.execute(lowered_marker_source.encode())
    decoder = Lua51Target().numeric_blob_decoder('')
    assert '_target51' not in decoder and 'table.unpack' not in decoder
    decode = lua.execute(('return function(blob) return ' + decoder + ' end').encode())
    rng = random.Random(5812)
    for length in (*range(17), 4095, 4096, 4097, 16385):
        data = bytes(rng.randrange(256) for _ in range(length))
        words = {0: length}
        for offset in range(0, length, 4):
            words[offset // 4 + 1] = int.from_bytes(data[offset:offset + 4].ljust(4, b'\0'), 'little')
        assert decode(lua.table_from(words)) == data, length

    source = (ROOT / 'test/fixtures/lua51_runtime_boundaries.lua').read_text(encoding='utf-8')
    original = Lua51Target.lower_source
    profiles = (
        ('lean', {'fake_handlers': False, 'mutate_handlers': False, 'junk_instructions': False}),
        ('default', {}),
        ('lean-string', {'fake_handlers': False, 'mutate_handlers': False,
                         'junk_instructions': False, 'blob_form': 'string'}),
    )
    # Keep the original audited spelling: source/debug changes can alter the
    # emitted protection plan, so test the original reproducer as well.
    reproducer = '''local function f(a,...)
local t={...};local s=a
for i=1,#t do s=s+t[i] end
return s,function(x) return s+x end
end
local a,g=f(1,2,3);assert(a==6 and g(4)==10)
'''
    for name, options in profiles:
        for backend in ('classic', 'karity', 'mov'):
            captured = []
            def capture(self, runtime):
                with patch('obfuscator.vm.targets.lua51.translate',
                           side_effect=AssertionError('native backend used whole-source translation')):
                    lowered = original(self, runtime)
                assert not re.search(r'\b(?:math\.type|table\.(?:unpack|pack))\s*\(', lowered)
                if backend == 'classic':
                    native_marker = '--<<TARGET_CLASSIC_EXEC_NATIVE>>'
                    assert native_marker in lowered
                    assert '_target51' not in lowered and 'local I=(function' not in lowered
                    native = lowered.split(native_marker,1)[1].split(
                        '--<<ENDTARGET_CLASSIC_EXEC_NATIVE>>',1)[0]
                    code = '\n'.join(
                        line for line in native.splitlines()
                        if not line.lstrip().startswith('--')
                    )
                    assert '_target51.' not in code and 'I.' not in code
                    assert not any(token in code for token in ('<<','>>','//','&','|'))
                elif backend == 'mov':
                    assert '_target51' not in lowered and 'local I=(function' not in lowered
                    helper = lowered.split('local function _target_mov_uint(read_u8)', 1)[1].split('\nend', 1)[0]
                    assert 'read_u8()' in helper and '_target51.' not in helper
                    assert re.search(
                        r'local function _mov_uint\(r\) return _target_mov_uint\(r\.\w+\) end',
                        lowered,
                    )
                elif backend == 'karity':
                    assert '_target51' not in lowered and 'local I=(function' not in lowered
                    assert not re.search(r'\bgoto\s+[A-Za-z_]\w*|::[A-Za-z_]\w*::', runtime)
                    control_marker = '--<<TARGET_51_NATIVE_51_KARITY_CONTROL_HELPERS>>'
                    control_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_CONTROL_HELPERS>>'
                    control = re.findall(
                        re.escape(control_marker) + r'(.*?)' + re.escape(control_end),
                        runtime, re.S,
                    )
                    assert len(control) == 1
                    control_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', control[0],
                    )
                    assert all(f'function {helper}(' in control_code for helper in (
                        '_arith2r', '_arith1r', '_call_args', '_return_values',
                        '_native_call', '_jump', '_loop_commit', '_forloop',
                    ))
                    assert '_target51.' not in control_code and 'I.' not in control_code
                    assert not any(token in control_code for token in ('<<', '>>', '//', '&', '|'))
                    assert control_marker not in lowered and control_end not in lowered
                    fetch_marker = '--<<TARGET_51_NATIVE_51_KARITY_FETCH>>'
                    fetch_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_FETCH>>'
                    fetches = re.findall(
                        re.escape(fetch_marker) + r'(.*?)' + re.escape(fetch_end),
                        runtime, re.S,
                    )
                    assert len(fetches) == 1
                    assert 'local _dk=_ikey48(' in fetches[0]
                    assert '_ifield48(_dw,' in fetches[0]
                    assert '_target51.' not in fetches[0]
                    assert not any(token in fetches[0] for token in ('<<', '>>', '//', '&', '|'))
                    assert fetch_marker not in lowered and fetch_end not in lowered
                    handler_marker = '--<<TARGET_51_NATIVE_51_KARITY_HANDLER_CHAIN>>'
                    handler_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_HANDLER_CHAIN>>'
                    handlers = re.findall(
                        re.escape(handler_marker) + r'(.*?)' + re.escape(handler_end),
                        runtime, re.S,
                    )
                    assert len(handlers) == 1
                    handler_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', handlers[0],
                    )
                    assert '_target51.' not in handler_code and 'I.' not in handler_code
                    assert not any(token in handler_code for token in ('<<', '>>', '//', '&', '|'))
                    assert not re.search(r'(?<![~=])~(?!=)', handler_code)
                    assert handler_marker not in lowered and handler_end not in lowered
                    graph_marker = '--<<TARGET_51_NATIVE_51_KARITY_GRAPH_STATE>>'
                    graph_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_GRAPH_STATE>>'
                    graph = re.findall(
                        re.escape(graph_marker) + r'(.*?)' + re.escape(graph_end),
                        runtime, re.S,
                    )
                    assert len(graph) == 1
                    graph_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', graph[0],
                    )
                    assert all(f'function {helper}(' in graph_code for helper in (
                        '_int2', '_int1', '_cross', '_flow', '_cf', '_branch',
                        '_sem', '_graph_for', '_couple_direct', '_arith2', '_arith1',
                    ))
                    assert '_target51.' not in graph_code and 'I.' not in graph_code
                    assert not any(token in graph_code for token in ('<<', '>>', '//', '&', '|'))
                    assert graph_marker not in lowered and graph_end not in lowered
                    bank_marker = '--<<TARGET_51_NATIVE_51_KARITY_REGISTER_BANK>>'
                    bank_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_REGISTER_BANK>>'
                    bank = re.findall(
                        re.escape(bank_marker) + r'(.*?)' + re.escape(bank_end),
                        runtime, re.S,
                    )
                    assert len(bank) == 1
                    bank_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', bank[0],
                    )
                    assert all(f'function {helper}(' in bank_code for helper in (
                        '_rstore', '_rdecode', '_rvalue', 'rget', 'rset',
                        '_rrotate', '_rmap_rotate', '_rmap_tick',
                    ))
                    assert '_target51.' not in bank_code and 'I.' not in bank_code
                    assert not any(token in bank_code for token in ('<<', '>>', '//', '&', '|'))
                    assert bank_marker not in lowered and bank_end not in lowered
                    pending_marker = '--<<TARGET_51_NATIVE_51_KARITY_PENDING>>'
                    pending_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_PENDING>>'
                    pending = re.findall(
                        re.escape(pending_marker) + r'(.*?)' + re.escape(pending_end),
                        runtime, re.S,
                    )
                    assert len(pending) == 1
                    pending_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', pending[0],
                    )
                    assert all(f'function {helper}(' in pending_code for helper in (
                        '_elinear2', '_elinear1', '_pending_snapshot',
                        '_pending_fragment', '_defer2r', '_defer1r',
                    ))
                    assert '_target51.' not in pending_code and 'I.' not in pending_code
                    assert not any(token in pending_code for token in ('<<', '>>', '//', '&', '|'))
                    assert pending_marker not in lowered and pending_end not in lowered
                    marker = '--<<TARGET_51_NATIVE_51_KARITY_REGISTERS>>'
                    end_marker = '--<<ENDTARGET_51_NATIVE_51_KARITY_REGISTERS>>'
                    states = re.findall(
                        re.escape(marker) + r'(.*?)' + re.escape(end_marker),
                        runtime, re.S,
                    )
                    assert len(states) == 1
                    state = '\n'.join(states)
                    assert '_target51.' not in state and 'I.' not in state
                    for helper_name in (
                        '_split_set', '_split_get',
                    ):
                        assert f'function {helper_name}(' in state, helper_name
                    assert marker not in lowered and end_marker not in lowered
                    storage_marker = '--<<TARGET_51_NATIVE_51_KARITY_VALUE_STORAGE>>'
                    storage_end = '--<<ENDTARGET_51_NATIVE_51_KARITY_VALUE_STORAGE>>'
                    storage = re.findall(
                        re.escape(storage_marker) + r'(.*?)' + re.escape(storage_end),
                        runtime, re.S,
                    )
                    assert len(storage) == 1
                    assert all(f'function {helper}(' in storage[0] for helper in (
                        'get_upvalue', 'set_upvalue', '_tkey', '_tget', '_tset', '_texpose',
                    ))
                    storage_code = re.sub(
                        r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', storage[0],
                    )
                    unsupported = [line for line in storage_code.splitlines()
                                   if any(token in line for token in ('<<', '>>', '//', '&', '|'))]
                    assert not unsupported, unsupported[:8]
                    start = lowered.index('local function get_box(')
                    end = lowered.index('local function make_closure(', start)
                    assert '_target51.' not in lowered[start:end]
                    assert 'I.' not in lowered[start:end]
                    assert storage_marker not in lowered and storage_end not in lowered
                captured.append(lowered)
                return lowered
            random.seed(5812)
            with patch.object(Lua51Target, 'lower_source', capture):
                output = VMPass(target=TargetProfile('5.1', backend), vm_options=options).run(reproducer)
            assert len(captured) == 1
            assert '_target51' not in output and 'local I=(function' not in output
            assert '_legacy_' not in output
            runtime = LuaRuntime(encoding=None)
            runtime.execute(output.encode())
            print('lua51-runtime-ok', name, backend, flush=True)
    # Dispatcher conversion clones and reshapes the handler chain after the
    # source template is authored. Every resulting 5.1 chain must retain its
    # native boundary, including full-width target-hiding comparisons.
    for index, dispatcher in enumerate(('bsearch', 'tailcall', 'split4', 'bsplit4')):
        def capture_dispatch(self, runtime):
            blocks = re.findall(
                r'--<<TARGET_51_NATIVE_51_KARITY_HANDLER_CHAIN>>(.*?)'
                r'--<<ENDTARGET_51_NATIVE_51_KARITY_HANDLER_CHAIN>>',
                runtime, re.S,
            )
            assert blocks
            for block in blocks:
                code = re.sub(r'--<<(?:END)?TARGET_[A-Z0-9_]+>>', '', block)
                assert '_target51.' not in code and 'I.' not in code
                assert not any(token in code for token in ('<<', '>>', '//', '&', '|'))
                assert not re.search(r'(?<![~=])~(?!=)', code)
            return original(self, runtime)
        random.seed(5830 + index)
        with patch.object(Lua51Target, 'lower_source', capture_dispatch):
            shaped = VMPass(target=TargetProfile('5.1', 'karity'), vm_options={
                'dispatcher_type': dispatcher, 'dispatcher_target_hiding': True,
                'vm_count': 2, 'fake_handlers': False,
                'mutate_handlers': False, 'junk_instructions': False,
            }).run(reproducer)
        assert '_target51' not in shaped and 'local I=(function' not in shaped
        LuaRuntime(encoding=None).execute(shaped.encode())
        print('lua51-runtime-ok native-dispatch', dispatcher, flush=True)
    random.seed(5848)
    with patch('obfuscator.vm.targets.lua51.translate',
               side_effect=AssertionError('Karity used whole-source translation')):
        hardened_karity = VMPass(
            target=TargetProfile('5.1', 'karity'), vm_output_passes=['minify'],
            vm_options={
                'dispatcher_type': 'mixed', 'dispatcher_target_hiding': True,
                'semantic_state_threading': True, 'blob_form': 'string',
                'vm_count': 2, 'fake_handlers': True, 'mutate_handlers': True,
                'junk_instructions': True, 'junk_rate': 0.2,
                'integrity_constants': True, 'integrity_constant_rate': 0.2,
            },
        ).run(reproducer)
    assert '_target51' not in hardened_karity and 'local I=(function' not in hardened_karity
    assert '_legacy_' not in hardened_karity
    LuaRuntime(encoding=None).execute(hardened_karity.encode())
    print('lua51-runtime-ok hardened-karity-native', flush=True)
    # Keep the target-native boundary enabled when all Classic protection
    # layers are active together: fake handlers, CFF mutation, dispatcher
    # reshaping, state coupling, target hiding, and multi-VM routing.
    captured = []
    def capture_hardened(self, runtime):
        lowered = original(self, runtime)
        marker = '--<<TARGET_CLASSIC_EXEC_NATIVE>>'
        assert marker in lowered
        assert '_target51' not in lowered and 'local I=(function' not in lowered
        native = lowered.split(marker, 1)[1].split(
            '--<<ENDTARGET_CLASSIC_EXEC_NATIVE>>', 1)[0]
        code = '\n'.join(
            line for line in native.splitlines()
            if not line.lstrip().startswith('--')
        )
        assert '_target51.' not in code and 'I.' not in code
        assert not any(token in code for token in ('<<', '>>', '//', '&', '|'))
        captured.append(lowered)
        return lowered
    random.seed(5816)
    with patch.object(Lua51Target, 'lower_source', capture_hardened):
        hardened = VMPass(target=TargetProfile('5.1', 'classic'), vm_options={
            'dispatcher_type': 'mixed', 'dispatcher_target_hiding': True,
            'semantic_state_threading': True, 'blob_form': 'string', 'vm_count': 2,
            'fake_handlers': True, 'mutate_handlers': True, 'junk_instructions': True,
            'junk_rate': 0.2, 'integrity_constants': True,
            'integrity_constant_rate': 0.2,
        }).run(reproducer)
    assert len(captured) == 1
    LuaRuntime(encoding=None).execute(hardened.encode())
    print('lua51-runtime-ok hardened-classic-native', flush=True)
    # Minification erases marker comments, so the target must retain its
    # selected native contract through the late output/line-state stages.
    random.seed(5817)
    minified = VMPass(
        target=TargetProfile('5.1', 'classic'), vm_output_passes=['minify'],
        vm_options={'fake_handlers': True, 'mutate_handlers': True,
                    'junk_instructions': True, 'blob_form': 'string'},
    ).run(reproducer)
    assert '_target51' not in minified
    LuaRuntime(encoding=None).execute(minified.encode())
    print('lua51-runtime-ok minified-classic-native', flush=True)
    # MOV's reader and nibble byte-storage helpers operate on bounded integers.
    # Their paired 5.1 blocks must survive output comment passes and must not
    # be sent through the generic compatibility translator.
    captured = []
    def capture_mov_native(self, runtime):
        native_blocks = re.findall(
            r'--<<TARGET_51_NATIVE_51_MOV_NATIVE>>(.*?)'
            r'--<<ENDTARGET_51_NATIVE_51_MOV_NATIVE>>',
            runtime, re.S,
        )
        assert len(native_blocks) >= 3
        for block in native_blocks:
            assert '_target51.' not in block and 'I.' not in block
            assert not any(token in block for token in ('<<', '>>', '//', '&', '|'))
        assert 'local function _mov_decode_byte' in ''.join(native_blocks)
        assert 'local function _mov_encode_byte' in ''.join(native_blocks)
        assert 'unsupported Lua 5.1 MOV operation: BAND' in ''.join(native_blocks)
        assert 'return _mdigits[i]' in ''.join(native_blocks)
        lowered = original(self, runtime)
        assert '--<<TARGET_51_NATIVE_51_MOV_NATIVE>>' not in lowered
        assert '_target51' not in lowered and 'local I=(function' not in lowered
        captured.append(lowered)
        return lowered
    random.seed(5818)
    with (patch.object(Lua51Target, 'lower_source', capture_mov_native),
          patch('obfuscator.vm.targets.lua51.translate',
                side_effect=AssertionError('MOV used generic source translation'))):
        minified_mov = VMPass(
            target=TargetProfile('5.1', 'mov'), vm_output_passes=['minify'],
            vm_options={'fake_handlers': True, 'mutate_handlers': True,
                        'junk_instructions': True, 'blob_form': 'string'},
        ).run(reproducer)
    assert len(captured) == 1
    assert '_target51' not in minified_mov
    LuaRuntime(encoding=None).execute(minified_mov.encode())
    print('lua51-runtime-ok minified-mov-native', flush=True)
    captured = []
    def capture_minified_karity(self, runtime):
        native_names = re.findall(
            r'--<<TARGET_51_NATIVE_([A-Z0-9_]+)>>', runtime
        )
        assert 'KARITY_EXEC_STATE' in native_names
        assert '51_KARITY_REGISTER_BANK' in native_names
        assert '51_KARITY_PENDING' in native_names
        assert '51_KARITY_GRAPH_STATE' in native_names
        assert '51_KARITY_FETCH' in native_names
        assert '51_KARITY_HANDLER_CHAIN' in native_names
        assert '51_KARITY_CONTROL_HELPERS' in native_names
        assert '51_KARITY_REGISTERS' in native_names
        assert '51_KARITY_VALUE_STORAGE' in native_names
        lowered = original(self, runtime)
        assert not re.search(r'--<<TARGET_51_NATIVE_[A-Z0-9_]+>>', lowered)
        assert '_target51' not in lowered and 'local I=(function' not in lowered
        captured.append(lowered)
        return lowered
    random.seed(5820)
    with patch.object(Lua51Target, 'lower_source', capture_minified_karity):
        minified_karity = VMPass(
            target=TargetProfile('5.1', 'karity'), vm_output_passes=['minify'],
            vm_options={'blob_form': 'string', 'fake_handlers': False,
                        'mutate_handlers': False, 'junk_instructions': False},
        ).run(reproducer)
    assert len(captured) == 1
    assert '_target51' not in minified_karity and 'local I=(function' not in minified_karity
    LuaRuntime(encoding=None).execute(minified_karity.encode())
    print('lua51-runtime-ok minified-karity-native-hooks', flush=True)
    byte_build = [
        's=s..string.char(' + ','.join(map(str, range(start, start + 64))) + ')'
        for start in range(0, 256, 64)
    ]
    byte_source = '\n'.join([
        byte_build[0].replace('s=s..', 'local s=', 1),
        *byte_build[1:],
        'local copy=s..string.char(255,0)',
        'assert(#copy==258)',
        'for i=1,256 do assert(string.byte(copy,i)==i-1) end',
        'assert(string.byte(copy,257)==255 and string.byte(copy,258)==0)',
    ])
    random.seed(5819)
    byte_output = VMPass(
        target=TargetProfile('5.1', 'mov'),
        vm_options={'fake_handlers': False, 'mutate_handlers': False,
                    'junk_instructions': False, 'blob_form': 'string'},
    ).run(byte_source)
    LuaRuntime(encoding=None).execute(byte_output.encode())
    print('lua51-runtime-ok mov-native-byte-roundtrip', flush=True)
    random.seed(5813)
    output = VMPass(target=TargetProfile('5.1', 'karity'), vm_options={
        'blob_form': 'numeric'}).run(source)
    LuaRuntime(encoding=None).execute(output.encode())
    random.seed(5814)
    closed_upvalues = '''local function make(v)
        local x=v
        return function() return x end, function(y) x=y end,
               function() return function() return x end end
    end
    local identity={}
    for _,initial in ipairs({false,true,3.25,'value',identity,-0.0}) do
        local get,set,nested=make(initial)
        local other=nested()
        assert(get()==initial and other()==initial,'initial '..type(initial))
        if type(initial)=='number' and initial==0 then
            assert(1/get()<0 and 1/other()<0,'negative zero')
        end
        set(nil);assert(get()==nil and other()==nil,'nil')
        set(false);assert(get()==false and other()==false,'false')
        set(identity);assert(get()==identity and other()==identity,'table')
        set(-7.5);assert(get()==-7.5 and other()==-7.5,'number')
    end
    local function pack(...) return {n=select('#',...),...} end
    local function echo(...) return ... end
    local function tail(...) return echo(...) end
    local function none() end
    local result=pack(tail(false,nil,3,nil))
    assert(result.n==4 and result[1]==false and result[2]==nil and result[3]==3 and result[4]==nil)
    assert(pack(tail()).n==0 and pack(none()).n==0)
    local a,b,c,d=echo(false,nil,3)
    assert(a==false and b==nil and c==3 and d==nil)'''
    for backend in ('classic','karity','mov'):
        random.seed(5814)
        output=VMPass(target=TargetProfile('5.1',backend),vm_options={
            'vm_count':3,'upvalue_virtualization':True,
            'semantic_state_threading':True}).run(closed_upvalues)
        LuaRuntime(encoding=None).execute(output.encode())
    boundary_source = (ROOT / 'test/fixtures/backend_escape_boundaries.lua').read_text(
        encoding='utf-8'
    )
    LuaRuntime(encoding=None).execute(boundary_source.encode())
    for backend in ('classic', 'karity', 'mov'):
        random.seed(5821)
        output = VMPass(
            target=TargetProfile('5.1', backend),
            vm_options={'fake_handlers': False, 'mutate_handlers': False,
                        'junk_instructions': False, 'blob_form': 'string'},
        ).run(boundary_source)
        LuaRuntime(encoding=None).execute(output.encode())
        print('lua51-boundary-escape-ok', backend, flush=True)
    yield_boundary_source = (
        ROOT / 'test/fixtures/lua51_metamethod_yield.lua'
    ).read_text(encoding='utf-8')
    # Pin the version-specific reference behavior before comparing each VM.
    LuaRuntime(encoding=None).execute(yield_boundary_source.encode())
    for backend in ('classic', 'karity', 'mov'):
        random.seed(5822)
        output = VMPass(
            target=TargetProfile('5.1', backend),
            vm_options={'fake_handlers': False, 'mutate_handlers': False,
                        'junk_instructions': False, 'blob_form': 'string'},
        ).run(yield_boundary_source)
        LuaRuntime(encoding=None).execute(output.encode())
        print('lua51-metamethod-yield-rejection-ok', backend, flush=True)
    repeated_pending = (ROOT / 'test/fixtures/backend_repeated_pending.lua').read_text(
        encoding='utf-8'
    )
    random.seed(5823)
    output = VMPass(
        target=TargetProfile('5.1', 'karity'),
        vm_options={'fake_handlers': False, 'mutate_handlers': False,
                    'junk_instructions': False, 'blob_form': 'string',
                    'cross_instruction_rate': 1.0,
                    'runtime_polymorphism_rate': 1.0,
                    'graph_execution_rate': 0.0},
    ).run(repeated_pending)
    LuaRuntime(encoding=None).execute(output.encode())
    print('lua51-repeated-pending-operands-ok karity', flush=True)
    comparison_source = '''local x=11;local y=x+1
    assert(y==y and not (y<y) and y<=y)
    local calls=0
    local t=setmetatable({},{__lt=function(a,b) calls=calls+1;return true end})
    assert(t<t and calls==1)
    local n=0/0;assert(not (n==n))'''
    for diversity in (0.0, 1.0):
        random.seed(5824)
        vm = VMPass(
            target=TargetProfile('5.1', 'karity'),
            vm_options={'fake_handlers': False, 'mutate_handlers': False,
                        'junk_instructions': False, 'blob_form': 'string',
                        'cross_instruction_rate': 1.0,
                        'semantic_diversity_rate': diversity,
                        'graph_execution_rate': 0.0},
        )
        output = vm.run(comparison_source)
        assert vm.last_lowered_ir.backend_data['optimization']['comparison_reads_coalesced'] >= 3
        LuaRuntime(encoding=None).execute(output.encode())
    print('lua51-repeated-comparison-operands-ok karity', flush=True)
    table_source = '''local key={}
    local function_key=function() end
    local t={[false]=false,[key]='object',-123456,3.25}
    t.self=t
    t[function_key]='function';t[-0.0]='zero'
    assert(t[false]==false and t[key]=='object' and t[1]==-123456 and t[2]==3.25)
    assert(t[function_key]=='function' and t[0.0]=='zero')
    assert(t.self==t and #t==2)
    t[key]=nil;assert(t[key]==nil)
    t[key]='again';t[1]=987654
    assert(t[key]=='again' and t[1]==987654)
    assert(rawget(t,'self')==t)
    assert(rawget(t,false)==false and rawget(t,key)=='again')
    assert(rawget(t,function_key)=='function' and rawget(t,0)=='zero')
    local n=0;for k,v in pairs(t) do n=n+1 end;assert(n==7)
    t[false]=nil;t[2]=nil;assert(t[false]==nil and #t==1)
    assert(t.self.self==t and t[key]=='again')'''
    from run_vm_output_emitter_regression import run_source
    for version in ('5.1','5.3'):
        if version=='5.1':
            LuaRuntime(encoding=None).execute(table_source.encode())
        else:
            assert run_source(table_source)==(0,b'',b'')
        random.seed(5815)
        output=VMPass(target=TargetProfile(version,'karity'),vm_options={
            'vm_count':2,'table_virtualization':True,
            'runtime_trace':version=='5.1',
            'semantic_state_threading':True}).run(table_source)
        if version=='5.1':
            traced=LuaRuntime(encoding=None)
            traced.execute(b'''_captured_trace={}
                io.stderr={write=function(self,...)
                    for i=1,select('#',...) do
                        _captured_trace[#_captured_trace+1]=tostring(select(i,...))
                    end
                end}''')
            traced.execute(output.encode())
            trace=traced.eval(b"table.concat(_captured_trace)")
            assert re.fullmatch(rb'karity-vm-trace:[0-9a-f]{16} blocks:\d+ blocktrace:[0-9a-f]{16}\n',trace),trace
        else:
            result=run_source(output)
            assert result==(0,b'',b''),result
    print('lua51-runtime-regression-ok builds=31 numeric-lengths=21 closed-upvalues=6 closure-backends=3 escape-boundaries=3 metamethod-yield-rejections=3 comparison-builds=2 table-targets=2')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
