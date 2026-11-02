"""Real-pool decoys survive storage without becoming guest instructions."""
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'test')]
from obfuscator.vm import VMPass
from obfuscator.vm import constant_pool
from obfuscator.vm.ir import IRBlock, IRFunction, IRInstruction, IROperand, IRValue, SemanticIR, validate_semantic_ir
from obfuscator.vm.backends import handler_codec
from obfuscator.vm.string_storage import decode
from obfuscator.vm.targets.profile import TargetProfile
from run_cross_backend_generated_regression import execute
from run_serialization_regression import harness
from run_vm_backend_regression import options
from run_source_protection_regression import run


def fixture():
    root = IRFunction('f0', 0, False, 0,
        tuple(IRValue(f'f0:k{i}', 'constant', i, literal=v)
              for i, v in enumerate((None, False, 0, -0.0, b'original'))),
        (IRBlock('f0:b0', (IRInstruction('f0:i0', 'RETURN',
            operands=(IROperand('values', 'register_range', 0, 0),)),)),))
    child = replace(root, id='f1', values=(), blocks=(IRBlock('f1:b0',
        (IRInstruction('f1:i0', 'RETURN', operands=(IROperand('values', 'register_range', 0, 0),)),)),))
    return SemanticIR('5.3', replace(root, children=(child,)))


@patch.object(constant_pool, 'DECOY_STRINGS', ['string1'])
class ConstantPoolTests(unittest.TestCase):
    def test_root_only_append_preserves_indices_and_instructions(self):
        before = fixture()
        texts = ['string1', 'string1', "한글\0'\\\n", '']
        with patch.object(constant_pool, 'DECOY_STRINGS', texts):
            after = constant_pool.inject_decoy_strings(before)
            self.assertIs(after, constant_pool.inject_decoy_strings(after))
        validate_semantic_ir(after)
        self.assertEqual(before.root.values, after.root.values[:len(before.root.values)])
        self.assertIs(before.root.blocks, after.root.blocks)
        self.assertIs(before.root.children, after.root.children)
        self.assertEqual([s.encode('utf8') for s in dict.fromkeys(texts)],
                         [v.literal for v in after.root.values[len(before.root.values):]])
        with patch.object(constant_pool, 'DECOY_STRINGS', []):
            self.assertIs(before, constant_pool.inject_decoy_strings(before))
        with patch.object(constant_pool, 'DECOY_STRINGS', ['original']):
            reused = constant_pool.inject_decoy_strings(before)
            self.assertIs(before.root.values, reused.root.values)
            self.assertEqual((b'original',), reused.root.debug_metadata[constant_pool.RETENTION_KEY])
            self.assertIs(reused, constant_pool.inject_decoy_strings(reused))

    def test_lowering_that_drops_values_or_the_contract_fails_closed(self):
        from obfuscator.vm.backends.bare import BareBackend
        original = BareBackend.optimize
        for metadata in (False, True):
            def drop(backend, lowered, context):
                lowered = original(backend, lowered, context)
                root = lowered.semantic_ir.root
                if metadata:
                    root = replace(root, debug_metadata={k:v for k,v in root.debug_metadata.items()
                                   if k != constant_pool.RETENTION_KEY})
                else:
                    root = replace(root, values=tuple(v for v in root.values if v.literal != b'string1'))
                lowered.semantic_ir = replace(lowered.semantic_ir, root=root)
                return lowered
            vm = VMPass(target=TargetProfile('5.3', 'bare'), vm_options=options('bare'))
            with patch.object(BareBackend, 'optimize', drop), self.assertRaisesRegex(ValueError, 'retained pool strings'):
                vm.run('return 7')

    def test_fake_header_or_child_pool_cannot_satisfy_root_retention(self):
        from run_serialization_regression import fixture as physical_fixture
        physical = physical_fixture()
        physical.children[0].source.constants.append(b'string1')
        with patch.object(handler_codec, '_FAKE_STRINGS', ['string1']), \
                self.assertRaisesRegex(ValueError, 'serialized root constants'):
            handler_codec.serialize(physical, retained_strings=(b'string1',))
        from obfuscator.vm.source_protection import SourceProtection
        pool = SourceProtection({}, 1, record_tags={'string': 4})
        pool.add_constant(b'other')
        with self.assertRaisesRegex(ValueError, 'Bare payload'):
            pool.payload(lambda v:v, retained_strings=(b'string1',))

    def test_final_vm_output_really_loads_the_retained_envelope(self):
        from obfuscator.vm import program_integrity
        from obfuscator.vm.backends import runtime_emitter
        original_prepare, original_patch = program_integrity.prepare, runtime_emitter.patch_integrity_sources
        for version in ('5.1', '5.3'):
            for backend in ('classic', 'karity', 'mov'):
                with self.subTest(version=version, backend=backend):
                    identity = []
                    def expose(source, layout, context, blob, **kwargs):
                        result = original_prepare(source, layout, context, blob, **kwargs)
                        index = layout.functions.source.constants.index(b'string1')+1
                        marker = program_integrity.initialization_source(version, backend)
                        self.assertEqual(1, result.count(marker))
                        getter = '''\n_ENV_NATIVE.POOL_ENVELOPE=function()
local s=_kss(proto.constants[INDEX][2]);local t={}
for j=1,#s do t[j]=string.format('%02x',string.byte(s,j)) end
return table.concat(t) end\n'''.replace('INDEX', str(index))
                        return result.replace(marker, marker+getter)
                    def observe(data, script, line, *args, **kwargs):
                        identity.append((script, line))
                        return original_patch(data, script, line, *args, **kwargs)
                    random.seed(7719)
                    vm = VMPass(target=TargetProfile(version, backend), vm_options=options(backend),
                        vm_output_passes=['strip_info', 'rename_obf', 'string_encode', 'minify'])
                    with patch.object(program_integrity, 'prepare', expose), \
                            patch.object(runtime_emitter, 'patch_integrity_sources', observe):
                        output = vm.run('return 7')
                    value, envelope = run(version, output, call=b'''local n=assert((loadstring or load)(source))()
return n,POOL_ENVELOPE()''')
                    self.assertEqual(7, value)
                    self.assertEqual(1, len(identity))
                    self.assertEqual(b'string1', decode(bytes.fromhex(envelope.decode()), *identity[0]))

    def test_all_backends_store_real_unreferenced_string_and_preserve_execution(self):
        source = '''local function f(...)return ... end
local a,b,c=f(7,nil,false);print(a,b,c,'guest');assert(a==7 and b==nil and c==false)'''
        for version in ('5.1', '5.3'):
            expected = execute(version, source)
            for backend in ('classic', 'karity', 'mov', 'bare'):
                with self.subTest(version=version, backend=backend):
                    random.seed(7719)
                    vm = VMPass(target=TargetProfile(version, backend), vm_options={**options(backend),
                        'integrity_constants': True, 'integrity_constant_rate': 1.0},
                        vm_output_passes=['strip_info', 'rename_obf', 'minify'])
                    output = vm.run(source)
                    self.assertEqual(expected, execute(version, output))
                    root = vm.last_lowered_ir.semantic_ir.root
                    item, = [v for v in root.values if v.kind=='constant' and v.literal==b'string1']
                    self.assertFalse(any(item.id in i.constants or any(
                        o.kind=='constant' and o.value==item.index for o in i.operands)
                        for b in root.blocks for i in b.instructions))
                    if backend == 'bare':
                        from obfuscator.vm.backends.bare_emitter import literal
                        pool = vm.last_lowered_ir.backend_data['source_protection']
                        self.assertIn(pool.payload(literal), output)
                        slot = pool.constant_lookup[(bytes, b'string1')]
                        raw = pool.raw_payload();offset = (slot ^ pool.index_mask)-1
                        tag, size = struct.unpack_from('<BI', raw, offset)
                        self.assertEqual(pool.record_tags['string'], tag)
                        self.assertEqual(b'string1', decode(raw[offset+5:offset+5+size], pool.script_hash, pool.line_state))
                    else:
                        physical = vm.last_lowered_ir.backend_data['layout'].functions
                        self.assertEqual(b'string1', physical.source.constants[item.index])
                        # Decode the actual real prototype pool after the existing
                        # fake header has been skipped, using the canonical ABI.
                        blob = handler_codec.serialize(physical, compact_synthesis=False)
                        decoded = harness(version)(blob, b'proto', 0)[0]
                        self.assertEqual(b'string1', decode(decoded[b'constants'][item.index+1][2]))


if __name__ == '__main__':
    unittest.main()
