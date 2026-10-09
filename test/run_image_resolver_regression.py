"""Synthetic PE fixtures exercise file/RVA separation and loader mutations."""
import sys
from pathlib import Path
import struct
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.image_resolver import CEBinaryResolver
from obfuscator.vm.targets.materialization import HostImageProvider, HostImageConstant, LiteralConstant, emit_host_reader
from obfuscator.vm.targets.profile import TargetProfile


def fixture(width):
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 224 if width == 4 else 240
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c if width == 4 else 0x8664,
                     2, 12345, 0, 0, optional_size, 0)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x10b if width == 4 else 0x20b)
    struct.pack_into('<II', data, optional + 56, 0x3000, 0x200)
    directory = optional + (96 if width == 4 else 112)
    struct.pack_into('<I', data, directory - 4, 16)
    struct.pack_into('<II', data, directory + 5 * 8, 0x2000, 12)
    section = optional + optional_size
    struct.pack_into('<8sIIIIIIHHI', data, section, b'.rdata', 0x200, 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<8sIIIIIIHHI', data, section + 40, b'.reloc', 0x200, 0x2000,
                     0x200, 0x400, 0, 0, 0, 0, 0x42000040)
    data[0x210:0x218] = b'constant'
    data[0x230:0x238] = b'constant'
    struct.pack_into('<IIHH', data, 0x400, 0x1000, 12,
                     ((3 if width == 4 else 10) << 12) | 0x10, 0)
    return data, directory, section


def main():
    resolver = CEBinaryResolver()
    try:
        from lupa.lua51 import LuaRuntime as Lua51
        from lupa.lua53 import LuaRuntime as Lua53
        runtimes = (Lua51, Lua53)
    except ImportError:
        runtimes = ()
        print('host reader execution skipped: Lupa unavailable')
    for width in (4, 8):
        data, directory, section = fixture(width)
        image = resolver.parse(bytes(data), 'host.dll')
        reference = image.find(b'constant')
        assert reference.offset == 0x1030  # The first match is relocated.
        assert reference.pointer_width == width
        assert reference.module == 'host.dll'
        assert image.image_hash == reference.image_hash
        assert image.find(b'missing') is None
        assert len(image.relocations) == 1
        provider = HostImageProvider(TargetProfile(environment='cheatengine', compatibility='binary_specific'), (image,))
        assert isinstance(provider.materialize(b'constant'), HostImageConstant)
        assert isinstance(provider.materialize(b'missing'), LiteralConstant)
        assert isinstance(provider.materialize(-0.0), LiteralConstant)
        reader = emit_host_reader((reference,)) + 'return _host_read(1)'
        assert 'constant' not in reader.replace('host constant', '')
        for factory in runtimes:
            lua = factory(encoding=None)
            lua.execute(b'''
                function getCheatEngineProcessID() return 7 end
                function enumModules(pid)
                    assert(pid==7)
                    return {{Name='HOST.DLL',Address=4096,PathToFile='host.dll',Is64Bit=IS64}}
                end
                function readBytesLocal(address,count,asTable)
                    assert(address==8240 and count==8 and asTable)
                    return {string.byte('constant',1,8)}
                end
            '''.replace(b'IS64', b'true' if width == 8 else b'false'))
            lua.globals()[b'md5file'] = lambda path: image.image_md5.encode()
            lua.globals()[b'stringToMD5String'] = lambda value: hashlib.md5(value).hexdigest().encode()
            assert lua.execute(reader.encode()) == b'constant'
            if factory is Lua51:
                from obfuscator.vm.targets.lua51 import Lua51Target
                assert lua.execute(Lua51Target().lower_source(reader).encode()) == b'constant'
            lua.globals()[b'md5file'] = lambda path: b'wrong-image'
            try:
                lua.execute(reader.encode())
            except Exception as error:
                assert 'host image mismatch' in str(error)
            else:
                raise AssertionError('wrong host binary accepted')
            lua.globals()[b'md5file'] = lambda path: image.image_md5.encode()
            lua.globals()[b'stringToMD5String'] = lambda value: b'changed-content'
            try:
                lua.execute(reader.encode())
            except Exception as error:
                assert 'host constant mismatch' in str(error)
            else:
                raise AssertionError('changed host memory accepted')
        # Writable sections and import-table sections are never candidates.
        writable = bytearray(data)
        struct.pack_into('<I', writable, section + 36, 0xc0000040)
        assert resolver.parse(bytes(writable), 'host.dll').find(b'constant') is None
        imports = bytearray(data)
        struct.pack_into('<II', imports, directory + 12 * 8, 0x1080, 8)
        assert resolver.parse(bytes(imports), 'host.dll').find(b'constant') is None
        overlapping = bytearray(data)
        struct.pack_into('<I', overlapping, section + 40 + 12, 0x1000)
        try:
            resolver.parse(bytes(overlapping), 'host.dll')
        except ValueError as error:
            assert 'overlapping' in str(error)
        else:
            raise AssertionError('overlapping mapped sections accepted')
        for truncated in (data[:60], data[:0x90], data[:0x300]):
            try:
                resolver.parse(bytes(truncated), 'host.dll')
            except ValueError:
                pass
            else:
                raise AssertionError('truncated image accepted')
    print('image-resolver-regression-ok PE32/PE32+ relocations imports writable truncation')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
