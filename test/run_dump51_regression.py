"""Canonical dump parity across native Lua 5.1 size and endian layouts."""
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.dump51 import normalize_dump


def transcode(data, endian, int_size, size_t):
    old_endian, old_int, old_size_t = data[6:9]
    position = 12
    output = bytearray(data[:6] + bytes((endian, int_size, size_t, 4, 8, 0)))

    def take(size):
        nonlocal position
        result = data[position:position + size]
        position += size
        return result

    def integer(old, new):
        value = int.from_bytes(take(old), 'little' if old_endian else 'big')
        output.extend(value.to_bytes(new, 'little' if endian else 'big'))
        return value

    def string():
        size = integer(old_size_t, size_t)
        output.extend(take(size))

    def proto():
        string(); integer(old_int,int_size); integer(old_int,int_size)
        output.extend(take(4))
        for _ in range(integer(old_int,int_size)):
            integer(4,4)
        for _ in range(integer(old_int,int_size)):
            tag = take(1); output.extend(tag)
            if tag == b'\1': output.extend(take(1))
            elif tag == b'\3':
                raw = take(8); output.extend(raw if old_endian == endian else raw[::-1])
            elif tag == b'\4': string()
            else: assert tag == b'\0'
        for _ in range(integer(old_int,int_size)): proto()
        for _ in range(integer(old_int,int_size)): integer(old_int,int_size)
        for _ in range(integer(old_int,int_size)):
            string(); integer(old_int,int_size); integer(old_int,int_size)
        for _ in range(integer(old_int,int_size)): string()
    proto()
    assert position == len(data)
    return bytes(output)


def main():
    raw = (ROOT/'test/fixtures/ir/lua51_closure.luac').read_bytes()
    expected = normalize_dump(raw)
    try:
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(encoding=None)
        from obfuscator.vm.targets.lua51 import Lua51Target
        runtime=Lua51Target().runtime_template('vm.lua')
        prepared=Lua51Target().prepare_runtime(
            runtime,SimpleNamespace(backend_data={},backend='classic'))
        dump_hook=prepared.split('--<<TARGET_FUNCTION_DUMP>>',1)[1].split(
            '--<<ENDTARGET_FUNCTION_DUMP>>',1)[0]
        native_aliases=('local _native_string_dump,_native_string_byte,_native_string_char='
                        'string.dump,string.byte,string.char;'
                        'local _native_table_concat,_native_math_floor=table.concat,math.floor;')
        normalize=lua.execute((native_aliases+dump_hook+
                               ';return _normalize_function_dump').encode())
    except ImportError:
        normalize=None
    for endian in (0,1):
        for integers in (4,8):
            for sizes in (4,8):
                changed=transcode(raw,endian,integers,sizes)
                assert normalize_dump(changed)==expected
                if normalize: assert normalize(changed)==expected
    if normalize:
        dump=lua.eval(b'function(s,name) return string.dump(assert(loadstring(s,name))) end')
        first=dump(b'return function(alpha) return alpha+1 end',b'@first')
        second=dump(b'return function(beta) return beta+1 end',b'@second')
        assert first!=second and normalize(first)==normalize(second)
        third=dump(b'return function(beta) return beta+2 end',b'@second')
        assert normalize(third)!=normalize(first)
        target = Lua51Target()
        target._native_mov_uint = True
        source = target.lower_source('return function(...) return true end')
        original = lua.execute(source.encode())
        tampered_source = source.replace('MOV field overflow',
                                         'MOV field width rejected')
        assert tampered_source != source
        tampered = lua.execute(tampered_source.encode())
        dump_function = lua.eval(b'string.dump')
        # An unused helper error message changes the self-function checksum,
        # even though normal execution returns the same result.
        assert original() is True and tampered() is True
        assert normalize(dump_function(original)) != normalize(dump_function(tampered))

    for bad in (raw[:30],raw+b'extra',b'not bytecode'):
        try:
            normalize_dump(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('malformed dump accepted')
    print('dump51-regression-ok layouts=8 Python/Lua parity debug independence')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
