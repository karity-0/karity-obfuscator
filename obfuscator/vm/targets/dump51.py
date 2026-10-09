"""Canonical checksum representation of standard Lua 5.1 function dumps."""
import struct


def normalize_dump(data: bytes) -> bytes:
    if len(data) < 12 or data[:6] != b'\x1bLua\x51\0':
        raise ValueError('expected a standard Lua 5.1 dump')
    endian, int_size, size_t, instruction_size, number_size, integral = data[6:12]
    if endian not in (0, 1) or int_size not in (4, 8) or size_t not in (4, 8) or (instruction_size, number_size, integral) != (4, 8, 0):
        raise ValueError('unsupported Lua 5.1 dump ABI')
    position = 12
    output = bytearray(b'KarityDump51\0')
    byteorder = 'little' if endian else 'big'

    def take(size):
        nonlocal position
        if size < 0 or position + size > len(data):
            raise ValueError('truncated Lua 5.1 dump')
        raw = data[position:position + size]
        position += size
        return raw

    def uint(size):
        value = int.from_bytes(take(size), byteorder)
        if value > 0xffffffff:
            raise ValueError('Lua 5.1 dump field exceeds canonical width')
        return value

    def put_uint(value):
        output.extend(struct.pack('<I', value))

    def count():
        value = uint(int_size)
        if value > 0x7fffffff:
            raise ValueError('negative Lua 5.1 dump count')
        return value

    def string(keep):
        size = uint(size_t)
        raw = take(size)
        if size and raw[-1:] != b'\0':
            raise ValueError('unterminated Lua 5.1 dump string')
        if keep:
            put_uint(size)
            output.extend(raw)

    def proto():
        string(False)  # Source names/debug tables do not affect executable code.
        put_uint(uint(int_size)); put_uint(uint(int_size))
        output.extend(take(4))  # nups, parameters, vararg flags, stack size.
        total = count(); put_uint(total)
        for _ in range(total):
            put_uint(uint(4))
        total = count(); put_uint(total)
        for _ in range(total):
            tag = take(1); output.extend(tag)
            if tag == b'\x01':
                output.extend(take(1))
            elif tag == b'\x03':
                raw = take(8); output.extend(raw if endian else raw[::-1])
            elif tag == b'\x04':
                string(True)
            elif tag != b'\0':
                raise ValueError('unknown Lua 5.1 dump constant tag')
        total = count(); put_uint(total)
        for _ in range(total):
            proto()
        take(count() * int_size)
        for _ in range(count()):
            string(False); take(int_size * 2)
        for _ in range(count()):
            string(False)

    proto()
    if position != len(data):
        raise ValueError('unexpected Lua 5.1 dump tail')
    return bytes(output)
