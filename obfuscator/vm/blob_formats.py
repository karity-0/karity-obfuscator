"""Bytecode storage alphabets and target-neutral UTF-8 byte decoders."""
from __future__ import annotations

from dataclasses import dataclass
import random


BLOB_FORMS = ("string", "table", "numeric", "emoji", "chinese")

# Single-codepoint emoji only: no variation selectors or joined sequences.
# Every entry occupies four UTF-8 bytes, so Lua 5.1 needs no utf8 library.
_EMOJI = tuple(chr(value) for start, end in (
    (0x1F600, 0x1F64F), (0x1F680, 0x1F6A5),
    (0x1F400, 0x1F43E), (0x1F330, 0x1F393),
) for value in range(start, end + 1))


@dataclass(frozen=True)
class UnicodeBlobCodec:
    alphabet: str
    width: int

    def literal(self, data: bytes) -> str:
        """One UTF-8 symbol per encrypted byte; no padding or length header."""
        return '"' + ''.join(self.alphabet[value] for value in data) + '"'

    def decoder(self) -> str:
        """Reassemble cipher bytes with bounded scratch storage before decrypting."""
        return (
            '(function(_data)'
            f'local _alphabet="{self.alphabet}";local _width={self.width};local _map={{}};'
            'for _i=1,#_alphabet,_width do '
            '_map[string.sub(_alphabet,_i,_i+_width-1)]=(_i-1)/_width end;'
            'local _out={};local _part={};'
            'for _i=1,#_data,_width do '
            '_part[#_part+1]=string.char(_map[string.sub(_data,_i,_i+_width-1)]);'
            'if #_part==4096 then _out[#_out+1]=table.concat(_part);_part={} end end;'
            'if #_part>0 then _out[#_out+1]=table.concat(_part) end;'
            'return table.concat(_out) end)(blob)'
        )


def unicode_blob_codec(form: str) -> UnicodeBlobCodec:
    if form == "emoji":
        return UnicodeBlobCodec(''.join(random.sample(_EMOJI, 256)), 4)
    if form == "chinese":
        # Basic CJK ideographs, each exactly three UTF-8 bytes.
        return UnicodeBlobCodec(''.join(chr(value) for value in
                                       random.sample(range(0x4E00, 0x9FA6), 256)), 3)
    raise ValueError(f"not a Unicode blob representation: {form}")
