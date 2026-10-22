"""Native dump identity primitives for generated-source protection."""
from pathlib import Path
import re
import zlib


def checksum(data: bytes) -> int:
    return zlib.crc32(data) & 0xffffffff


def primitive_source(version: str, *, library_dump: bool = False, tailcalls: bool = True) -> str:
    # Exact nibble arithmetic keeps the same CRC on binary64 Lua 5.1 and 5.3.
    result = '''local _Bfloor=math.floor
local _BXor={}
for a=0,15 do for b=0,15 do
 local x,y,n,p=a,b,0,1
 for i=1,4 do if x%2~=y%2 then n=n+p end;x=_Bfloor(x/2);y=_Bfloor(y/2);p=p*2 end
 _BXor[a*16+b]=n
end end
local function _Bxor(a,b)
 local n,p=0,1
 for i=1,8 do n=n+_BXor[(a%16)*16+b%16]*p;a=_Bfloor(a/16);b=_Bfloor(b/16);p=p*16 end
 return n
end
local _BCrc={}
for i=0,255 do local n=i;for j=1,8 do
 if n%2==1 then n=_Bxor(_Bfloor(n/2),3988292384) else n=_Bfloor(n/2) end
end;_BCrc[i]=n end
local _Bbyte=string.byte
local function _Bcrc(data)
 local n=4294967295
 for i=1,#data do local b=_Bbyte(data,i);local lo=n%256
  local slot=_BXor[(lo%16)*16+b%16]+16*_BXor[_Bfloor(lo/16)*16+_Bfloor(b/16)]
  n=_Bxor(_BCrc[slot],_Bfloor(n/256))
 end
 return _Bxor(n,4294967295)
end
local _Bdump0=string.dump
local function _Bmul(a,b)
 local al=a%65536;local ah=_Bfloor(a/65536)
 local bl=b%65536;local bh=_Bfloor(b/65536)
 return (al*bl+((al*bh+ah*bl)%65536)*65536)%4294967296
end
'''
    if version=='5.3':
        result='''local function _Bxor(a,b) return (a~b)&4294967295 end
local function _Bmul(a,b) return (a*b)&4294967295 end
local _BCrc={}
for i=0,255 do local n=i;for j=1,8 do
 if n&1==1 then n=(n>>1)~3988292384 else n=n>>1 end
end;_BCrc[i]=n end
local _Bbyte=string.byte
local function _Bcrc(data)
 local n=4294967295
 for i=1,#data do n=_BCrc[(n~_Bbyte(data,i))&255]~(n>>8) end
 return n~4294967295
end
local _Bdump0=string.dump
'''
    if tailcalls:
        result += 'local _Bselect=select;local _Bunpack=' + ('unpack' if version=='5.1' else 'table.unpack') + '\n'
        result += '''local function _Bpack(...) return {n=_Bselect('#',...),...} end
local function _Bthunk(fn,...)
 local packet={n=_Bselect('#',...)+1,fn,...}
 local function release(fn,...) packet=nil;return fn(...) end
 return function() return release(_Bunpack(packet,1,packet.n)) end
end
local function _Btail(guard,thunk)
 local values=_Bpack(thunk())
 guard(true)
 return _Bunpack(values,1,values.n)
end
local _Bknown=setmetatable({},{__mode='k'})
local function _Bregister(fn) _Bknown[fn]=true;return fn end
local function _Broute(guard,fn,...)
 if _Bknown[fn] then return fn(...) end
 return _Btail(guard,_Bthunk(fn,...))
end
'''
    if version == '5.1':
        text = (Path(__file__).parent / 'runtimes/lua51/vm.lua').read_text(encoding='utf8')
        fragment = text[text.index('local function _normalize_function_dump'):text.index('--<<ENDTARGET_FUNCTION_DUMP>>')]
        fragment = re.sub(r',"(?:[^"\\]|\\.)*"\)', ')', fragment).replace('assert(', '_Bassert(')
        aliases = {'_native_string_byte':'string.byte', '_native_string_char':'string.char',
                   '_native_table_concat':'table.concat', '_native_math_floor':'math.floor',
                   '_native_string_dump':'_Bdump0'}
        result += 'local function _Bassert(v) if not v then error(nil,0) end;return v end\n'
        result += '\n'.join('local ' + key + '=' + value for key,value in aliases.items()) + '\n'
        result += fragment.replace('local function _function_dump', 'local function _Bdump')
    elif library_dump:
        from ..toolchain import LIBRARY_DUMP_FUNCTION
        result += 'local _Bdump=function(f) return ' + LIBRARY_DUMP_FUNCTION + '(f,true) end\n'
    else:
        result += 'local function _Bdump(f) return _Bdump0(f,true) end\n'
    return result
