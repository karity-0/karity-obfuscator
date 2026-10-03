-- Lua 5.1 target runtime template; maintained independently from Lua 5.3.
-- Loader and Karity executor; generation markers are resolved by the target emitter.

----------------------------------------
--<<TARGET_RUNTIME_API>>
-- Private words are an exact-state representation only. They share neither a
-- metatable nor an arithmetic dispatcher with user-visible Lua values.
local _PRIVATE_WORD_MARKER={}
local function _is_private_word(value)
    return _native_type(value)=="table" and value._private_word==_PRIVATE_WORD_MARKER
end
local function _is_private_state(value)
    return _is_private_word(value)
end
local function _private_number(value)
    if value.hi>=2147483648 then
        local lo=(-value.lo)%4294967296
        local hi=(4294967295-value.hi+(lo==0 and 1 or 0))%4294967296
        return -(hi*4294967296.0+lo)
    end
    return value.hi*4294967296.0+value.lo
end
local function _number_kind(value)
    if _is_private_state(value) then return "integer" end
    return _native_type(value)=="number" and "float" or nil
end
local function _pack_values(...) return {n=_native_select("#",...),...} end
local function _unpack_values(values,first,last)
    return _native_unpack(values,first or 1,last or #values)
end
local function _target_hex64(value)
    if _is_private_state(value) then
        return _native_string_format("%08x",value.hi).._native_string_format("%08x",value.lo)
    end
    return _native_string_format("%016x",value)
end
--<<ENDTARGET_RUNTIME_API>>

--<<TARGET_INSTRUCTION_XOR>>
local _ixn={}
for a=0,15 do
    local row={};_ixn[a]=row
    for b=0,15 do
        local x,y,value,p=a,b,0,1
        for _=1,4 do
            local ax,by=x%2,y%2
            if ax~=by then value=value+p end
            x=math.floor(x/2);y=math.floor(y/2);p=p*2
        end
        row[b]=value
    end
end
local function _ixor(a,b)
    local value,p=0,1
    for _=1,12 do
        local an,bn=a%16,b%16
        value=value+_ixn[an][bn]*p
        a=math.floor(a/16);b=math.floor(b/16);p=p*16
    end
    return value
end
local function _ifield48(value,shift,width)
    return math.floor(value/2^shift)%width
end
local function _integrity_xor(a,b)
    local word,mask
    if not _is_private_state(a) and _native_type(a)=='table' then word,mask=a,b
    elseif not _is_private_state(b) and _native_type(b)=='table' then word,mask=b,a
    elseif _is_private_state(a) then return _ixor(a.lo,b)
    elseif _is_private_state(b) then return _ixor(a,b.lo)
    else return _ixor(a,b) end
    local lo,hi=_ixor(word[1],mask),word[2]
    if hi>=2147483648 then
        return -((4294967295-hi)*4294967296.0+(4294967296.0-lo))
    end
    return hi*4294967296.0+lo
end
--<<ENDTARGET_INSTRUCTION_XOR>>

--<<TARGET_BLOB_CIPHER>>
local _KAE_PRIMES={7,11,13,17,19,23,29,31}
local function _gf_mul(a,b)
    local p=0
    for _=1,8 do
        if b%2~=0 then p=_ixor(p,a) end
        local high=a>=128
        a=(a*2)%256
        if high then a=_ixor(a,27) end
        b=math.floor(b/2)
    end
    return p
end
local _KAE_SBOX do
    local function _gf_inv(x)
        if x==0 then return 0 end
        local result,base,exponent=1,x,254
        while exponent>0 do
            if exponent%2~=0 then result=_gf_mul(result,base) end
            base=_gf_mul(base,base);exponent=math.floor(exponent/2)
        end
        return result
    end
    local function _bit(value,index) return math.floor(value/2^index)%2 end
    local function _affine(x)
        local constant,result=99,0
        for i=0,7 do
            local bit=(_bit(x,i)+_bit(x,(i+4)%8)+_bit(x,(i+5)%8)+
                       _bit(x,(i+6)%8)+_bit(x,(i+7)%8)+_bit(constant,i))%2
            result=result+bit*2^i
        end
        return result
    end
    _KAE_SBOX={}
    for i=0,255 do _KAE_SBOX[i]=_affine(_gf_inv(i)) end
end
local function _kae_derive(key_bytes,length)
    local keys,previous={},106
    for i=0,length-1 do
        local k0=key_bytes[i%#key_bytes+1]
        local index=_ixor(_ixor(k0,i),math.floor(i/8))%256
        local raw=_gf_mul(_KAE_SBOX[index],_KAE_PRIMES[i%8+1])
        local rotated=(previous*8)%256+math.floor(previous/32)
        local key=_ixor(_ixor(raw,rotated),(i*151)%256)%256
        keys[i+1]=key;previous=key
    end
    return keys
end
local function kae_decrypt(blob,key)
    local nonce={}
    for i=1,8 do nonce[i]=string.byte(blob,i) end
    local length=#blob-8
    local key_bytes={}
    for i=1,#key do key_bytes[i]=string.byte(key,i) end
    local blended={}
    for i=0,length+7 do
        blended[i+1]=_ixor(_ixor(key_bytes[i%#key_bytes+1],nonce[i%8+1]),
                            _KAE_SBOX[i%256])%256
    end
    local round_keys=_kae_derive(blended,length)
    local plain={}
    for i=1,length do plain[i]=_ixor(string.byte(blob,8+i),round_keys[i])%256 end
    local chunks={}
    for i=1,#plain,4096 do
        local last=i+4095;if last>#plain then last=#plain end
        chunks[#chunks+1]=string.char(_unpack_values(plain,i,last))
    end
    return table.concat(chunks)
end
--<<ENDTARGET_BLOB_CIPHER>>

----------------------------------------

local _CRC_TABLE
--<<TARGET_CRC>>
local function _crc32(data)
    local __VM_HOT_LOOP__=true
    if not _CRC_TABLE then
        _CRC_TABLE={}
        for i=0,255 do
            local c=i
            for _=1,8 do
                if c%2~=0 then c=_ixor(3988292384,math.floor(c/2))
                else c=math.floor(c/2) end
            end
            _CRC_TABLE[i]=c
        end
    end
    local crc=4294967295
    for i=1,#data do
        local b=string.byte(data,i)
        crc=_ixor(_CRC_TABLE[_ixor(crc,b)%256],math.floor(crc/256))
    end
    return _ixor(crc,4294967295)
end
--<<ENDTARGET_CRC>>

----------------------------------------

--<<TARGET_BLOB_BASE>>
local function from_base36(s)
    if string.sub(s,1,7) ~= "KARITY/" then error("invalid blob") end
    s = string.sub(s,8)
    local sep = string.find(s,':',1,true)
    local length = 0
    for i=1,sep-1 do
        local c=string.byte(s,i)
        length=length*36+(c>=48 and c<=57 and c-48 or c-55)
    end
    local bytes={}
    local i=sep+1
    while i+6<=#s do
        local n=0
        for j=i,i+6 do
            local c=string.byte(s,j)
            n=n*36+(c>=48 and c<=57 and c-48 or c-55)
        end
        bytes[#bytes+1]=n%256
        bytes[#bytes+1]=math.floor(n/256)%256
        bytes[#bytes+1]=math.floor(n/65536)%256
        bytes[#bytes+1]=math.floor(n/16777216)%256
        i=i+7
    end
    while #bytes>length do bytes[#bytes]=nil end
    local chunks={}
    for j=1,#bytes,4096 do
        local last=j+4095; if last>#bytes then last=#bytes end
        chunks[#chunks+1]=string.char(table.unpack(bytes,j,last))
    end
    return table.concat(chunks)
end
--<<ENDTARGET_BLOB_BASE>>

--<<TARGET_READER_PRIMITIVES>>
local function make_reader(blob)
    local pos=1; local r={}
    function r.u8() local v=string.byte(blob,pos); pos=pos+1; return v end
    function r.u16()
        local a,b=string.byte(blob,pos,pos+1); pos=pos+2
        return a+b*256
    end
    function r.u32()
        local a,b,c,d=string.byte(blob,pos,pos+3); pos=pos+4
        return a+b*256+c*65536+d*16777216
    end
    function r.u64()
        local lo=r.u32(); local hi=r.u32()
        --<<TARGET_WORD_READ>>
return {lo,hi}
--<<ENDTARGET_WORD_READ>>
    end
    function r.iword()
        local lo=r.u32(); local hi=r.u32()
        --<<TARGET_INSTRUCTION_READ>>
return lo+(hi%65536)*4294967296.0
--<<ENDTARGET_INSTRUCTION_READ>>
    end
    function r.i64()
        --<<TARGET_SIGNED_READ>>
local lo,hi=r.u32(),r.u32()
        if hi>=2147483648 then
            return -((4294967295-hi)*4294967296.0+(4294967296.0-lo))
        end
        return hi*4294967296.0+lo
--<<ENDTARGET_SIGNED_READ>>
    end
    function r.f64()
        --<<TARGET_FLOAT_READ>>
local lo,hi=0,0
        for i=3,0,-1 do
            lo=lo*256+string.byte(blob,pos+i)
            hi=hi*256+string.byte(blob,pos+4+i)
        end
        pos=pos+8
        local sign=hi>=2147483648 and -1 or 1
        local exponent=math.floor(hi/1048576)%2048
        local fraction=(hi%1048576)*4294967296.0+lo
        local value
        if exponent==2047 then value=fraction==0 and math.huge or 0/0
        elseif exponent==0 then value=math.ldexp(fraction,-1074)
        else value=math.ldexp(1+fraction/4503599627370496.0,exponent-1023) end
        return sign*value
--<<ENDTARGET_FLOAT_READ>>
    end
    function r.str()
        local len=r.u32(); if len==0 then return nil end
        local sv=string.sub(blob,pos,pos+len-1); pos=pos+len; return sv
    end
    return r
end
--<<ENDTARGET_READER_PRIMITIVES>>

local CTAG_NIL=__VM_CTAG_NIL__;local CTAG_BOOL=__VM_CTAG_BOOL__;local CTAG_INT=__VM_CTAG_INT__;local CTAG_FLOAT=__VM_CTAG_FLOAT__;local CTAG_STR=__VM_CTAG_STR__;local CTAG_IEXPR=__VM_CTAG_IEXPR__
local CK_NIL=__VM_CK_NIL__;local CK_BOOL=__VM_CK_BOOL__;local CK_INT=__VM_CK_INT__;local CK_FLOAT=__VM_CK_FLOAT__;local CK_STR=__VM_CK_STR__;local CK_IEXPR=__VM_CK_IEXPR__
local _IT={seed=0,layout=0,vmc=1,script=0,line=0}

-- 런타임 내부 keystream: read_proto가 디코드 직후 code[i]를 메모리에서 한 번 더
-- 마스킹하고, exec가 fetch 시점에 동일 마스크로 푼다. 따라서 메모리에 상주하는
-- p.code[]는 항상 마스킹된 상태(평문 명령어가 통째로 상주하지 않음).
-- _ksd는 run()에서 crc로 세팅 -> 리터럴이 아니고 tamper에 엮임. read_proto와
-- exec가 같은 _ksd를 쓰므로 한 run 안에서 항상 round-trip(실행 정확성 보장).
local _ksd=0
--<<TARGET_INSTRUCTION_STATE_KEY>>
local function _ikey48(value)
    if _is_private_state(value) then
        return value.lo+(value.hi%65536)*4294967296.0
    end
    return value%281474976710656.0
end
--<<ENDTARGET_INSTRUCTION_STATE_KEY>>
--<<KSTREAM>>
local function _ksm(i)
    local x=(i*0x9E3779B1)&0xFFFFFFFFFFFF
    x=(x~((_ksd*0x85EBCA6B)&0xFFFFFFFFFFFF))&0xFFFFFFFFFFFF
    x=(x~(x>>17)~((i<<13)&0xFFFFFFFFFFFF))&0xFFFFFFFFFFFF
    return x
end

-- 문자열 상수용 keystream(대칭 XOR). read_proto가 상수풀에 마스킹 저장하고,
-- kval/상수 pre-unpack 시점에 풀어 쓴다. -> p.constants(상수 풀)는 메모리에서
-- 마스킹된 상태로 상주(연속된 평문 상수 덤프 타깃 제거). regs로 풀린 값은 평문.
local function _kss(s)
    local out={}
    for i=1,#s do
        local m=((i*0x6D)~_ksd~(i>>3))&0xFF
        out[i]=(string.byte(s,i)~m)&0xFF
    end
    local chunks={}
    for i=1,#out,4096 do
        local last=i+4095; if last>#out then last=#out end
        chunks[#chunks+1]=string.char(table.unpack(out,i,last))
    end
    return table.concat(chunks)
end
--<<ENDKSTREAM>>

-- instruction 워드 필드 시프트. 파이프라인이 per-run 랜덤 레이아웃으로 인라인한다
-- (serializer의 packing과 동일 레이아웃 공유). 아래 def는 standalone 실행용 기본값.
-- op은 비트 0 고정(7비트), B=C+9 연속(Bx=B|C), 모든 필드는 _ksm 48비트 마스크 범위 안.
local _SH_A,_SH_B,_SH_C,_SH_V=32,23,14,40
local _MASK_OV=0xFF000000007F

local function read_proto(r, acc_state)
    local p={}
    p.num_params=r.u8(); p.is_vararg=r.u8(); p.max_stack_size=r.u8()
    p.vm_id=r.u8()
    local n=r.u32(); p.code={}
    --<<TARGET_PROTO_CODE>>
for i=1,n do
        local raw64=r.iword()
        --<<TARGET_INSTRUCTION_FIELDS>>
        local enc_op=raw64%128
        local enc_variant=math.floor(raw64/2^_SH_V)%256
        --<<ENDTARGET_INSTRUCTION_FIELDS>>
        local acc=acc_state[1];local idx=acc_state[2]
        local actual_op=_ixor(enc_op,acc%128)
        local actual_variant=_ixor(enc_variant,math.floor(acc/128)%256)
        local actual_vop=actual_op+actual_variant*128
        acc_state[1]=(acc+actual_vop+idx)%65536
        acc_state[2]=idx+1
        --<<TARGET_WORD_REKEY>>
        local _variant_scale=2^_SH_V
        raw64=raw64-(raw64%128)-(math.floor(raw64/_variant_scale)%256)*_variant_scale+
              actual_op+actual_variant*_variant_scale
        --<<ENDTARGET_WORD_REKEY>>
        p.code[i]=_ixor(raw64,_ksm(i))
    end
--<<ENDTARGET_PROTO_CODE>>
    --<<TARGET_PROTO_METADATA>>
p.avalanche={}
    for i=1,n do
        local an=r.u8()
        if an>0 then
            local slots={}
            for j=1,an do slots[j]=r.u8() end
            p.avalanche[i]=slots
        end
    end
    p.graph_sites={}
    for i=1,n do
        local sn=r.u8()
        if sn>0 then
            local sites={}
            for j=1,sn do
                local family=r.u8()
                local policy=r.u8()
                local state_key=r.u16()
                local site=r.u32()
                local selector=r.u32()
                sites[j]={family,site,selector,state_key,policy}
            end
            p.graph_sites[i]=sites
        end
    end
    n=r.u16();p.block_routes={}
    for i=1,n do
        local rn=r.u8();local route={}
        for j=1,rn do route[j]=r.u32() end
        p.block_routes[i]=route
    end
    n=r.u32();p.constants={}
    for i=1,n do
        local tag=r.u8()
        if tag==CTAG_NIL then p.constants[i]={CK_NIL}
        elseif tag==CTAG_BOOL then p.constants[i]={CK_BOOL,r.u8()~=0}
        elseif tag==CTAG_INT then p.constants[i]={CK_INT,r.i64()}
        elseif tag==CTAG_FLOAT then p.constants[i]={CK_FLOAT,r.f64()}
        elseif tag==CTAG_STR then local _s=r.str() or '';p.constants[i]={CK_STR,_kss(_s)}
        elseif tag==CTAG_IEXPR then
            local _e=r.u64();local _pn=r.u8();local _p={}
            for _j=1,_pn do
                local _op=r.u8()
                if _op==1 then _p[_j]={_op,r.u32()} else _p[_j]={_op} end
            end
            p.constants[i]={CK_IEXPR,_e,_p}
        else error('bad const tag '..tostring(tag)) end
    end
--<<ENDTARGET_PROTO_METADATA>>
    n=r.u32(); p.upvalues={}
    --<<TARGET_PROTO_CHILDREN>>
for i=1,n do
        p.upvalues[i]={instack=r.u8(),idx=r.u8()}
    end
    n=r.u32();p.protos={}
    for i=1,n do p.protos[i]=read_proto(r,acc_state) end
--<<ENDTARGET_PROTO_CHILDREN>>
    return p
end

--<<TARGET_INTEGRITY_MIX>>
local _IU32=4294967296
local function _iu32(value)
    if _is_private_word(value) then
        return value.lo
    end
    return value%_IU32
end
local function _imul32(a,b)
    local a0,a1=a%65536,math.floor(a/65536)
    local b0,b1=b%65536,math.floor(b/65536)
    return (a0*b0+((a0*b1+a1*b0)%65536)*65536)%_IU32
end
local function _imix(proto)
    local value=_ixor(_iu32(_IT.seed),(_iu32(_IT.vmc)%65536)*2048)
    value=_ixor(value,_iu32(_IT.layout))
    value=_ixor(value,(_iu32(proto.vm_id)%256)*8388608)
    return _ixor(value,_imul32(#proto.code%65536,73244475))%_IU32
end
--<<ENDTARGET_INTEGRITY_MIX>>

--<<TARGET_INTEGRITY_EXPRESSION>>
local function _ieval(prog,proto)
    local st,sp={},0
    for i=1,#prog do
        local ins=prog[i];local op=ins[1]
        if op==1 then sp=sp+1;st[sp]=_iu32(ins[2])
        elseif op==2 then sp=sp+1;st[sp]=_iu32(_IT.seed)
        elseif op==3 then sp=sp+1;st[sp]=_iu32(_IT.vmc)
        elseif op==4 then sp=sp+1;st[sp]=_iu32(_IT.layout)
        elseif op==5 then sp=sp+1;st[sp]=_iu32(proto.vm_id)
        elseif op==6 then sp=sp+1;st[sp]=#proto.code%_IU32
        elseif op==10 then sp=sp+1;st[sp]=_iu32(_IT.script)
        elseif op==11 then sp=sp+1;st[sp]=_iu32(_IT.line)
        else
            local b=st[sp];local a=st[sp-1];sp=sp-1
            if op==7 then st[sp]=_ixor(a,b)%_IU32
            elseif op==8 then st[sp]=(a+b)%_IU32
            elseif op==9 then st[sp]=_imul32(a,b-(b%2)+1)
            else st[sp]=_ixor(a,b)%_IU32 end
        end
    end
    return st[sp]%_IU32
end
--<<ENDTARGET_INTEGRITY_EXPRESSION>>

--<<TARGET_CONSTANT_RESOLVER>>
local function kval(k,proto)
    if not k then return nil end
    if k[1]==CK_NIL then return nil end
    if k[1]==CK_STR and k[2] then return _kss(k[2]) end
    if k[1]==CK_IEXPR then
        --<<TARGET_INTEGRITY_DECODE>>
        return _integrity_xor(k[2],_ieval(k[3],proto))
        --<<ENDTARGET_INTEGRITY_DECODE>>
    end
    return k[2]
end
--<<ENDTARGET_CONSTANT_RESOLVER>>

local function decode(ins,key)
    --<<TARGET_INSTRUCTION_DECODE>>
ins=_ixor(ins,key)
    local op=ins%128
    local A=math.floor(ins/2^_SH_A)%256
    local B=math.floor(ins/2^_SH_B)%512
    local C=math.floor(ins/2^_SH_C)%512
    local variant=math.floor(ins/2^_SH_V)%256
    local Bx=math.floor(ins/2^_SH_C)%262144
    local sBx=Bx-131071
    return op+variant*128,A,B,C,Bx,sBx
--<<ENDTARGET_INSTRUCTION_DECODE>>
end

local function get_environment(upvals) return upvals.environment end
local function bind_environment(fn,values,parent)
    values.environment=get_environment(parent)
    return fn
end
--<<TARGET_SOURCE_VALUE>>
local function _source_value(v)
    if _is_private_word(v) then return _private_number(v) end
    return v
end
--<<ENDTARGET_SOURCE_VALUE>>

local exec, _EX, _NX
-- Closures own their descriptors; this registry must not root environment or
-- recursive-upvalue cycles on runtimes without ephemeron weak-key tables.
local _VF=setmetatable({},{__mode="kv"})

--<<TARGET_PRIVATE_MIX>>
local function _pmul64(hi,lo,khi,klo)
    local a0,a1,a2,a3=lo%65536,math.floor(lo/65536),hi%65536,math.floor(hi/65536)
    local b0,b1,b2,b3=klo%65536,math.floor(klo/65536),khi%65536,math.floor(khi/65536)
    local value=a0*b0
    local r0=value%65536;local carry=math.floor(value/65536)
    value=carry+a0*b1+a1*b0
    local r1=value%65536;carry=math.floor(value/65536)
    value=carry+a0*b2+a1*b1+a2*b0
    local r2=value%65536;carry=math.floor(value/65536)
    value=carry+a0*b3+a1*b2+a2*b1+a3*b0
    local r3=value%65536
    return r2+r3*65536,r0+r1*65536
end
local _private_literals={}
local function _pnew(hi,lo)
    return {hi=hi,lo=lo,_private_word=_PRIVATE_WORD_MARKER}
end
local function _pisword(value)
    return _is_private_word(value)
end
local function _pint(text)
    local value=_private_literals[text]
    if not value then
        local hi,lo=0,0
        for index=1,#text do
            local digit=string.byte(text,index)-48
            hi,lo=_pmul64(hi,lo,0,10)
            lo=lo+digit
            if lo>=4294967296 then lo=lo-4294967296;hi=(hi+1)%4294967296 end
        end
        value=_pnew(hi,lo);_private_literals[text]=value
    end
    return value
end
local function _pword(value)
    if _pisword(value) then return value.hi,value.lo end
    if value>=0 then return math.floor(value/4294967296)%4294967296,value%4294967296 end
    local magnitude=-value
    local lo=(-magnitude)%4294967296
    local hi=(4294967295-math.floor(magnitude/4294967296)+(lo==0 and 1 or 0))%4294967296
    return hi,lo
end
local function _peq(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    return ahi==bhi and alo==blo
end
local function _plow(value,modulus)
    local _,lo=_pword(value)
    return lo%modulus
end
local function _pmod(value,modulus)
    local hi,lo=_pword(value)
    local limb=4294967296%modulus
    local result=((hi%modulus)*limb+(lo%modulus))%modulus
    if hi>=2147483648 then result=(result-(limb*limb)%modulus)%modulus end
    return result
end
local function _padd(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    local lo=alo+blo
    return _pnew((ahi+bhi+math.floor(lo/4294967296))%4294967296,lo%4294967296)
end
local function _pneg(a)
    local hi,lo=_pword(a);lo=(-lo)%4294967296
    return _pnew((4294967295-hi+(lo==0 and 1 or 0))%4294967296,lo)
end
local function _psub(a,b) return _padd(a,_pneg(b)) end
local function _pmul(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    local hi,lo=_pmul64(ahi,alo,bhi,blo)
    return _pnew(hi,lo)
end
local function _pmul_low(a,b,modulus)
    local _,lo=_pmul64(0,a,0,b)
    return lo%modulus
end
local function _pand_limb(a,b) return (a+b-_ixor(a,b))/2 end
local function _por_limb(a,b) return (a+b+_ixor(a,b))/2 end
local function _pband(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    return _pnew(_pand_limb(ahi,bhi),_pand_limb(alo,blo))
end
local function _pxor(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    return _pnew(_ixor(ahi,bhi),_ixor(alo,blo))
end
local function _pbor(a,b)
    local ahi,alo=_pword(a);local bhi,blo=_pword(b)
    return _pnew(_por_limb(ahi,bhi),_por_limb(alo,blo))
end
local function _pnot(a)
    local hi,lo=_pword(a)
    return _pnew(4294967295-hi,4294967295-lo)
end
local function _pshift_count(value)
    if not _pisword(value) then return value end
    if value.hi<2147483648 then return value.hi==0 and value.lo or 64 end
    local lo=(-value.lo)%4294967296
    local hi=(4294967295-value.hi+(lo==0 and 1 or 0))%4294967296
    return hi==0 and lo<64 and -lo or -64
end
local function _plow_shift(value,count,modulus,right)
    local hi,lo=_pword(value)
    count=_pshift_count(count)
    if right then count=-count end
    if count>=32 then return 0 end
    if count>=0 then return ((lo%2^(32-count))*2^count)%modulus end
    count=-count
    if count>=64 then return 0 end
    if count>=32 then return math.floor(hi/2^(count-32))%modulus end
    return (math.floor(lo/2^count)+(hi%2^count)*2^(32-count))%modulus
end
local _pshl,_pshr
_pshl=function(a,n)
    local hi,lo=_pword(a);n=_pshift_count(n)
    if n<0 then return _pshr(a,-n) end
    if n>=64 then return _pnew(0,0) end
    if n==0 then return _pnew(hi,lo) end
    if n>=32 then return _pnew((lo%2^(64-n))*2^(n-32),0) end
    return _pnew((hi%2^(32-n))*2^n+math.floor(lo/2^(32-n)),(lo%2^(32-n))*2^n)
end
_pshr=function(a,n)
    local hi,lo=_pword(a);n=_pshift_count(n)
    if n<0 then return _pshl(a,-n) end
    if n>=64 then return _pnew(0,0) end
    if n==0 then return _pnew(hi,lo) end
    if n>=32 then return _pnew(0,math.floor(hi/2^(n-32))) end
    return _pnew(math.floor(hi/2^n),math.floor(lo/2^n)+(hi%2^n)*2^(32-n))
end
local function _pmix_words(hi,lo)
    local function shift_xor(n)
        local shifted_hi=math.floor(hi/2^n)
        local shifted_lo=math.floor(lo/2^n)+(hi%2^n)*2^(32-n)
        hi,lo=_ixor(hi,shifted_hi),_ixor(lo,shifted_lo)
    end
    shift_xor(30);hi,lo=_pmul64(hi,lo,3210233709,484763065)
    shift_xor(27);hi,lo=_pmul64(hi,lo,2496678331,321982955)
    shift_xor(31)
    return hi,lo
end
local function _pmix(x)
    local hi,lo=_pmix_words(_pword(x))
    return _pnew(hi,lo)
end
--<<ENDTARGET_PRIVATE_MIX>>

-- Karity continuation frames carry exact private state, but PC/top/handler
-- fields remain proved small native values once unmasked.  Keep the crossing
-- explicit instead of relying on the generic Lua 5.3 expression translator.
local function _frame_encode(value,mask) return _pxor(value,mask) end
local function _frame_decode(value,mask) return _private_number(_pxor(value,mask)) end
local function _frame_state(value,mask)
    return _ixor(value%256,_plow(mask,256))
end

local _AR=__VM_ARITH_BUNDLE__
local _GV=__VM_VALUE_GRAPHS__
local _CG=__VM_CALL_GRAPHS__
local _FG=__VM_CONTROL_GRAPHS__
local _OG=__VM_OCCURRENCE_GRAPHS__
local _LG=__VM_LOOP_GRAPHS__
local _DG=__VM_SEMANTIC_GRAPHS__
local _RP=__VM_AFFINE_POOL__
local _MP=__VM_REGISTER_MAPS__
local _PY=__VM_POLY_THRESHOLD__
local _SY=__VM_SEMANTIC_STATE__
local _AY=__VM_ARGUMENT_VIRTUALIZATION__
local _UY=__VM_UPVALUE_VIRTUALIZATION__
local _TY=__VM_TABLE_VIRTUALIZATION__
local _BY=__VM_BRANCH_VIRTUALIZATION__
local _PN,_PE=0,0
--<<RUNTIME_TRACE>>
local _PX,_PBC,_PBH=0,0,0
--<<ENDRUNTIME_TRACE>>

local function _vid(p)
    return p.vm_id
end

--<<TARGET_ARGUMENT_PACKET>>
local _AC=0
local _AN={}
local _AU32=4294967296
local function _aword(value)
    -- This packet helper is also extracted for standalone target tests, so
    -- keep its pair check local instead of capturing the loader sentinel.
    if _native_type(value)=='table' and value._private_word~=nil then
        return {value.hi,value.lo}
    end
    if _native_type(value)=='table' then return value end
    if value<0 then
        local magnitude=-value
        local lo=(-magnitude)%_AU32
        return {(4294967295-math.floor(magnitude/_AU32)+(lo==0 and 1 or 0))%_AU32,lo}
    end
    return {math.floor(value/_AU32)%_AU32,value%_AU32}
end
local function _axor_word(a,b)
    a,b=_aword(a),_aword(b)
    return {_ixor(a[1],b[1]),_ixor(a[2],b[2])}
end
local function _aadd_word(a,b)
    a,b=_aword(a),_aword(b)
    local lo=a[2]+b[2]
    return {(a[1]+b[1]+math.floor(lo/_AU32))%_AU32,lo%_AU32}
end
local function _amix_word(value)
    value=_aword(value)
    local hi,lo=_pmix_words(value[1],value[2])
    return {hi,lo}
end
local function _aword_key(value)
    value=_aword(value)
    return tostring(value[1])..':'..tostring(value[2])
end
local function _ashift_counter(value)
    return {math.floor(value/2048)%_AU32,(value%2048)*2097152}
end
local function _aseed(q)
    local seed=_axor_word(q[__VM_AP_SEED__],__VM_ARG_MASK__)
    seed=_axor_word(seed,_IT.layout or 0)
    return _axor_word(seed,_ksd)
end
local function _akey(seed,i)
    local hi,lo=_pmul64(0,i%_AU32,2654435769,2135587861)
    return _aword_key(_amix_word(_axor_word(_axor_word(seed,{hi,lo}),__VM_ARG_KEY__)))
end
local function _apack(values,n,flow)
    if not _AY then values.n=n; return values end
    _AC=_AC+1
    local seed=_axor_word(_PN,_IT.seed or 0)
    seed=_axor_word(seed,flow or 0)
    seed=_axor_word(seed,n)
    seed=_amix_word(_axor_word(seed,_ashift_counter(_AC)))
    local q={
        [__VM_AP_MARK__]=__VM_ARG_TAG__,
        [__VM_AP_SEED__]=_axor_word(_axor_word(_axor_word(seed,__VM_ARG_MASK__),_IT.layout or 0),_ksd),
        [__VM_AP_COUNT__]=_ixor(n,seed[2]%2147483648),
        [__VM_AP_DATA__]={},
    }
    local data=q[__VM_AP_DATA__]
    for i=1,n do
        local v=values[i]
        data[_akey(seed,i)]=(v==nil and _AN or v)
    end
    local pads=seed[2]%4+1
    for i=1,pads do
        local pad=_amix_word(_axor_word(_axor_word(seed,i),__VM_ARG_PAD__))
        data[_aword_key(pad)]=_amix_word(_aadd_word(seed,i))
    end
    return q
end
local function _acount(q)
    if q and q[__VM_AP_MARK__]==__VM_ARG_TAG__ then
        local seed=_aseed(q)
        return _ixor(q[__VM_AP_COUNT__],seed[2]%2147483648)
    end
    return q and (q.n or #q) or 0
end
local function _aget(q,i)
    if q and q[__VM_AP_MARK__]==__VM_ARG_TAG__ then
        if i>_acount(q) then return nil end
        local v=q[__VM_AP_DATA__][_akey(_aseed(q),i)]
        if v==nil then error('argument packet mismatch '..i..'/'.._acount(q)) end
        if v==_AN then return nil end
        return v
    end
    if q then return q[i] end
    return nil
end
--<<ENDTARGET_ARGUMENT_PACKET>>

local _UV=setmetatable({},{__mode="k"})
-- Lua table keys equate both zero signs; value identity must preserve them.
local _negative_zero_key={}
local function _value_key(v)
    if type(v)=="number" and v==0 and 1/v<0 then return _negative_zero_key end
    return v
end
local _UO={}
local _UI=setmetatable({},{__mode="k"})
local _UC=0
local _TM=setmetatable({},{__mode="k"})
local _TC=0

--<<EXEC>>
exec = function(proto, upvals, args, va_in, _fr, _kk, _rr, _zz, _xx)
    --<<TARGET_EXEC_PRIVATE_BINDINGS>>
    --<<ENDTARGET_EXEC_PRIVATE_BINDINGS>>
    local _fm    = _fr and _fr[__VM_FR_MASK__] or 0
    local regs   = _fr and _fr[__VM_FR_REGS__] or {}
    local boxes  = _fr and _fr[__VM_FR_BOXES__] or {}
    local consts = proto["constants"]
    local _subs  = proto["protos"]
    local code   = proto["code"]
    local _avd   = proto["avalanche"]
    local _gsd   = proto["graph_sites"]
    local _brd   = proto["block_routes"]
    local _cd    = code   -- rename되지 않는 code 별칭 (fused 핸들러가 다음 슬롯을 읽을 때 사용)
    local pc     = _fr and _frame_decode(_fr[__VM_FR_PC__],_fm) or 1
    local top    = _fr and _frame_decode(_fr[__VM_FR_TOP__],_fm) or -1
    local _st    = _fr and _frame_state(_fr[__VM_FR_STATE__],_fm) or 0
    local _va    = _fr and _fr[__VM_FR_VARARG__] or va_in or {}
    local _split_tmp = _fr and _fr[__VM_FR_SPLIT__]
    local _split_share = _fr and _fr[__VM_FR_SPLIT_SHARE__]
    local _split_epoch = _fr and _fr[__VM_FR_SPLIT_EPOCH__]
    local _split_kind = _fr and _fr[__VM_FR_SPLIT_TYPE__]
    local _S     = _fr and _fr[__VM_FR_SCRATCH__] or {[611]=_zz or 0}
    local _MJ    = {}
    --<<TARGET_KARITY_EXEC_STATE>>
    -- Store helpers as table fields so protected executor branches do not
    -- consume scarce Lua 5.1 local slots.
    _MJ._c_u32=function(value) return _iu32(value) end
    _MJ._c_xor=function(a,b) return _ixor(_MJ._c_u32(a),_MJ._c_u32(b)) end
    _MJ._c_and=function(a,b)
        a,b=_MJ._c_u32(a),_MJ._c_u32(b)
        return (a+b-_ixor(a,b))/2
    end
    _MJ._c_or=function(a,b)
        a,b=_MJ._c_u32(a),_MJ._c_u32(b)
        return (a+b+_ixor(a,b))/2
    end
    _MJ._c_not=function(value) return 4294967295-_MJ._c_u32(value) end
    _MJ._c_shl=function(value,count)
        count=_MJ._c_u32(count)
        if count>=32 then return 0 end
        return (_MJ._c_u32(value)%2^(32-count))*2^count
    end
    _MJ._c_shr=function(value,count)
        count=_MJ._c_u32(count)
        if count>=32 then return 0 end
        return math.floor(_MJ._c_u32(value)/2^count)
    end
    --<<ENDTARGET_KARITY_EXEC_STATE>>
    -- Mutation CFF and decoy handlers share this executor-local scratch
    -- table.  Keeping their temporary values out of branch-local declarations
    -- is necessary on Lua 5.1, whose compiler caps a function at 200 locals.
    local _AA    = _fr and _fr[__VM_FR_ACTIVE__] or {}
    local _FC    = _fr and _fr[__VM_FR_FLOW_CACHE__] or {}
    local _SC    = _fr and _fr[__VM_FR_SEM_CACHE__] or {}
    local _LC    = _fr and _fr[__VM_FR_LOOP_CACHE__] or {}
    local _GC    = _fr and _fr[__VM_FR_GRAPH_CACHE__] or {}
    local _RS    = _fr and _fr[__VM_FR_REG_SHARES__] or {}
    local _RE    = _fr and _fr[__VM_FR_REG_EPOCHS__] or {}
    local _RT    = _fr and _fr[__VM_FR_REG_TYPES__] or {}
    local _RO    = _fr and _fr[__VM_FR_VALUE_VAULT__] or {}
    local _RI    = _fr and _fr[__VM_FR_VALUE_INDEX__] or setmetatable({},{__mode="k"})
    local _RX    = _fr and _fr[__VM_FR_REPR_COUNTERS__] or {0,0}
    local _PD    = _fr and _fr[__VM_FR_PENDING__] or {}
    local _RZ    = _fr and _fr[__VM_FR_REG_SEED__] or
                   (--<<TARGET_PRIVATE_EXPRESSION>>
                    (((_zz or 0)~(_IT.seed or 0)~(proto.vm_id<<17)~#code~
                    ((_PY~=0 and _PN) or 0))|1)
                    --<<ENDTARGET_PRIVATE_EXPRESSION>>
                   )
    local _MG    = _fr and _fr[__VM_FR_MAP_STATE__] or
                   {(--<<TARGET_PRIVATE_LOW_EXPRESSION:1024>>
                     ((_IT.seed~proto.vm_id~#code~
                     ((_PY~=0 and _PN) or 0))&0x3FF)
                     --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                    ),0}
    local _RL    = _fr and _fr[__VM_FR_LOGICAL_SLOTS__] or {}
    local _PR    = _fr and _fr[__VM_FR_ROUTE_STATE__]
    local _SS    = _fr and _fr[__VM_FR_SEM_STATE__]
    local _seal_next
    local _pending_finish
    local _gsl, _gq
    local _XF    = _fr and _fr[__VM_FR_LEDGER__] or _xx or {[1]=_zz or 0}

    local function _rmix(x)
        return _pmix(x)
    end

    if not _PR then
        _PR={_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                   _PN~(_zz or 0)~(_IT.seed or 0)~(proto.vm_id<<19)~#code
                   --<<ENDTARGET_PRIVATE_EXPRESSION>>
                  )),0}
    end

    if not _SS then
        _SS={_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                   (_zz or 0)~(_IT.seed or 0)~(_IT.layout or 0)~
                   (_IT.script or 0)~(proto.vm_id<<23)~#code~_ksd~
                   ((_XF and _XF[2]) or 0)
                   --<<ENDTARGET_PRIVATE_EXPRESSION>>
                  )),0}
    end

    local function _ss_step(ip,op,a,b,c)
        if not _SY then return end
        local n=(--<<TARGET_USER_EXPRESSION>>
                 (_SS[2] or 0)+1
                 --<<ENDTARGET_USER_EXPRESSION>>
                )
        local x=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      (_SS[1] or 0)~(ip<<32)~(op<<24)~(a<<16)~
                      (b<<7)~c~n~(_S[611] or 0)~(_XF[1] or 0)~
                      ((_XF and _XF[2]) or 0)~(_PR[1] or 0)~
                      ((_MG[1] or 0)<<11)~_st~_ksd
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
        _SS[1],_SS[2]=x,n
        _XF[2]=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      (_XF[2] or 0)~x~op~ip
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
    end

    local function _ss_value(slot,encoded,epoch,kind)
        if not _SY then return end
        local x=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      (_SS[1] or 0)~slot~encoded~epoch~(kind or 0)~
                      ((_RX[1] or 0)<<1)~((_MG[1] or 0)<<17)~
                      (_XF[2] or 0)
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
        _SS[1]=x
        _XF[2]=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      (_XF[2] or 0)~x~slot~epoch
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
    end

    local function _route_step(ip,op,a,b,c)
        if (--<<TARGET_USER_EXPRESSION>>
            _PY==0
            --<<ENDTARGET_USER_EXPRESSION>>
           ) then return end
        local n=(--<<TARGET_USER_EXPRESSION>>
                 (_PR[2] or 0)+1
                 --<<ENDTARGET_USER_EXPRESSION>>
                )
        local x=(--<<TARGET_PRIVATE_EXPRESSION>>
                 ((_PR[1] or 0)~_PN~(ip<<32)~(op<<24)~
                 (a<<16)~(b<<7)~c~n~(_MG[1]<<3)~(_RX[1] or 0))&-1
                 --<<ENDTARGET_PRIVATE_EXPRESSION>>
                )
        x=(--<<TARGET_PRIVATE_EXPRESSION>>
           (x~(x<<13)~(x>>7)~(x<<17))&-1
           --<<ENDTARGET_PRIVATE_EXPRESSION>>
          )
        _PR[1],_PR[2]=x,n
        --<<RUNTIME_TRACE>>
        _PX=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                  _PX~x~ip~(op<<11)~n
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 ))
        --<<ENDRUNTIME_TRACE>>
    end

    local function _poly_gate(salt)
        return (--<<TARGET_PRIVATE_LOW_EXPRESSION:65536>>
                ((_PR[1] or 0)~salt~((_PR[2] or 0)<<7))&0xFFFF
                --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
               )
    end

    local function _poly_word(salt)
        return _rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      (_PR[1] or 0)~salt~((_PR[2] or 0)<<17)~_PN
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
    end

    local function _poly_pick(count,salt,baseline)
        if (--<<TARGET_USER_EXPRESSION>>
            _PY==0
            --<<ENDTARGET_USER_EXPRESSION>>
           ) then return baseline end
        if (--<<TARGET_USER_EXPRESSION>>
            _poly_gate(salt)>=_PY
            --<<ENDTARGET_USER_EXPRESSION>>
           ) then return baseline end
        local x=_poly_word(salt)
        local pick=(--<<TARGET_USER_EXPRESSION>>
                    (--<<TARGET_PRIVATE_MOD_EXPRESSION>>
                    (x>>16)%count
                    --<<ENDTARGET_PRIVATE_MOD_EXPRESSION>>
                    )+1
                    --<<ENDTARGET_USER_EXPRESSION>>
                   )
        --<<RUNTIME_TRACE>>
        _PX=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                  _PX~x~pick~salt
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 ))
        --<<ENDRUNTIME_TRACE>>
        return pick
    end

    local function _poly_lazy(salt)
        if (--<<TARGET_USER_EXPRESSION>>
            _PY==0
            --<<ENDTARGET_USER_EXPRESSION>>
           ) then return true end
        if (--<<TARGET_USER_EXPRESSION>>
            _poly_gate(salt)>=_PY
            --<<ENDTARGET_USER_EXPRESSION>>
           ) then return true end
        local x=_poly_word(salt)
        local lazy=(--<<TARGET_USER_EXPRESSION>>
                    (--<<TARGET_PRIVATE_LOW_EXPRESSION:2>>
                    ((x>>16)&1)
                    --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                    )==0
                    --<<ENDTARGET_USER_EXPRESSION>>
                   )
        --<<RUNTIME_TRACE>>
        _PX=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                  _PX~x~(lazy and 0x4C415A59 or 0x4E4F5721)
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 ))
        --<<ENDRUNTIME_TRACE>>
        return lazy
    end

    local function _poly_route(route,salt)
        local x=_poly_word((--<<TARGET_PRIVATE_EXPRESSION>>
                           salt~#route~0x424C4F43
                           --<<ENDTARGET_PRIVATE_EXPRESSION>>
                          ))
        local pick=(--<<TARGET_USER_EXPRESSION>>
                    (--<<TARGET_PRIVATE_MOD_EXPRESSION>>
                    (x>>16)%#route
                    --<<ENDTARGET_PRIVATE_MOD_EXPRESSION>>
                    )+1
                    --<<ENDTARGET_USER_EXPRESSION>>
                   )
        --<<RUNTIME_TRACE>>
        _PX=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                  _PX~x~pick~salt~0x524F5554
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 ))
        _PBC=_PBC+1
        _PBH=_pmix((--<<TARGET_PRIVATE_EXPRESSION>>
                   _PBH~x~pick~route[pick]~_PBC
                   --<<ENDTARGET_PRIVATE_EXPRESSION>>
                  ))
        --<<ENDRUNTIME_TRACE>>
        _PR[1]=(--<<TARGET_PRIVATE_EXPRESSION>>
                (_PR[1]~x~route[pick])&-1
                --<<ENDTARGET_PRIVATE_EXPRESSION>>
               )
        return route[pick]
    end

    local function _rparams(slot,epoch)
        local z=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                       _RZ~epoch~((slot+1)*-7046029254386353131)
                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                      ))
        local pair=_RP[(--<<TARGET_USER_EXPRESSION>>
                        (--<<TARGET_PRIVATE_LOW_EXPRESSION:16>>
                         z&15
                         --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                        )+1
                        --<<ENDTARGET_USER_EXPRESSION>>
                       )]
        return pair[1],_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                             z~-2960836687051489901
                             --<<ENDTARGET_PRIVATE_EXPRESSION>>
                            )),pair[2]
    end

    local function _rnext(slot,salt)
        _RX[1]=(--<<TARGET_PRIVATE_EXPRESSION>>
                ((_RX[1] or 0)-7046029254386353131+slot+(salt or 0))&-1
                --<<ENDTARGET_PRIVATE_EXPRESSION>>
               )
        return _rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                      _RX[1]~_RZ~(_SY and (_SS[1] or 0) or 0)
                      --<<ENDTARGET_PRIVATE_EXPRESSION>>
                     ))
    end

    --<<TARGET_REGISTER_MAP>>
    local function _rslot(slot)
        return (--<<TARGET_PRIVATE_LOW_EXPRESSION:1024>>
                (slot&0x3FF)
                --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
               )
    end

    local function _rpos_at(kind,slot,generation)
        local map=_MP[kind]
        return (_rslot(slot)*map[1]+map[2]+generation*map[3])%1024
    end

    local function _rpositions_at(slot,generation)
        return _rpos_at(1,slot,generation),_rpos_at(2,slot,generation),
               _rpos_at(3,slot,generation),_rpos_at(4,slot,generation)
    end

    local function _rmap_offsets()
        local generation=_MG[1]
        for kind=1,5 do
            local map=_MP[kind]
            _MG[kind+2]=(map[2]+generation*map[3])%1024
        end
    end

    local function _rpos(kind,slot)
        return (_rslot(slot)*_MP[kind][1]+_MG[kind+2])%1024
    end

    local function _rpositions(slot)
        slot=_rslot(slot)
        return (slot*_MP[1][1]+_MG[3])%1024,
               (slot*_MP[2][1]+_MG[4])%1024,
               (slot*_MP[3][1]+_MG[5])%1024,
               (slot*_MP[4][1]+_MG[6])%1024
    end

    _rmap_offsets()
    --<<ENDTARGET_REGISTER_MAP>>

    -- The register bank uses native, bounded positions and vault IDs.  Only
    -- its affine payloads and epochs are private words; those operations are
    -- lowered explicitly before this region is protected from Lua 5.1's
    -- general syntax translator.
    --<<TARGET_51_KARITY_REGISTER_BANK>>
    local function _rstore(slot,encoded,epoch,kind)
        _PD[_rpos(5,slot)]=nil
        local share=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                           epoch~_RZ~((slot+3)*-3372029247567499371)
                           --<<ENDTARGET_PRIVATE_EXPRESSION>>
                          ))
        local p1,p2,p3,p4=_rpositions(slot)
        regs[p1]=(--<<TARGET_PRIVATE_EXPRESSION>>
                  encoded-share
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 )
        _RS[p2]=share
        _RE[p3]=epoch
        if kind~=nil then _RT[p4]=kind end
        _RL[_rslot(slot)]=true
        _ss_value(slot,encoded,epoch,kind)
    end

    local function _rdecode(encoded,kind)
        if kind==1 then return encoded end
        if kind==2 then return not _peq(encoded,0) end
        if kind==3 then return nil end
        local index_hi,index_lo=_pword(encoded)
        if index_hi~=0 or index_lo==0 then error('register vault index mismatch') end
        return _RO[index_lo]
    end

    local function _rvalue(v,epoch)
        if math.type(v)=="integer" then return v,1 end
        if type(v)=="boolean" then return v and 1 or 0,2 end
        if v==nil then
            return _rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                          epoch~_RZ~0x4E494C
                          --<<ENDTARGET_PRIVATE_EXPRESSION>>
                         )),3
        end
        local id
        if not (type(v)=="number" and v~=v) then id=_RI[_value_key(v)] end
        if id==nil then
            _RX[2]=(_RX[2] or 0)+1; id=_RX[2]
            if id>4294967295 then error('register vault exhausted') end
            _RO[id]=v
            if not (type(v)=="number" and v~=v) then _RI[_value_key(v)]=id end
        end
        return id,4
    end
    --<<RGET>>
    local function rget(i)
        if _PD[_rpos(5,i)]~=nil then _pending_finish(i) end
        local p1,p2,p3,p4=_rpositions(i)
        local epoch=_RE[p3]
        if epoch==nil then return nil end
        local _,b,inv=_rparams(i,epoch)
        return _rdecode((--<<TARGET_PRIVATE_EXPRESSION>>
                         ((regs[p1]+_RS[p2])-b)*inv
                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                        ),_RT[p4])
    end
    --<<ENDRGET>>

    --<<RSET>>
    local function rset(i,v)
        local seal=_seal_next
        _seal_next=nil
        local salt=0
        if seal then
            local desc=seal[1]
            salt=(--<<TARGET_PRIVATE_EXPRESSION>>
                  desc[2]~desc[3]~(seal[2] or 0)~seal[3]
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 )
        end
        local epoch=_rnext(i,salt)
        local payload,kind=_rvalue(v,epoch)
        local a,b=_rparams(i,epoch)
        _rstore(i,(--<<TARGET_PRIVATE_EXPRESSION>>
                   a*payload+b
                   --<<ENDTARGET_PRIVATE_EXPRESSION>>
                  ),epoch,kind)
    end
    --<<ENDRSET>>

    local function _rrotate(slot,salt)
        local p1,p2,p3=_rpositions(slot)
        local old_epoch=_RE[p3]
        if old_epoch==nil then return end
        local _,old_b,old_inv=_rparams(slot,old_epoch)
        local new_epoch=_rnext(slot,salt)
        local new_a,new_b=_rparams(slot,new_epoch)
        local alpha=(--<<TARGET_PRIVATE_EXPRESSION>>
                     new_a*old_inv
                     --<<ENDTARGET_PRIVATE_EXPRESSION>>
                    )
        local beta=(--<<TARGET_PRIVATE_EXPRESSION>>
                    new_b-alpha*old_b
                    --<<ENDTARGET_PRIVATE_EXPRESSION>>
                   )
        local delta=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                           new_epoch~salt~_RZ
                           --<<ENDTARGET_PRIVATE_EXPRESSION>>
                          ))
        regs[p1]=(--<<TARGET_PRIVATE_EXPRESSION>>
                  alpha*regs[p1]+delta
                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                 )
        _RS[p2]=(--<<TARGET_PRIVATE_EXPRESSION>>
                 alpha*_RS[p2]+beta-delta
                 --<<ENDTARGET_PRIVATE_EXPRESSION>>
                )
        _RE[p3]=new_epoch
    end

    local function _rmap_rotate(salt)
        local old_generation=_MG[1]
        local step=(--<<TARGET_PRIVATE_LOW_EXPRESSION:1024>>
                    ((_rmix(_RZ~salt~old_generation)&0x3FF)|1)
                    --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                   )
        local new_generation=(--<<TARGET_USER_EXPRESSION>>
                              (old_generation+step)%1024
                              --<<ENDTARGET_USER_EXPRESSION>>
                             )
        local new_regs,new_shares,new_epochs,new_types,new_pending={},{},{},{},{}
        for slot in pairs(_RL) do
            local o1,o2,o3,o4=_rpositions_at(slot,old_generation)
            local n1,n2,n3,n4=_rpositions_at(slot,new_generation)
            new_regs[n1]=regs[o1]
            new_shares[n2]=_RS[o2]
            new_epochs[n3]=_RE[o3]
            new_types[n4]=_RT[o4]
            new_pending[_rpos_at(5,slot,new_generation)]=
                _PD[_rpos_at(5,slot,old_generation)]
        end
        for key in pairs(regs) do regs[key]=nil end
        for key in pairs(_RS) do _RS[key]=nil end
        for key in pairs(_RE) do _RE[key]=nil end
        for key in pairs(_RT) do _RT[key]=nil end
        for key in pairs(_PD) do _PD[key]=nil end
        for key,value in pairs(new_regs) do regs[key]=value end
        for key,value in pairs(new_shares) do _RS[key]=value end
        for key,value in pairs(new_epochs) do _RE[key]=value end
        for key,value in pairs(new_types) do _RT[key]=value end
        for key,value in pairs(new_pending) do _PD[key]=value end
        _MG[1]=new_generation
        _rmap_offsets()
    end

    local function _rmap_tick(salt)
        _MG[2]=(_MG[2] or 0)+1
        if _MG[2]<=2 or _MG[2]%1024==0 then
            _rmap_rotate((--<<TARGET_PRIVATE_EXPRESSION>>
                          salt~(_SY and (_SS[1] or 0) or 0)
                          --<<ENDTARGET_PRIVATE_EXPRESSION>>
                         ))
        end
    end
    --<<ENDTARGET_51_KARITY_REGISTER_BANK>>

    -- The split-temp cell uses the same register bank representation but is
    -- separated from the generic tick helper so its native boundary stays exact.
    --<<TARGET_51_KARITY_REGISTERS>>
    local function _split_set(v)
        local epoch=_rnext(-7,0x53504C49)
        local payload,kind=_rvalue(v,epoch)
        local a,b=_rparams(-7,epoch)
        local encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                       a*payload+b
                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                      )
        _split_share=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                            epoch~_RZ~0x544D5053
                            --<<ENDTARGET_PRIVATE_EXPRESSION>>
                           ))
        _split_tmp=(--<<TARGET_PRIVATE_EXPRESSION>>
                    encoded-_split_share
                    --<<ENDTARGET_PRIVATE_EXPRESSION>>
                   )
        _split_epoch=epoch
        _split_kind=kind
    end

    local function _split_get()
        if _split_epoch==nil then return _split_tmp end
        local _,b,inv=_rparams(-7,_split_epoch)
        return _rdecode((--<<TARGET_PRIVATE_EXPRESSION>>
                         ((_split_tmp+_split_share)-b)*inv
                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                        ),_split_kind)
    end
    --<<ENDTARGET_51_KARITY_REGISTERS>>

    if not _fr then
        args = args or {}
        local _argc=_acount(args)
        for i=1,proto.num_params do rset(i-1,_aget(args,i)) end
        if proto.is_vararg==1 then
            local _vv={}; local _vn=0
            for i=proto.num_params+1,_argc do
                _vn=_vn+1; _vv[_vn]=_aget(args,i)
            end
            _va=_apack(_vv,_vn,(_SS and _SS[1]) or (_XF[2] or 0))
        end
    end

    local function _av_read()
        for slot in pairs(_AA) do
            local v=rget(slot)
            _S[611]=_pxor(_pxor(_S[611] or 0,v),slot)
            _XF[1]=_pxor(_pxor(_XF[1] or 0,v),slot)
            _AA[slot]=nil
        end
    end

    -- 상수 풀을 register 파일 상위(256+)에 미리 풀어 넣는다.
    -- RK operand는 reg(0~255) / const(256~) 를 같은 인덱스 공간에서 가리키므로
    -- 이후 모든 rk 접근이 분기 없는 단일 테이블 인덱스(regs[x])로 처리된다.
    -- RK constants enter the same affine-share or vault-handle domain as stack slots.
    for _ci=1,256 do
        local _c=consts[_ci]
        if not _c then break end
        if _c[1]==CK_STR then
            if _c[2] then rset(255+_ci,_kss(_c[2])) end
        elseif _c[1]~=0 then
            rset(255+_ci,kval(_c,proto))
        end
    end

    -- Closed upvalues and virtual tables store native Lua 5.1 user keys.
    -- Private physical keys are retained as stable objects by the reverse map.
    --<<TARGET_51_NATIVE_51_KARITY_VALUE_STORAGE>>
    local function get_box(slot)
        if not boxes[slot] then
            boxes[slot]={
                get=function() return rget(slot) end,
                set=function(v) rset(slot,v) end
            }
        end
        return boxes[slot]
    end

    local function get_upvalue(box)
        if box.get then return box.get() end
        if not _UY then return box.v end
        local q=_UV[box]
        if not q then
            local v=box.v
            _UC=_UC+1
            local epoch=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                              _RZ~_UC~(_SS[1] or 0)~(_XF[2] or 0)~__VM_UV_SEED__
                              --<<ENDTARGET_PRIVATE_EXPRESSION>>
                             ))
            local payload,kind
            if math.type(v)=="integer" then payload,kind=v,1
            elseif type(v)=="boolean" then payload,kind=(v and 1 or 0),2
            elseif v==nil then payload,kind=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                                                  epoch~__VM_UV_NIL__
                                                  --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                                 )),3
            else
                if not (type(v)=="number" and v~=v) then payload=_UI[_value_key(v)] end
                if payload==nil then
                    payload=#_UO+1; _UO[payload]=v
                    if not (type(v)=="number" and v~=v) then _UI[_value_key(v)]=payload end
                end
                kind=4
            end
            local pair=_RP[(--<<TARGET_USER_EXPRESSION>>
                           (--<<TARGET_PRIVATE_LOW_EXPRESSION:16>>
                            epoch&15
                            --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                           )+1
                           --<<ENDTARGET_USER_EXPRESSION>>
                          )]
            -- Closed boxes cross VM frame boundaries.  Derive their representation
            -- from the box epoch rather than the current frame's register seed so
            -- every closure sharing the box can decode the same payload.
            local bias=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                             epoch~__VM_UV_BIAS__
                             --<<ENDTARGET_PRIVATE_EXPRESSION>>
                            ))
            local encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                           pair[1]*payload+bias
                           --<<ENDTARGET_PRIVATE_EXPRESSION>>
                          )
            local share=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                              epoch~__VM_UV_SHARE__
                              --<<ENDTARGET_PRIVATE_EXPRESSION>>
                             ))
            q={[__VM_UV_LEFT__]=(--<<TARGET_PRIVATE_EXPRESSION>>
                                encoded-share
                                --<<ENDTARGET_PRIVATE_EXPRESSION>>
                               ),[__VM_UV_RIGHT__]=share,
               [__VM_UV_EPOCH__]=epoch,[__VM_UV_KIND__]=kind}
            _UV[box]=q; box.v=nil
            _ss_value(-31,encoded,epoch,kind)
        end
        local epoch=q[__VM_UV_EPOCH__]
        local pair=_RP[(--<<TARGET_USER_EXPRESSION>>
                       (--<<TARGET_PRIVATE_LOW_EXPRESSION:16>>
                        epoch&15
                        --<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>
                       )+1
                       --<<ENDTARGET_USER_EXPRESSION>>
                      )]
        local bias=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                         epoch~__VM_UV_BIAS__
                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                        ))
        local payload=(--<<TARGET_PRIVATE_EXPRESSION>>
                       ((q[__VM_UV_LEFT__]+q[__VM_UV_RIGHT__])-bias)*pair[2]
                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                      )
        local kind=q[__VM_UV_KIND__]
        if kind==1 then return payload end
        if kind==2 then return not _peq(payload,0) end
        if kind==3 then return nil end
        -- The payload is an exact private word, while the vault is a dense
        -- native array. Check the whole word before crossing that boundary.
        local index_hi,index_lo=_pword(payload)
        if index_hi~=0 or index_lo<1 or index_lo>#_UO then
            error("invalid virtualized upvalue index")
        end
        return _UO[index_lo]
    end

    local function set_upvalue(box,v)
        if box.set then box.set(v)
        elseif not _UY then box.v=v
        else box.v=v; _UV[box]=nil; get_upvalue(box) end
    end

    local function _tnew()
        local t={}
        if not _TY then return t end
        _TC=_TC+1
        local salt=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                         _TC~(_SS[1] or 0)~(_XF[2] or 0)~_RZ~__VM_TABLE_SEED__
                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                        ))
        _TM[t]={[__VM_TB_LEFT__]={},[__VM_TB_RIGHT__]={},
                [__VM_TB_KEYS__]={},[__VM_TB_REVERSE__]={},
                [__VM_TB_SALT__]=salt,[__VM_TB_NEXT__]=0,
                [__VM_TB_EXPOSED__]=false}
        return t
    end

    local function _tkey(m,k,create)
        local id=m[__VM_TB_REVERSE__][k]
        if id~=nil or not create then return id end
        id=m[__VM_TB_NEXT__]+1; m[__VM_TB_NEXT__]=id
        local physical=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                             m[__VM_TB_SALT__]~id~__VM_TABLE_KEY__
                             --<<ENDTARGET_PRIVATE_EXPRESSION>>
                            ))
        m[__VM_TB_REVERSE__][k]=physical
        m[__VM_TB_KEYS__][physical]=k
        return physical
    end

    local function _tget(t,k)
        local m=_TM[t]
        if not m or m[__VM_TB_EXPOSED__] then return t[k] end
        local physical=_tkey(m,k,false)
        if physical==nil then return nil end
        local left=m[__VM_TB_LEFT__][physical]
        if left==nil then return nil end
        local right=m[__VM_TB_RIGHT__][physical]
        if type(left)=="number" and math.type(left)=="integer" and
           type(right)=="number" then return (--<<TARGET_PRIVATE_EXPRESSION>>
                                              left+right
                                              --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                             ) end
        return left
    end

    local function _tset(t,k,v)
        local m=_TM[t]
        if not m or m[__VM_TB_EXPOSED__] then t[k]=v; return end
        local physical=_tkey(m,k,v~=nil)
        if physical==nil then return end
        if v==nil then
            m[__VM_TB_LEFT__][physical]=nil
            m[__VM_TB_RIGHT__][physical]=nil
            return
        end
        if math.type(v)=="integer" then
            local share=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                              m[__VM_TB_SALT__]~physical~(_SS[1] or 0)~__VM_TABLE_SHARE__
                              --<<ENDTARGET_PRIVATE_EXPRESSION>>
                             ))
            m[__VM_TB_LEFT__][physical]=(--<<TARGET_PRIVATE_EXPRESSION>>
                                       v-share
                                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                      )
            m[__VM_TB_RIGHT__][physical]=share
        else
            m[__VM_TB_LEFT__][physical]=v
            m[__VM_TB_RIGHT__][physical]=false
        end
        _ss_value(-47,physical,m[__VM_TB_SALT__],math.type(v)=="integer" and 1 or 4)
    end

    local function _tlen(t)
        local m=_TM[t]
        if not m or m[__VM_TB_EXPOSED__] then return #t end
        local n=0
        while _tget(t,n+1)~=nil do n=n+1 end
        return n
    end

    local function _texpose(v,seen)
        local m=type(v)=="table" and _TM[v] or nil
        if not m or m[__VM_TB_EXPOSED__] then return v end
        seen=seen or {}
        if seen[v] then return v end
        seen[v]=true
        m[__VM_TB_EXPOSED__]=true
        for physical,k in pairs(m[__VM_TB_KEYS__]) do
            local x=m[__VM_TB_LEFT__][physical]
            if x~=nil then
                local right=m[__VM_TB_RIGHT__][physical]
                if type(x)=="number" and math.type(x)=="integer" and
                   type(right)=="number" then x=(--<<TARGET_PRIVATE_EXPRESSION>>
                                                x+right
                                                --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                               ) end
                v[_texpose(k,seen)]=_texpose(x,seen)
            end
        end
        return v
    end

    local function close_upvalues(first)
        for slot,box in pairs(boxes) do
            if slot>=first then
                local value=get_upvalue(box)
                box.get=nil; box.set=nil
                set_upvalue(box,value)
                boxes[slot]=nil
            end
        end
    end
    --<<ENDTARGET_51_NATIVE_51_KARITY_VALUE_STORAGE>>

    local function make_closure(sub)
        local new_uv={}
        for i,uv in ipairs(sub.upvalues) do
            if uv.instack==1 then
                new_uv[i]=get_box(uv.idx)
            else
                new_uv[i]=upvals[uv.idx+1]
            end
        end
        -- exec는 {r=테이블, n=개수} wrapper를 단일값으로 반환.
        -- 래퍼는 이를 받아 native처럼 다중반환으로 변환.
        local metadata={[__VM_META_PROTO__]=sub,[__VM_META_UPVALS__]=new_uv}
        local fn=function(...)
            local sub,new_uv=metadata[__VM_META_PROTO__],metadata[__VM_META_UPVALS__]
            local _av=table.pack(...)
            local w=_CG[__VM_ROUTE_ENTER__](_NX,{
                [__VM_Q_KIND__]=__VM_CALL_ENTER__,[__VM_Q_PROTO__]=sub,
                [__VM_Q_UPVALS__]=new_uv,
                [__VM_Q_ARGS__]=_apack(_av,_av.n,(_SS and _SS[1]) or 0)})
            for i=1,w[__VM_RES_COUNT__] do
                w[__VM_RES_VALUES__][i]=_texpose(w[__VM_RES_VALUES__][i])
            end
            return table.unpack(w[__VM_RES_VALUES__],1,w[__VM_RES_COUNT__])
        end
        _VF[fn]=metadata
        return bind_environment(fn,new_uv,upvals)
    end

    local _carry

    local function _frame(a,c,parent)
        if proto.max_stack_size>0 then
            local slot=_pmod(_pband(
                _pxor(_pxor(_pxor(pc,a),c),_S[611] or 0),2147483647),
                proto.max_stack_size)
            _rrotate(slot,_pxor(_pxor(pc,a),c))
        end
        _rmap_tick(_pxor(_pxor(_pxor(pc,a),c),_S[611] or 0))
        local m=_pxor(_S[611] or 0,_XF[1] or 0)
        m=_pxor(m,_pbor(_pshl(_st,8),_pband(_st,255)))
        for slot in pairs(_AA) do
            local p1=_rpos(1,slot);m=_pxor(_pxor(m,regs[p1]),slot)
        end
        return {[__VM_FR_REGS__]=regs,[__VM_FR_BOXES__]=boxes,
                [__VM_FR_MASK__]=m,[__VM_FR_PC__]=_frame_encode(pc,m),
                [__VM_FR_TOP__]=_frame_encode(top,m),
                [__VM_FR_STATE__]=_frame_state(_st,m),[__VM_FR_VARARG__]=_va,
                [__VM_FR_SPLIT__]=_split_tmp,
                [__VM_FR_SPLIT_SHARE__]=_split_share,
                [__VM_FR_SPLIT_EPOCH__]=_split_epoch,
                [__VM_FR_SPLIT_TYPE__]=_split_kind,
                [__VM_FR_SCRATCH__]=_S,
                [__VM_FR_ACTIVE__]=_AA,[__VM_FR_FLOW_CACHE__]=_FC,
                [__VM_FR_SEM_CACHE__]=_SC,
                [__VM_FR_LOOP_CACHE__]=_LC,
                [__VM_FR_GRAPH_CACHE__]=_GC,
                [__VM_FR_REG_SHARES__]=_RS,
                [__VM_FR_REG_EPOCHS__]=_RE,
                [__VM_FR_REG_TYPES__]=_RT,
                [__VM_FR_VALUE_VAULT__]=_RO,
                [__VM_FR_VALUE_INDEX__]=_RI,
                [__VM_FR_REPR_COUNTERS__]=_RX,
                [__VM_FR_PENDING__]=_PD,
                [__VM_FR_REG_SEED__]=_RZ,
                [__VM_FR_MAP_STATE__]=_MG,
                [__VM_FR_LOGICAL_SLOTS__]=_RL,
                [__VM_FR_ROUTE_STATE__]=_PR,
                [__VM_FR_SEM_STATE__]=_SS,
                [__VM_FR_LEDGER__]=_XF,
                [__VM_FR_PROTO__]=proto,
                [__VM_FR_UPVALS__]=upvals,[__VM_FR_A__]=_frame_encode(a,m),
                [__VM_FR_C__]=_frame_encode(c,m),[__VM_FR_PARENT__]=parent}
    end

    local function _leave(r,n,av,tag)
        local q={
            [__VM_Q_KIND__]=__VM_CALL_LEAVE__,[__VM_Q_CONT__]=_kk,
            [__VM_Q_RESULT__]={[__VM_RES_VALUES__]=r,[__VM_RES_COUNT__]=n},
            [__VM_Q_FLOW__]=_S[611] or 0,[__VM_Q_LEDGER__]=_XF}
        return _CG[__VM_ROUTE_LEAVE__](_NX,_carry(q,av,tag))
    end

    -- Graph sites may contain a full-width PC/tag word. Cache keys use the
    -- exact hi:lo packet key; operation-bank indices remain native and small.
    --<<TARGET_51_KARITY_GRAPH_STATE>>
    local function _int2(a, b)
        return math.type(a)=="integer" and math.type(b)=="integer" and 2 or 1
    end

    local function _int1(a)
        return math.type(a)=="integer" and 2 or 1
    end

    local function _cross(delta)
        _XF[1]=_pxor(_XF[1] or 0,delta)
        local k=_kk
        if not k then return end
        local old=k[__VM_FR_MASK__]
        local new=_pxor(old,delta)
        k[__VM_FR_PC__]=_pxor(_pxor(k[__VM_FR_PC__],old),new)
        k[__VM_FR_TOP__]=_pxor(_pxor(k[__VM_FR_TOP__],old),new)
        k[__VM_FR_STATE__]=_ixor(
            _ixor(k[__VM_FR_STATE__],_plow(old,256)),_plow(new,256))
        k[__VM_FR_A__]=_pxor(_pxor(k[__VM_FR_A__],old),new)
        k[__VM_FR_C__]=_pxor(_pxor(k[__VM_FR_C__],old),new)
        k[__VM_FR_MASK__]=new
    end

    _carry=function(v,av,tag)
        if not av then
            _S[1731]=_pxor(_pxor(_S[1731] or 0,tag),pc%256)
            return v
        end
        _cross(_pxor(_pxor(tag,pc),_S[611] or 0))
        local pick=_poly_pick(2,_pxor(_pxor(tag,pc),0x56414C55),
                              _plow(tag*5+3,2)+1)
        return _GV[pick](v,_S,av,rset,_AA,boxes,tag)
    end

    --<<FLOW>>
    local function _flow(q,av,tag)
        q=_carry(q,av,tag)
        if av then
            local site=_pxor(_pshl(pc-1,8),tag)
            local site_key=_aword_key(site)
            if not _FC[site_key] then
                _FC[site_key]=true
                local base=_plow(_pxor(_pxor(_pxor(tag,pc),proto.vm_id),
                                        _S[611] or 0),2)+1
                local pick=_poly_pick(2,_pxor(_pxor(site,tag),0x464C4F57),base)
                q=_FG[pick](q,_S)
            end
        end
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then return q end
        local site=desc[2]
        local site_key=_aword_key(site)
        local hit=_GC[site_key] or 0
        _GC[site_key]=hit+1
        local live=_pxor(_pxor(_pxor(_pxor(_pxor(_pxor(_pxor(
                   _S[desc[4]] or 0,_S[611] or 0),_XF[1] or 0),
                   desc[2]),desc[3]),_st),hit),tag)
        _S[desc[4]]=live
        local old=q[__VM_CF_KEY__]
        local key=_pxor(_pxor(_pxor(live,desc[2]),desc[3]),tag)
        for _,f in ipairs(q[__VM_CF_FIELDS__]) do
            q[f]=_pxor(_pxor(q[f],old),key)
        end
        q[__VM_CF_KEY__]=nil
        q[__VM_CF_SEAL__]=desc
        local mixed=_pxor(_pxor(live,hit),tag)
        if desc[5]%2~=0 then _S[611]=_pxor(_S[611] or 0,mixed) end
        if math.floor(desc[5]/2)%2~=0 then
            _XF[1]=_pxor(_XF[1] or 0,mixed)
        end
        if proto.max_stack_size>0 then
            _rrotate(_pmod(_pxor(_pxor(site,tag),hit),proto.max_stack_size),mixed)
        end
        _rmap_tick(_pxor(_pxor(mixed,site),tag))
        return q
    end
    --<<ENDFLOW>>

    local function _cf(q,field,tag)
        local desc=q[__VM_CF_SEAL__]
        if not desc then return _source_value(_pxor(q[field],q[__VM_CF_KEY__])) end
        local key=_pxor(_pxor(_pxor(_S[desc[4]] or 0,desc[2]),desc[3]),tag)
        return _source_value(_pxor(q[field],key))
    end

    local function _branch(v,expected,av,tag)
        if not _BY then return v==expected end
        local k=_pxor(_pxor(_pxor(_pxor(_pxor(
                _S[611] or 0,_SS[1] or 0),_XF[2] or 0),
                _pshl(pc,17)),tag),__VM_BRANCH_SEED__)
        local bit=(v==expected) and 1 or 0
        local q={[__VM_CF_KEY__]=k,[__VM_CF_TAKE__]=_pxor(bit,k),
                 [__VM_CF_FIELDS__]={__VM_CF_TAKE__}}
        q=_flow(q,av,tag)
        return _cf(q,__VM_CF_TAKE__,tag)~=0
    end

    --<<SEM>>
    local function _sem(tag,x,y,z)
        if _TY then
            if tag==__VM_OP_NEWTABLE__ then return _tnew() end
            if tag==__VM_DATA_GET__ then return _tget(x,y) end
            if tag==__VM_DATA_SET__ then _tset(x,y,z); return nil end
            if tag==__VM_OP_LEN__ and type(x)=="table" and _TM[x] then
                return _tlen(x)
            end
            if tag==__VM_OP_SETLIST__ and _TM[x] then
                for i=1,z[2] do _tset(x,z[1]+i,y[i]) end
                return nil
            end
        end
        local site=_pxor(_pshl(pc-1,32),tag)
        local route=_plow(_pxor(_pxor(_pxor(_DG[2][tag],_DG[3][tag]),pc),
                                 _S[611] or 0),2)+1
        local semantic=_DG[1][route]
        local bank=semantic[1][_ixor(semantic[2][tag],semantic[3][tag])]
        local site_key=_aword_key(site)
        local hit=_SC[site_key] or 0
        _SC[site_key]=hit+1
        local base=hit==0 and 1 or 2
        local pick=_poly_pick(2,_pxor(_pxor(_pxor(site,tag),hit),0x53454D41),base)
        return bank[pick](x,y,z,_S)
    end
    --<<ENDSEM>>

    local function _touch(av,tag)
        _carry(nil,av,tag)
    end

    local function _graph_for(desc)
        if not desc or desc[1]==0 then return nil,nil end
        local site=desc[2]
        local site_key=_aword_key(site)
        local hit=_GC[site_key] or 0
        _GC[site_key]=hit+1
        if hit==0 or _plow(_pxor(_pxor(_pxor(hit,desc[3]),
                                _S[611] or 0),_st),16)==0 then
            return _OG[desc[1]],hit
        end
        return false,hit
    end

    local function _couple_direct(v,desc,hit)
        local rv=0
        if math.type(v)=="integer" then rv=v end
        local mixed=_pxor(_pxor(_pxor(_pxor(desc[2],desc[3]),rv),_st),hit or 0)
        local key=desc[4]
        _S[key]=_pxor(_S[key] or 0,mixed)
        local policy=desc[5]
        if policy%2~=0 then
            _S[611]=_pxor(_pxor(_S[611] or 0,mixed),desc[2])
        end
        if math.floor(policy/2)%2~=0 then
            _XF[1]=_pxor(_pxor(_XF[1] or 0,mixed),desc[3])
        end
        return v
    end

    local function _seal_result(v,desc,hit)
        if math.type(v)=="integer" then
            _seal_next={desc,hit,_st}
        end
        return v
    end

    local function _arith2(a,b,av,slot,desc)
        local base=_plow(_pxor(_pxor(_pxor(pc,slot),proto.vm_id),
                                _S[611] or 0),2)+1
        local route=_plow(_pxor(_pxor(_pxor(_AR[2][slot],_AR[3][slot]),pc),
                                 _S[611] or 0),2)+1
        local arithmetic=_AR[1][route]
        local semantic_index=_ixor(arithmetic[3][slot],arithmetic[4][slot])
        local graph,hit=_graph_for(desc)
        if graph then
            local pick=_poly_pick(4,_pxor(_pxor(slot,pc),0x41524932),base)
            local bank=arithmetic[_int2(a,b)][semantic_index]
            local out=graph(bank,pick,a,b,_S,av,rset,_AA,boxes,_XF,_st,
                            desc[2],desc[3],desc[4],desc[5])
            return _seal_result(out,desc,hit)
        end
        local pick=_poly_pick(2,_pxor(_pxor(slot,pc),0x41524932),base)
        local out=arithmetic[1][semantic_index][pick](a,b)
        if graph==false then
            out=_couple_direct(out,desc,hit)
            return out
        end
        return out
    end

    local function _arith1(a,av,slot,desc)
        local base=_plow(_pxor(_pxor(_pxor(pc,slot),proto.vm_id),
                                _S[611] or 0),2)+1
        local route=_plow(_pxor(_pxor(_pxor(_AR[2][slot],_AR[3][slot]),pc),
                                 _S[611] or 0),2)+1
        local arithmetic=_AR[1][route]
        local semantic_index=_ixor(arithmetic[3][slot],arithmetic[4][slot])
        local graph,hit=_graph_for(desc)
        if graph then
            local pick=_poly_pick(4,_pxor(_pxor(slot,pc),0x41524931),base)
            local bank=arithmetic[_int1(a)][semantic_index]
            local out=graph(bank,pick,a,a,_S,av,rset,_AA,boxes,_XF,_st,
                            desc[2],desc[3],desc[4],desc[5])
            return _seal_result(out,desc,hit)
        end
        local pick=_poly_pick(2,_pxor(_pxor(slot,pc),0x41524931),base)
        local out=arithmetic[1][semantic_index][pick](a)
        if graph==false then
            out=_couple_direct(out,desc,hit)
            return out
        end
        return out
    end
    --<<ENDTARGET_51_KARITY_GRAPH_STATE>>

    -- Pending arithmetic keeps its fragments as exact private words while
    -- snapshots and register positions remain native Lua 5.1 table entries.
    --<<TARGET_51_KARITY_PENDING>>
    local function _elinear2(dst,lhs,rhs,sign)
        if _PD[_rpos(5,lhs)]~=nil then _pending_finish(lhs) end
        if _PD[_rpos(5,rhs)]~=nil then _pending_finish(rhs) end
        local l1,l2,l3,l4=_rpositions(lhs)
        local r1,r2,r3,r4=_rpositions(rhs)
        local le,re=_RE[l3],_RE[r3]
        if le==nil or re==nil or _RT[l4]~=1 or _RT[r4]~=1 then return false end
        local _,lb,li=_rparams(lhs,le)
        local _,rb,ri=_rparams(rhs,re)
        local epoch=_rnext(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                                sign~lhs~(rhs<<8)
                                --<<ENDTARGET_PRIVATE_EXPRESSION>>
                               ))
        local oa,ob=_rparams(dst,epoch)
        local encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                       oa*li*(regs[l1]+_RS[l2]-lb)+
                       sign*oa*ri*(regs[r1]+_RS[r2]-rb)+ob
                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                      )
        _rstore(dst,encoded,epoch,1)
        return true
    end

    local function _elinear1(dst,src,sign)
        if _PD[_rpos(5,src)]~=nil then _pending_finish(src) end
        local p1,p2,p3,p4=_rpositions(src)
        local se=_RE[p3]
        if se==nil or _RT[p4]~=1 then return false end
        local _,sb,si=_rparams(src,se)
        local epoch=_rnext(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                                sign~src
                                --<<ENDTARGET_PRIVATE_EXPRESSION>>
                               ))
        local oa,ob=_rparams(dst,epoch)
        _rstore(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                     sign*oa*si*(regs[p1]+_RS[p2]-sb)+ob
                     --<<ENDTARGET_PRIVATE_EXPRESSION>>
                    ),epoch,1)
        return true
    end

    local function _pending_snapshot(slot)
        if _PD[_rpos(5,slot)]~=nil then _pending_finish(slot) end
        local p1,p2,p3,p4=_rpositions(slot)
        local epoch=_RE[p3]
        if epoch==nil or _RT[p4]~=1 then return nil end
        return {regs[p1],_RS[p2],epoch,slot}
    end

    local function _pending_fragment(snapshot,scale,salt)
        local _,bias,inverse=_rparams(snapshot[4],snapshot[3])
        local share=_rmix((--<<TARGET_PRIVATE_EXPRESSION>>
                          snapshot[3]~salt~_RZ
                          --<<ENDTARGET_PRIVATE_EXPRESSION>>
                         ))
        return (--<<TARGET_PRIVATE_EXPRESSION>>
                scale*inverse*(snapshot[1]+snapshot[2]-bias)-share
                --<<ENDTARGET_PRIVATE_EXPRESSION>>
               ),share
    end

    _pending_finish=function(dst)
        local physical=_rpos(5,dst)
        local q=_PD[physical]
        if q==nil then return end
        _PD[physical]=nil
        local encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                       q[2]+q[3]
                       --<<ENDTARGET_PRIVATE_EXPRESSION>>
                      )
        if q[1]==__VM_PENDING_UNM__ then
            encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                     -encoded
                     --<<ENDTARGET_PRIVATE_EXPRESSION>>
                    )
        else
            local right=(--<<TARGET_PRIVATE_EXPRESSION>>
                         q[4]+q[5]
                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                        )
            encoded=(--<<TARGET_PRIVATE_EXPRESSION>>
                     encoded+(q[1]==__VM_PENDING_ADD__ and right or -right)
                     --<<ENDTARGET_PRIVATE_EXPRESSION>>
                    )
        end
        _rstore(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                    encoded+q[7]
                    --<<ENDTARGET_PRIVATE_EXPRESSION>>
                   ),q[6],1)
    end

    local function _defer2r(dst,lhs,rhs,av,slot,token)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then
            local left=_pending_snapshot(lhs)
            local right
            if lhs==rhs then right=left else right=_pending_snapshot(rhs) end
            if left and right and _poly_lazy((--<<TARGET_PRIVATE_EXPRESSION>>
                                              token~dst~lhs~(rhs<<8)
                                              --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                             )) then
                local epoch=_rnext(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                                        token~lhs~(rhs<<8)
                                        --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                       ))
                local scale,bias=_rparams(dst,epoch)
                local l1,l2=_pending_fragment(left,scale,(--<<TARGET_PRIVATE_EXPRESSION>>
                                                         epoch~token
                                                         --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                                        ))
                local r1,r2=_pending_fragment(right,scale,(--<<TARGET_PRIVATE_EXPRESSION>>
                                                          epoch~token~1
                                                          --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                                         ))
                _PD[_rpos(5,dst)]={token,l1,l2,r1,r2,epoch,bias}
                _RL[_rslot(dst)]=true
                return
            end
        end
        local left=rget(lhs)
        local right
        if lhs==rhs then right=left else right=rget(rhs) end
        rset(dst,_arith2(left,right,av,slot,desc))
    end

    local function _defer1r(dst,src,av,slot,token)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then
            local value=_pending_snapshot(src)
            if value and _poly_lazy((--<<TARGET_PRIVATE_EXPRESSION>>
                                     token~dst~src
                                     --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                    )) then
                local epoch=_rnext(dst,(--<<TARGET_PRIVATE_EXPRESSION>>
                                        token~src
                                        --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                       ))
                local scale,bias=_rparams(dst,epoch)
                local p1,p2=_pending_fragment(value,scale,(--<<TARGET_PRIVATE_EXPRESSION>>
                                                          epoch~token
                                                          --<<ENDTARGET_PRIVATE_EXPRESSION>>
                                                         ))
                _PD[_rpos(5,dst)]={token,p1,p2,nil,nil,epoch,bias}
                _RL[_rslot(dst)]=true
                return
            end
        end
        rset(dst,_arith1(rget(src),av,slot,desc))
    end
    --<<ENDTARGET_51_KARITY_PENDING>>

    -- Call/return vectors and decoded PC/slot fields are native values.  A
    -- control packet's seal and loop site are exact private words instead.
    --<<TARGET_51_KARITY_CONTROL_HELPERS>>
    local function _arith2r(dst,lhs,rhs,av,slot,linear)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if linear and (not desc or desc[1]==0) and
           _elinear2(dst,lhs,rhs,linear) then return end
        local left=rget(lhs)
        local right
        if lhs==rhs then right=left else right=rget(rhs) end
        rset(dst,_arith2(left,right,av,slot,desc))
    end

    local function _arith1r(dst,src,av,slot,linear)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if linear and (not desc or desc[1]==0) and
           _elinear1(dst,src,linear) then return end
        rset(dst,_arith1(rget(src),av,slot,desc))
    end

    local function _arith2s(a,b,av,slot)
        _gq=(_gq or 0)+1
        return _arith2(a,b,av,slot,_gsl and _gsl[_gq])
    end

    local function _arith1s(a,av,slot)
        _gq=(_gq or 0)+1
        return _arith1(a,av,slot,_gsl and _gsl[_gq])
    end

    if _rr then
        local _ra=_frame_decode(_fr[__VM_FR_A__],_fm)
        local _rc=_frame_decode(_fr[__VM_FR_C__],_fm)
        if _rc==0 then
            for i=1,_rr[__VM_RES_COUNT__] do
                rset(_ra+i-1,_rr[__VM_RES_VALUES__][i])
            end
            top=_ra+_rr[__VM_RES_COUNT__]-1
        elseif _rc>1 then
            for i=1,_rc-1 do rset(_ra+i-1,_rr[__VM_RES_VALUES__][i]) end
        end
    end

    local function _call_args(a,b,...)
        local values={};local count=0
        local last=(b==0 and top) or (b>1 and (a+b-1)) or a
        for i=a+1,last do count=count+1;values[count]=rget(i) end
        values.n=count
        return values
    end

    local function _return_values(a,b,...)
        if b==1 then return {},0 end
        local result={};local count=(b==0 and (top-a+1)) or (b-1)
        for i=1,count do result[i]=rget(a+i-1) end
        return result,count
    end

    local function _native_call(fn,args,a,c,av,tail,tag,...)
        local count=args.n
        if not tail then _touch(av,tag) end
        for i=1,count do args[i]=_texpose(args[i]) end
        local result=table.pack(fn(table.unpack(args,1,count)))
        if tail then return _leave(result,result.n,av,tag) end
        if c==0 then
            for i=1,result.n do rset(a+i-1,result[i]) end
            top=a+result.n-1
        elseif c>1 then
            for i=1,c-1 do rset(a+i-1,result[i]) end
        end
    end

    local function _jump(sbx,av,tag,...)
        local key=_pxor(_pxor(_S[611] or 0,pc),sbx)
        local packet={[__VM_CF_KEY__]=key,
                      [__VM_CF_TARGET__]=_pxor(pc+sbx,key),
                      [__VM_CF_FIELDS__]={__VM_CF_TARGET__}}
        packet=_flow(packet,av,tag)
        return _cf(packet,__VM_CF_TARGET__,tag)
    end

    local function _loop_commit(q,a,tag,...)
        local idx=q[__VM_CF_VALUE__]
        rset(a,idx)
        if q[__VM_CF_TAKE__] then
            pc=_cf(q,__VM_CF_TARGET__,tag);rset(a+3,idx)
        end
    end

    local function _forloop(a,sbx,av,tag,...)
        local step=rget(a+2)
        local limit=rget(a+1)
        local key=_pxor(_pxor(_S[611] or 0,pc),a)
        local packet={[__VM_CF_KEY__]=key,
                      [__VM_CF_TARGET__]=_pxor(pc+sbx,key),
                      [__VM_CF_FIELDS__]={__VM_CF_TARGET__}}
        packet[__VM_CF_VALUE__]=rget(a)
        packet[__VM_CF_STEP__]=step
        packet[__VM_CF_LIMIT__]=limit
        packet=_flow(packet,av,tag)
        local site_key=_aword_key(_pxor(_pshl(pc-1,8),__VM_LOOP_FORLOOP__))
        if not _LC[site_key] then
            _LC[site_key]=true
            packet=_LG[__VM_LOOP_FORLOOP__](packet,_S)
        else
            packet[__VM_CF_VALUE__]=packet[__VM_CF_VALUE__]+packet[__VM_CF_STEP__]
            local value=packet[__VM_CF_VALUE__]
            local delta=packet[__VM_CF_STEP__]
            local bound=packet[__VM_CF_LIMIT__]
            packet[__VM_CF_TAKE__]=
                (delta>0 and value<=bound) or (delta<=0 and value>=bound)
        end
        _loop_commit(packet,a,tag)
    end
    --<<ENDTARGET_51_KARITY_CONTROL_HELPERS>>

    --<<TARGET_51_KARITY_HANDLER_CHAIN>>
    --[[VM_DISPATCH_ENTRY]] while true do
        --<<FETCH>>
        _av_read(); local _ip=pc; _gsl=_gsd[_ip]; _gq=0; local _dk=_ikey48((_S[611] or 0)~(_XF[1] or 0)); local ins=_ixor(_ixor(code[pc],_ksm(pc)),_dk); local _av=_avd[_ip]; local op,A,B,C,Bx,sBx=decode(ins,_dk); pc=pc+1; _route_step(_ip,op,A,B,C); _ss_step(_ip,op,A,B,C)
        --<<ENDFETCH>>

        if     op==0  then rset(A,_carry(_sem(__VM_DATA_VALUE__,rget(B),nil,nil),_av,0))
        elseif op==1  then rset(A,_carry(_sem(__VM_DATA_VALUE__,kval(consts[Bx+1],proto),nil,nil),_av,1))
        elseif op==2  then
            local ei=_ixor(_ixor(_ixor(code[pc],_ksm(pc)),_dk),_dk); pc=pc+1
            local ax=_ifield48(ei,_SH_A,256)*262144+_ifield48(ei,_SH_B,512)*512+_ifield48(ei,_SH_C,512)
            rset(A,_carry(_sem(__VM_DATA_VALUE__,kval(consts[ax+1],proto),nil,nil),_av,2))
        elseif op==3  then rset(A,_carry(_sem(__VM_DATA_VALUE__,(B~=0),nil,nil),_av,3)); if C~=0 then pc=pc+1 end
        elseif op==4  then for i=A,A+B do rset(i,nil) end; _touch(_av,4)
        elseif op==5  then rset(A,_carry(_sem(__VM_DATA_VALUE__,get_upvalue(upvals[B+1]),nil,nil),_av,5))
        elseif op==6  then rset(A,_carry(_sem(__VM_DATA_GET__,get_upvalue(upvals[B+1]),rget(C),nil),_av,6))
        elseif op==7  then rset(A,_carry(_sem(__VM_DATA_GET__,rget(B),rget(C),nil),_av,7))
        elseif op==8  then _sem(__VM_DATA_SET__,get_upvalue(upvals[A+1]),rget(B),rget(C)); _touch(_av,8)
        elseif op==9 then set_upvalue(upvals[B+1],rget(A)); _touch(_av,9)
        elseif op==10 then _sem(__VM_DATA_SET__,rget(A),rget(B),rget(C)); _touch(_av,10)
        elseif op==11 then rset(A,_carry(_sem(__VM_OP_NEWTABLE__,nil,nil,nil),_av,11))
        elseif op==12 then local t=rget(B); rset(A+1,_carry(_sem(__VM_DATA_VALUE__,t,nil,nil),_av,112)); rset(A,_carry(_sem(__VM_DATA_GET__,t,rget(C),nil),_av,12))
        elseif op==13 then _arith2r(A,B,C,_av,__VM_SLOT_ADD__,1)
        elseif op==14 then _arith2r(A,B,C,_av,__VM_SLOT_SUB__,-1)
        elseif op==15 then _arith2r(A,B,C,_av,__VM_SLOT_MUL__,nil)
        elseif op==16 then rset(A,_carry(_sem(__VM_OP_MOD__,rget(B),rget(C),nil),_av,16))
        elseif op==17 then rset(A,_carry(_sem(__VM_OP_POW__,rget(B),rget(C),nil),_av,17))
        elseif op==18 then rset(A,_carry(_sem(__VM_OP_DIV__,rget(B),rget(C),nil),_av,18))
        elseif op==19 then rset(A,_carry(_sem(__VM_OP_IDIV__,rget(B),rget(C),nil),_av,19))
        elseif op==20 then _arith2r(A,B,C,_av,__VM_SLOT_BAND__,nil)
        elseif op==21 then _arith2r(A,B,C,_av,__VM_SLOT_BOR__,nil)
        elseif op==22 then _arith2r(A,B,C,_av,__VM_SLOT_BXOR__,nil)
        elseif op==23 then _arith2r(A,B,C,_av,__VM_SLOT_SHL__,nil)
        elseif op==24 then _arith2r(A,B,C,_av,__VM_SLOT_SHR__,nil)
        elseif op==25 then _arith1r(A,B,_av,__VM_SLOT_UNM__,-1)
        elseif op==26 then _arith1r(A,B,_av,__VM_SLOT_BNOT__,nil)
        elseif op==27 then rset(A,_carry(_sem(__VM_OP_NOT__,rget(B),nil,nil),_av,27))
        elseif op==28 then rset(A,_carry(_sem(__VM_OP_LEN__,rget(B),nil,nil),_av,28))
        elseif op==29 then
            local t={}; for i=B,C do t[#t+1]=rget(i) end
            rset(A,_carry(_sem(__VM_OP_CONCAT__,t,nil,#t),_av,29))
        elseif op==30 then if A>0 then close_upvalues(A-1) end; pc=_jump(sBx,_av,30)
        elseif op==31 then if not _branch(_carry(_sem(__VM_CMP_EQ__,rget(B),rget(C),nil),_av,31),A~=0,_av,31) then pc=pc+1 end
        elseif op==32 then if not _branch(_carry(_sem(__VM_CMP_LT__,rget(B),rget(C),nil),_av,32),A~=0,_av,32) then pc=pc+1 end
        elseif op==33 then if not _branch(_carry(_sem(__VM_CMP_LE__,rget(B),rget(C),nil),_av,33),A~=0,_av,33) then pc=pc+1 end
        elseif op==34 then if not _branch(_carry(_sem(__VM_CMP_TRUTH__,rget(A),nil,nil),_av,34),C~=0,_av,34) then pc=pc+1 end
        elseif op==35 then
            if _branch(_carry(_sem(__VM_CMP_TRUTH__,rget(B),nil,nil),_av,35),C~=0,_av,35) then rset(A,rget(B)) else pc=pc+1 end

        elseif op==36 then
            local fn=rget(A)
            local ca=_call_args(A,B)
            local ca_n=ca.n
            local _vm=_VF[fn]
            if _vm then
                ca.n=ca_n
                local q={[__VM_Q_KIND__]=__VM_CALL_ENTER__,
                         [__VM_Q_PROTO__]=_vm[__VM_META_PROTO__],
                         [__VM_Q_UPVALS__]=_vm[__VM_META_UPVALS__],
                         [__VM_Q_ARGS__]=_apack(ca,ca_n,(_SS and _SS[1]) or 0),
                         [__VM_Q_FLOW__]=_S[611] or 0,[__VM_Q_LEDGER__]=_XF}
                q=_carry(q,_av,136)
                q[__VM_Q_CONT__]=_frame(A,C,_kk)
                return _CG[__VM_ROUTE_ENTER__](_NX,q)
            else
                _native_call(fn,ca,A,C,_av,false,36)
            end

        elseif op==37 then
            close_upvalues(0)
            local fn=rget(A)
            local ca=_call_args(A,B)
            local ca_n=ca.n
            local _vm=_VF[fn]
            if _vm then
                ca.n=ca_n
                local q={[__VM_Q_KIND__]=__VM_CALL_ENTER__,
                         [__VM_Q_PROTO__]=_vm[__VM_META_PROTO__],
                         [__VM_Q_UPVALS__]=_vm[__VM_META_UPVALS__],
                         [__VM_Q_ARGS__]=_apack(ca,ca_n,(_SS and _SS[1]) or 0),[__VM_Q_CONT__]=_kk,
                         [__VM_Q_FLOW__]=_S[611] or 0,[__VM_Q_LEDGER__]=_XF}
                return _CG[__VM_ROUTE_ENTER__](_NX,
                    _carry(q,_av,137))
            end
            return _native_call(fn,ca,A,C,_av,true,37)

        elseif op==38 then
            close_upvalues(0)
            local r,n=_return_values(A,B)
            return _leave(r,n,_av,38)

        elseif op==39 then _forloop(A,sBx,_av,39)

        elseif op==40 then
            local k=_pxor(_pxor(_S[611] or 0,pc),A)
            local q={[__VM_CF_KEY__]=k,[__VM_CF_TARGET__]=_pxor(pc+sBx,k),[__VM_CF_A__]=_pxor(A,k),[__VM_CF_FIELDS__]={__VM_CF_TARGET__,__VM_CF_A__}}
            q=_flow(q,_av,40); local qa=_cf(q,__VM_CF_A__,40)
            q[__VM_CF_VALUE__]=rget(qa); q[__VM_CF_STEP__]=rget(qa+2)
            q=_LG[__VM_LOOP_FORPREP__](q,_S)
            rset(qa,q[__VM_CF_VALUE__]); pc=_cf(q,__VM_CF_TARGET__,40)

        elseif op==41 then
            local k=_pxor(_pxor(_pxor(_S[611] or 0,pc),A),C)
            local q={[__VM_CF_KEY__]=k,[__VM_CF_A__]=_pxor(A,k),[__VM_CF_C__]=_pxor(C,k),[__VM_CF_FIELDS__]={__VM_CF_A__,__VM_CF_C__}}
            q=_flow(q,_av,41); local qa=_cf(q,__VM_CF_A__,41)
            local qc=_cf(q,__VM_CF_C__,41)
            local _it=rget(qa); local _is=_texpose(rget(qa+1)); local _ic=_texpose(rget(qa+2))
            local res=table.pack(_it(_is,_ic))
            for i=1,qc do rset(qa+2+i,res[i]) end

        elseif op==42 then
            local k=_pxor(_pxor(_S[611] or 0,pc),A)
            local q={[__VM_CF_KEY__]=k,[__VM_CF_TARGET__]=_pxor(pc+sBx,k),[__VM_CF_A__]=_pxor(A,k),[__VM_CF_FIELDS__]={__VM_CF_TARGET__,__VM_CF_A__}}
            q=_flow(q,_av,42); local qa=_cf(q,__VM_CF_A__,42)
            q[__VM_CF_VALUE__]=rget(qa+1)
            local _ls=_aword_key(_pxor(_pshl(pc-1,8),__VM_LOOP_TFORLOOP__))
            if not _LC[_ls] then
                _LC[_ls]=true; q=_LG[__VM_LOOP_TFORLOOP__](q,_S)
            else
                q[__VM_CF_TAKE__]=(q[__VM_CF_VALUE__]~=nil)
            end
            if q[__VM_CF_TAKE__] then rset(qa,q[__VM_CF_VALUE__]);
                pc=_cf(q,__VM_CF_TARGET__,42) end

        elseif op==43 then
            if C==0 then
                local ei=_ixor(code[pc],_ksm(pc)); pc=pc+1
                C=_ifield48(ei,_SH_A,256)*262144+_ifield48(ei,_SH_B,512)*512+_ifield48(ei,_SH_C,512)
            end
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B
            local tbl=rget(A)
            local vals={}; for i=1,cnt do vals[i]=rget(A+i) end
            _sem(__VM_OP_SETLIST__,tbl,vals,{base,cnt})
            _touch(_av,43)

        elseif op==44 then
            get_box(A)
            local fn=_sem(__VM_OP_CLOSURE__,make_closure,_subs[Bx+1],nil)
            rset(A,_carry(fn,_av,44))

        elseif op==45 then
            local _vn=B==0 and _acount(_va) or B-1
            local k=_pxor(_pxor(_pxor(_pxor(_S[611] or 0,pc),A),B),_vn)
            local q={[__VM_CF_KEY__]=k,[__VM_CF_A__]=_pxor(A,k),[__VM_CF_B__]=_pxor(B,k),[__VM_CF_COUNT__]=_pxor(_vn,k),[__VM_CF_FIELDS__]={__VM_CF_A__,__VM_CF_B__,__VM_CF_COUNT__}}
            q=_flow(q,_av,45); local qa=_cf(q,__VM_CF_A__,45)
            local qb=_cf(q,__VM_CF_B__,45)
            local qn=_cf(q,__VM_CF_COUNT__,45)
            if _AY then
                for i=1,qn do rset(qa+i-1,_aget(_va,i)) end
            else
                _sem(__VM_OP_VARARG__,rset,qa,{qn,_va})
            end
            if qb==0 then
                top=qa+qn-1
            end

        elseif op==46 then error("unexpected EXTRAARG")
        elseif op==47 then rset(A,_carry(_sem(__VM_DATA_VALUE__,kval(consts[Bx+1],proto),nil,nil),_av,147))
        elseif op==48 then rset(A,_iu32(_IT.script))
        elseif op==49 then rset(A,_iu32(_IT.vmc))
        elseif op==50 then rset(A,_iu32(_IT.layout))
        elseif op==51 then rset(A,_iu32(_IT.seed))
        elseif op==52 then rset(A,_iu32(proto.vm_id))
        elseif op==53 then rset(A,#proto.code%4294967296)
        elseif op==54 then rset(A,_integrity_xor((rget(B) or 0),(rget(C) or 0)))
        elseif op==55 then rset(A,(_iu32(rget(B) or 0)+_iu32(rget(C) or 0))%4294967296)
        elseif op==56 then rset(A,_imul32(_iu32(rget(B) or 0),_MJ._c_or(rget(C) or 0,1)))
        elseif op==57 then rset(A,consts[Bx+1][2])
        elseif op==58 then pc=_poly_route(_brd[A+1],_pxor(_pxor(A,pc),proto.vm_id))
        elseif op==59 then pc=Bx+1
        elseif op==60 then rset(A,_sem(__VM_DATA_GET__,get_environment(upvals),kval(consts[Bx+1],proto),nil))
        elseif op==61 then _sem(__VM_DATA_SET__,get_environment(upvals),kval(consts[Bx+1],proto),rget(A))
        elseif op==62 then
            local n=_acount(_va);local t=_tnew();_tset(t,"n",_source_value(n))
            for i=1,n do _tset(t,i,_aget(_va,i)) end;rset(A,t)
        else error("unknown op "..op) end
    end
    return _leave({},0,nil,138)
    --<<ENDTARGET_51_KARITY_HANDLER_CHAIN>>
end
--<<ENDEXEC>>
_EX={exec}

--<<NEXT_ROUTER>>
_NX=function(...)
    local q=...
    if q[__VM_Q_KIND__]==__VM_CALL_ENTER__ then
        local p=q[__VM_Q_PROTO__]
        return _EX[p.vm_id+1](p,q[__VM_Q_UPVALS__],q[__VM_Q_ARGS__],nil,
                              nil,q[__VM_Q_CONT__],nil,q[__VM_Q_FLOW__],
                              q[__VM_Q_LEDGER__])
    end
    local k=q[__VM_Q_CONT__]
    local r=q[__VM_Q_RESULT__]
    if not k then return r end
    return _EX[k[__VM_FR_PROTO__].vm_id+1](k[__VM_FR_PROTO__],
               k[__VM_FR_UPVALS__],nil,nil,k,k[__VM_FR_PARENT__],r)
end
--<<ENDNEXT_ROUTER>>

--<<TARGET_FUNCTION_DUMP>>
local function _normalize_function_dump(data)
    assert(#data>=12 and data:sub(1,6)=="\27Lua\81\0","expected standard Lua 5.1 dump")
    local endian,int_size,size_t,instruction_size,number_size,integral=_native_string_byte(data,7,12)
    assert((endian==0 or endian==1) and (int_size==4 or int_size==8) and
           (size_t==4 or size_t==8) and instruction_size==4 and number_size==8 and integral==0,
           "unsupported Lua 5.1 dump ABI")
    local position=13
    local output={"KarityDump51\0"}
    local function take(size)
        assert(size>=0 and position+size<=#data+1,"truncated Lua 5.1 dump")
        local value=data:sub(position,position+size-1)
        position=position+size
        return value
    end
    local function uint(size)
        local raw=take(size)
        local value=0
        for index=1,size do
            local byte=_native_string_byte(raw,endian==1 and size-index+1 or index)
            value=value*256+byte
            assert(value<=4294967295,"Lua 5.1 dump field exceeds canonical width")
        end
        return value
    end
    local function put_uint(value)
        local bytes={}
        for index=1,4 do
            bytes[index]=_native_string_char(value%256);value=_native_math_floor(value/256)
        end
        output[#output+1]=_native_table_concat(bytes)
    end
    local function count()
        local value=uint(int_size)
        assert(value<=2147483647,"negative Lua 5.1 dump count")
        return value
    end
    local function str(keep)
        local size=uint(size_t)
        local raw=take(size)
        assert(size==0 or raw:sub(-1)=="\0","unterminated Lua 5.1 dump string")
        if keep then put_uint(size);output[#output+1]=raw end
    end
    local proto
    proto=function()
        str(false)
        put_uint(uint(int_size));put_uint(uint(int_size))
        output[#output+1]=take(4)
        local total=count();put_uint(total)
        for index=1,total do put_uint(uint(4)) end
        total=count();put_uint(total)
        for index=1,total do
            local tag=take(1);output[#output+1]=tag
            if tag=="\1" then output[#output+1]=take(1)
            elseif tag=="\3" then
                local raw=take(8);output[#output+1]=endian==1 and raw or raw:reverse()
            elseif tag=="\4" then str(true)
            else assert(tag=="\0","unknown Lua 5.1 dump constant tag") end
        end
        total=count();put_uint(total)
        for index=1,total do proto() end
        take(count()*int_size)
        for index=1,count() do str(false);take(int_size*2) end
        for index=1,count() do str(false) end
    end
    proto()
    assert(position==#data+1,"unexpected Lua 5.1 dump tail")
    return _native_table_concat(output)
end
local function _function_dump(fn)
    return _normalize_function_dump(_native_string_dump(fn))
end
--<<ENDTARGET_FUNCTION_DUMP>>

-- Keep the entry closure's helper references behind the existing executor
-- registry. Multi-VM integrity builds otherwise exceed Lua 5.1's 60-upvalue
-- limit as the runtime feature set grows.
_EX._runctx={
    function_dump=_function_dump,crc32=_crc32,ixor=_ixor,line_state=_LS,
    debug=debug,pcall=pcall,string=string,unpack_values=_unpack_values,
    io=io,os=os,math=math,assert=assert,arg=arg,
    IT=_IT,pmix=_pmix,read_proto=read_proto,
    kae_decrypt=kae_decrypt,from_base36=from_base36,make_reader=make_reader,
    CG=_CG,NX=_NX,apack=_apack,env=_ENV,
}
-- Keep the entry closure on the existing executor registry instead of adding
-- another long-lived local to the Lua 5.1 runtime function (which is already
-- close to the target's 200-local compiler limit under full protections).
_EX.run=function(blob,rand_tail,self_func)
    local ctx=_EX._runctx
    local dump=ctx.function_dump(self_func)
    local dump_crc=ctx.crc32(dump)
    local crc=ctx.ixor(dump_crc,(ctx.line_state or 0))
    -- anti-tamper: 변조 신호를 키에 섞는다. clean이면 _t==0 -> crc 불변
    -- -> 팩 타임 키와 일치. 변조 시 _t~=0 -> 키 교란 -> garbage(분기 없음, 패치 불가).
    -- 아래 블록(마커 사이)은 파이프라인이 per-run 랜덤화한다(검사 항목/순서/가중치/
    -- 혼합식). clean일 때 _t==0 -> crc 항등을 항상 보존한다. def는 standalone 기본값.
    --<<TAMPER>>
    -- (1) debug hook(single-step/덤프 후킹) 감지
    local _hk,_hm,_hc=ctx.debug.gethook()
    local _t=0
    if _hk~=nil          then _t=_t+1 end
    if _hm and #_hm>0    then _t=_t+2 end
    if _hc and _hc~=0    then _t=_t+4 end
    -- (2) 보안 핵심 내장함수가 진짜 C 함수인지 검사(Lua 함수로 바꿔치기 감지).
    -- getinfo 자신도 포함(체커 자기보호). 하나라도 비-C면 해당 비트 set.
    local function _isC(f)
        local ok,info=ctx.pcall(ctx.debug.getinfo,f,"S")
        return ok and info~=nil and info.what=="C"
    end
    if not _isC(ctx.debug.getinfo) then _t=_t+8 end
    if not _isC(ctx.string.dump)   then _t=_t+16 end
    if not _isC(ctx.debug.gethook) then _t=_t+32 end
    if not _isC(ctx.string.byte)   then _t=_t+64 end
    if not _isC(ctx.string.char)   then _t=_t+128 end
    if not _isC(ctx.string.format) then _t=_t+256 end
    if not _isC(ctx.unpack_values) then _t=_t+512 end
    crc=(crc~((_t*0x9E3779B1)&0xFFFFFFFF))&0xFFFFFFFF
    --<<ENDTAMPER>>
    ctx.IT.script=crc
    ctx.IT.line=ctx.line_state or 0
    _ksd=dump_crc
    local key="karityObfuscator/"..ctx.string.format("%08x",crc).."/"..rand_tail
    blob=ctx.kae_decrypt(ctx.from_base36(blob),key)
    local r=ctx.make_reader(blob)
    local seed=r.u16()
    ctx.IT.seed=seed; ctx.IT.layout=r.u32(); ctx.IT.vmc=r.u16()
    _PE=_PE+1
    local _pa=tostring({})
    local _pf=tostring(self_func)
    local _aa=tonumber(_pa:match("(%x+)$") or "0",16) or 0
    local _af=tonumber(_pf:match("(%x+)$") or "0",16) or 0
    local _clock=ctx.math.floor(((ctx.os.clock and ctx.os.clock()) or 0)*1000000000)
    local _wall=(ctx.os.time and ctx.os.time()) or 0
    _PN=ctx.pmix((--<<TARGET_PRIVATE_EXPRESSION>>
               _aa~_af~_clock~(_wall<<21)~crc~seed~_PE
               --<<ENDTARGET_PRIVATE_EXPRESSION>>
              ))
    --<<RUNTIME_TRACE>>
    _PX=ctx.pmix((--<<TARGET_PRIVATE_EXPRESSION>>
               _PN~seed~crc
               --<<ENDTARGET_PRIVATE_EXPRESSION>>
              ))
    _PBC=0; _PBH=ctx.pmix((--<<TARGET_PRIVATE_EXPRESSION>>
                        _PN~0x424C4F434B
                        --<<ENDTARGET_PRIVATE_EXPRESSION>>
                       ))
    --<<ENDRUNTIME_TRACE>>
    local acc_state={seed,0}
    -- 가짜 상수 풀 스킵
    --<<TARGET_FAKE_CONSTANT_SKIP>>
local _fn=r.u32()
    for _=1,_fn do
        local _ft=r.u8()
        if _ft==CTAG_NIL then
        elseif _ft==CTAG_BOOL then r.u8()
        elseif _ft==CTAG_INT then r.i64()
        elseif _ft==CTAG_FLOAT then r.f64()
        elseif _ft==CTAG_STR then r.str()
        elseif _ft==CTAG_IEXPR then
            r.i64();local _pn=r.u8()
            for _j=1,_pn do local _op=r.u8();if _op==1 then r.u32() end end
        end
    end
--<<ENDTARGET_FAKE_CONSTANT_SKIP>>
    local proto=ctx.read_proto(r,acc_state)
    local env_box={v=ctx.env}
    --<<RUN_ENTRY>>
    ctx.CG[__VM_ROUTE_ENTER__](ctx.NX[proto.vm_id+1],
        {[__VM_Q_KIND__]=__VM_CALL_ENTER__,[__VM_Q_PROTO__]=proto,
         [__VM_Q_UPVALS__]={env_box,environment=env_box.v},[__VM_Q_ARGS__]=ctx.apack({},0,crc)})
    --<<ENDRUN_ENTRY>>
    --<<RUNTIME_TRACE>>
    ctx.io.stderr:write("karity-vm-trace:",ctx.string.format("%016x",_PX),
                    " blocks:",_PBC," blocktrace:",
                    ctx.string.format("%016x",_PBH),"\n")
    --<<ENDRUNTIME_TRACE>>
end

if _EX._runctx.arg and _EX._runctx.arg[0] and _EX._runctx.arg[0]:match("vm") then
    local f=_EX._runctx.assert(_EX._runctx.io.open(_EX._runctx.arg[1],"rb"))
    local blob=f:read("*a"); f:close()
    _EX.run(blob)
end
