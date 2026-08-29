-- Lua 5.3 VM (standalone)

----------------------------------------
local _KAE_PRIMES={0x07,0x0B,0x0D,0x11,0x13,0x17,0x1D,0x1F}

local function _gf_mul(a,b)
    local p=0
    for _=1,8 do
        if b&1~=0 then p=p~a end
        local hi=a&0x80
        a=(a<<1)&0xFF
        if hi~=0 then a=a~0x1B end
        b=b>>1
    end
    return p
end

local _KAE_SBOX do
    local function _gf_inv(x)
        if x==0 then return 0 end
        local r,base,exp=1,x,254
        while exp>0 do
            if exp&1~=0 then r=_gf_mul(r,base) end
            base=_gf_mul(base,base); exp=exp>>1
        end
        return r
    end
    local function _affine(x)
        local c,result=0x63,0
        for i=0,7 do
            local bit=((x>>i)&1)~((x>>((i+4)%8))&1)~((x>>((i+5)%8))&1)~
                      ((x>>((i+6)%8))&1)~((x>>((i+7)%8))&1)~((c>>i)&1)
            result=result|(bit<<i)
        end
        return result
    end
    _KAE_SBOX={}
    for i=0,255 do _KAE_SBOX[i]=_affine(_gf_inv(i)) end
end

local function _kae_derive(key_bytes, length)
    local K,prev={},0x6A
    for i=0,length-1 do
        local k0=key_bytes[i%#key_bytes+1]
        local raw=_gf_mul(_KAE_SBOX[(k0~i~(i>>3))&0xFF],_KAE_PRIMES[i%8+1])
        local ki=raw~((prev<<3|prev>>5)&0xFF)~((i*0x97)&0xFF)
        K[i+1]=ki; prev=ki
    end
    return K
end

local function kae_decrypt(blob, key)
    local nonce={}
    for i=1,8 do nonce[i]=string.byte(blob,i) end
    local n=#blob-8
    local key_ints={}
    for i=1,#key do key_ints[i]=string.byte(key,i) end
    local blended={}
    for i=0,n+7 do
        blended[i+1]=(key_ints[i%#key_ints+1]~nonce[i%8+1]~_KAE_SBOX[i&0xFF])&0xFF
    end
    local RK=_kae_derive(blended,n)
    local pt={}
    for i=1,n do pt[i]=string.byte(blob,8+i)~RK[i] end
    local chunks={}
    for i=1,#pt,4096 do
        local last=i+4095; if last>#pt then last=#pt end
        chunks[#chunks+1]=string.char(table.unpack(pt,i,last))
    end
    return table.concat(chunks)
end

----------------------------------------

local _CRC_TABLE
local function _crc32(data)
    local __VM_HOT_LOOP__=true
    if not _CRC_TABLE then
        _CRC_TABLE={}
        for i=0,255 do
            local c=i
            for _=1,8 do
                if c&1~=0 then c=0xEDB88320~(c>>1) else c=c>>1 end
            end
            _CRC_TABLE[i]=c
        end
    end
    local crc=0xFFFFFFFF
    for i=1,#data do
        local b=string.byte(data,i)
        crc=_CRC_TABLE[(crc~b)&0xFF]~(crc>>8)
    end
    return crc~0xFFFFFFFF
end

----------------------------------------

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
        bytes[#bytes+1]= n     &0xFF
        bytes[#bytes+1]=(n>> 8)&0xFF
        bytes[#bytes+1]=(n>>16)&0xFF
        bytes[#bytes+1]=(n>>24)&0xFF
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

local function make_reader(blob)
    local pos=1; local r={}
    function r.u8() local v=string.byte(blob,pos); pos=pos+1; return v end
    function r.u16()
        local a,b=string.byte(blob,pos,pos+1); pos=pos+2
        return a|(b<<8)
    end
    function r.u32()
        local a,b,c,d=string.byte(blob,pos,pos+3); pos=pos+4
        return a|(b<<8)|(c<<16)|(d<<24)
    end
    function r.u64()
        local lo=r.u32(); local hi=r.u32()
        return lo|(hi*0x100000000)
    end
    function r.i64()
        local lo=r.u32(); local hi=r.u32()
        if hi==0 then return lo end
        if hi==0xFFFFFFFF then return lo-0x100000000 end
        if hi>=0x80000000 then
            return -((~hi&0xFFFFFFFF)*0x100000000+((~lo&0xFFFFFFFF)+1))
        end
        return hi*0x100000000+lo
    end
    function r.f64() local v=string.unpack('<d',blob,pos); pos=pos+8; return v end
    function r.str()
        local len=r.u32(); if len==0 then return nil end
        local sv=string.sub(blob,pos,pos+len-1); pos=pos+len; return sv
    end
    return r
end

local CTAG_NIL=__VM_CTAG_NIL__;local CTAG_BOOL=__VM_CTAG_BOOL__;local CTAG_INT=__VM_CTAG_INT__;local CTAG_FLOAT=__VM_CTAG_FLOAT__;local CTAG_STR=__VM_CTAG_STR__;local CTAG_IEXPR=__VM_CTAG_IEXPR__
local CK_NIL=__VM_CK_NIL__;local CK_BOOL=__VM_CK_BOOL__;local CK_INT=__VM_CK_INT__;local CK_FLOAT=__VM_CK_FLOAT__;local CK_STR=__VM_CK_STR__;local CK_IEXPR=__VM_CK_IEXPR__
local _IT={seed=0,layout=0,vmc=1,script=0,line=0}

-- 런타임 내부 keystream: read_proto가 디코드 직후 code[i]를 메모리에서 한 번 더
-- 마스킹하고, exec가 fetch 시점에 동일 마스크로 푼다. 따라서 메모리에 상주하는
-- p.code[]는 항상 마스킹된 상태(평문 명령어가 통째로 상주하지 않음).
-- _ksd는 run()에서 crc로 세팅 -> 리터럴이 아니고 tamper에 엮임. read_proto와
-- exec가 같은 _ksd를 쓰므로 한 run 안에서 항상 round-trip(실행 정확성 보장).
local _ksd=0
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
    for i=1,n do
        local raw64=r.u64()
        local enc_op      = raw64 & 0x7F
        local enc_variant = (raw64>>_SH_V) & 0xFF
        local acc=acc_state[1]; local idx=acc_state[2]
        local actual_op      = enc_op      ~ (acc & 0x7F)
        local actual_variant = enc_variant ~ ((acc>>7) & 0xFF)
        local actual_vop     = actual_op | (actual_variant<<7)
        acc_state[1] = (acc + actual_vop + idx) & 0xFFFF
        acc_state[2] = idx + 1
        raw64 = (raw64 & ~_MASK_OV) | actual_op | (actual_variant<<_SH_V)
        p.code[i]=raw64 ~ _ksm(i)
    end
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
    n=r.u16(); p.block_routes={}
    for i=1,n do
        local rn=r.u8(); local route={}
        for j=1,rn do route[j]=r.u32() end
        p.block_routes[i]=route
    end
    n=r.u32(); p.constants={}
    for i=1,n do
        local tag=r.u8()
        if     tag==CTAG_NIL   then p.constants[i]={CK_NIL}
        elseif tag==CTAG_BOOL  then p.constants[i]={CK_BOOL,r.u8()~=0}
        elseif tag==CTAG_INT   then p.constants[i]={CK_INT,r.i64()}
        elseif tag==CTAG_FLOAT then p.constants[i]={CK_FLOAT,r.f64()}
        elseif tag==CTAG_STR   then local _s=r.str(); p.constants[i]={CK_STR,_s and _kss(_s) or nil}
        elseif tag==CTAG_IEXPR then
            local _e=r.i64(); local _pn=r.u8(); local _p={}
            for _j=1,_pn do
                local _op=r.u8()
                if _op==1 then _p[_j]={_op,r.u32()} else _p[_j]={_op} end
            end
            p.constants[i]={CK_IEXPR,_e,_p}
        else error("bad const tag "..tostring(tag)) end
    end
    n=r.u32(); p.upvalues={}
    for i=1,n do p.upvalues[i]={instack=r.u8(),idx=r.u8()} end
    n=r.u32(); p.protos={}
    for i=1,n do p.protos[i]=read_proto(r,acc_state) end
    return p
end

local function _imix(proto)
    return (_IT.seed~((_IT.vmc&0xFFFF)<<11)~_IT.layout~
            ((proto.vm_id&0xFF)<<23)~((#proto.code&0xFFFF)*0x45D9F3B))&0xFFFFFFFF
end

local function _ieval(prog,proto)
    local st,sp={},0
    for i=1,#prog do
        local ins=prog[i]; local op=ins[1]
        if op==1 then sp=sp+1; st[sp]=ins[2]&0xFFFFFFFF
        elseif op==2 then sp=sp+1; st[sp]=_IT.seed&0xFFFFFFFF
        elseif op==3 then sp=sp+1; st[sp]=_IT.vmc&0xFFFFFFFF
        elseif op==4 then sp=sp+1; st[sp]=_IT.layout&0xFFFFFFFF
        elseif op==5 then sp=sp+1; st[sp]=proto.vm_id&0xFFFFFFFF
        elseif op==6 then sp=sp+1; st[sp]=#proto.code&0xFFFFFFFF
        elseif op==10 then sp=sp+1; st[sp]=_IT.script&0xFFFFFFFF
        elseif op==11 then sp=sp+1; st[sp]=_IT.line&0xFFFFFFFF
        else
            local b=st[sp]; local a=st[sp-1]; sp=sp-1
            if op==7 then st[sp]=(a~b)&0xFFFFFFFF
            elseif op==8 then st[sp]=(a+b)&0xFFFFFFFF
            elseif op==9 then st[sp]=(a*(b|1))&0xFFFFFFFF
            else st[sp]=(a~b)&0xFFFFFFFF end
        end
    end
    return st[sp]&0xFFFFFFFF
end

local function kval(k,proto)
    if not k then return nil end
    if k[1]==CK_NIL then return nil end
    if k[1]==CK_STR and k[2] then return _kss(k[2]) end
    if k[1]==CK_IEXPR then
        return k[2]~_ieval(k[3],proto)
    end
    return k[2]
end

local function decode(ins,key)
    ins=ins~key
    local op     =  ins         & 0x7F
    local A      = (ins >> _SH_A) & 0xFF
    local B      = (ins >> _SH_B) & 0x1FF
    local C      = (ins >> _SH_C) & 0x1FF
    local variant= (ins >> _SH_V) & 0xFF
    local Bx     = (ins >> _SH_C) & 0x3FFFF
    local sBx    = Bx - 131071
    local vop    = op | (variant << 7)
    return vop,A,B,C,Bx,sBx
end

local exec, _EX, _NX
local _VF=setmetatable({},{__mode="k"})
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
local _PTRACE=__VM_POLY_TRACE__
local _SY=__VM_SEMANTIC_STATE__
local _AY=__VM_ARGUMENT_VIRTUALIZATION__
local _UY=__VM_UPVALUE_VIRTUALIZATION__
local _TY=__VM_TABLE_VIRTUALIZATION__
local _BY=__VM_BRANCH_VIRTUALIZATION__
local _PN,_PX,_PE,_PBC,_PBH=0,0,0,0,0

local function _vid(p)
    return p.vm_id
end

local function _pmix(x)
    x=(x~(x>>30))*-4658895280553007687
    x=(x~(x>>27))*-7723592293110705685
    return (x~(x>>31))&-1
end

local _AC=0
local _AN={}
local function _aseed(q)
    return q[__VM_AP_SEED__]~__VM_ARG_MASK__~(_IT.layout or 0)~_ksd
end
local function _akey(seed,i)
    return _pmix(seed~(i*-7046029254386353131)~__VM_ARG_KEY__)
end
local function _apack(values,n,flow)
    if not _AY then values.n=n; return values end
    _AC=_AC+1
    local seed=_pmix(_PN~(_IT.seed or 0)~(flow or 0)~n~(_AC<<21))
    local q={
        [__VM_AP_MARK__]=__VM_ARG_TAG__,
        [__VM_AP_SEED__]=seed~__VM_ARG_MASK__~(_IT.layout or 0)~_ksd,
        [__VM_AP_COUNT__]=n~(seed&0x7FFFFFFF),
        [__VM_AP_DATA__]={},
    }
    local data=q[__VM_AP_DATA__]
    for i=1,n do
        local v=values[i]
        data[_akey(seed,i)]=(v==nil and _AN or v)
    end
    local pads=(seed&3)+1
    for i=1,pads do data[_pmix(seed~i~__VM_ARG_PAD__)]=_pmix(seed+i) end
    return q
end
local function _acount(q)
    if q and q[__VM_AP_MARK__]==__VM_ARG_TAG__ then
        local seed=_aseed(q)
        return q[__VM_AP_COUNT__]~(seed&0x7FFFFFFF)
    end
    return q and (q.n or #q) or 0
end
local function _aget(q,i)
    if q and q[__VM_AP_MARK__]==__VM_ARG_TAG__ then
        if i>_acount(q) then return nil end
        local v=q[__VM_AP_DATA__][_akey(_aseed(q),i)]
        if v==nil then error("argument packet mismatch "..i.."/".._acount(q)) end
        if v==_AN then return nil end
        return v
    end
    return q and q[i] or nil
end

local _UV=setmetatable({},{__mode="k"})
local _UO={}
local _UI=setmetatable({},{__mode="k"})
local _UC=0
local _TM=setmetatable({},{__mode="k"})
local _TC=0

--<<EXEC>>
exec = function(proto, upvals, args, va_in, _fr, _kk, _rr, _zz, _xx)
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
    local pc     = _fr and (_fr[__VM_FR_PC__]~_fm) or 1
    local top    = _fr and (_fr[__VM_FR_TOP__]~_fm) or -1
    local _st    = _fr and (_fr[__VM_FR_STATE__]~(_fm&0xFF)) or 0
    local _va    = _fr and _fr[__VM_FR_VARARG__] or va_in or {}
    local _split_tmp = _fr and _fr[__VM_FR_SPLIT__]
    local _split_share = _fr and _fr[__VM_FR_SPLIT_SHARE__]
    local _split_epoch = _fr and _fr[__VM_FR_SPLIT_EPOCH__]
    local _split_kind = _fr and _fr[__VM_FR_SPLIT_TYPE__]
    local _S     = _fr and _fr[__VM_FR_SCRATCH__] or {[611]=_zz or 0}
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
                   (((_zz or 0)~(_IT.seed or 0)~(proto.vm_id<<17)~#code~
                    ((_PY~=0 and _PN) or 0))|1)
    local _MG    = _fr and _fr[__VM_FR_MAP_STATE__] or
                   {((_IT.seed~proto.vm_id~#code~
                     ((_PY~=0 and _PN) or 0))&0x3FF),0}
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
        _PR={_rmix(_PN~(_zz or 0)~(_IT.seed or 0)~
                   (proto.vm_id<<19)~#code),0}
    end

    if not _SS then
        _SS={_rmix((_zz or 0)~(_IT.seed or 0)~(_IT.layout or 0)~
                   (_IT.script or 0)~(proto.vm_id<<23)~#code~_ksd~
                   ((_XF and _XF[2]) or 0)),0}
    end

    local function _ss_step(ip,op,a,b,c)
        if not _SY then return end
        local n=(_SS[2] or 0)+1
        local x=_rmix((_SS[1] or 0)~(ip<<32)~(op<<24)~(a<<16)~
                      (b<<7)~c~n~(_S[611] or 0)~(_XF[1] or 0)~
                      ((_XF and _XF[2]) or 0)~(_PR[1] or 0)~
                      ((_MG[1] or 0)<<11)~_st~_ksd)
        _SS[1],_SS[2]=x,n
        _XF[2]=_rmix((_XF[2] or 0)~x~op~ip)
    end

    local function _ss_value(slot,encoded,epoch,kind)
        if not _SY then return end
        local x=_rmix((_SS[1] or 0)~slot~encoded~epoch~(kind or 0)~
                      ((_RX[1] or 0)<<1)~((_MG[1] or 0)<<17)~
                      (_XF[2] or 0))
        _SS[1]=x
        _XF[2]=_rmix((_XF[2] or 0)~x~slot~epoch)
    end

    local function _route_step(ip,op,a,b,c)
        if _PY==0 then return end
        local n=(_PR[2] or 0)+1
        local x=((_PR[1] or 0)~_PN~(ip<<32)~(op<<24)~
                 (a<<16)~(b<<7)~c~n~(_MG[1]<<3)~(_RX[1] or 0))&-1
        x=(x~(x<<13)~(x>>7)~(x<<17))&-1
        _PR[1],_PR[2]=x,n
        if _PTRACE then _PX=_rmix(_PX~x~ip~(op<<11)~n) end
    end

    local function _poly_gate(salt)
        return ((_PR[1] or 0)~salt~((_PR[2] or 0)<<7))&0xFFFF
    end

    local function _poly_word(salt)
        return _rmix((_PR[1] or 0)~salt~((_PR[2] or 0)<<17)~_PN)
    end

    local function _poly_pick(count,salt,baseline)
        if _PY==0 then return baseline end
        if _poly_gate(salt)>=_PY then return baseline end
        local x=_poly_word(salt)
        local pick=((x>>16)%count)+1
        if _PTRACE then _PX=_rmix(_PX~x~pick~salt) end
        return pick
    end

    local function _poly_lazy(salt)
        if _PY==0 then return true end
        if _poly_gate(salt)>=_PY then return true end
        local x=_poly_word(salt)
        local lazy=((x>>16)&1)==0
        if _PTRACE then
            _PX=_rmix(_PX~x~(lazy and 0x4C415A59 or 0x4E4F5721))
        end
        return lazy
    end

    local function _poly_route(route,salt)
        local x=_poly_word(salt~#route~0x424C4F43)
        local pick=((x>>16)%#route)+1
        if _PTRACE then _PX=_rmix(_PX~x~pick~salt~0x524F5554) end
        _PBC=_PBC+1
        _PBH=_pmix(_PBH~x~pick~route[pick]~_PBC)
        _PR[1]=(_PR[1]~x~route[pick])&-1
        return route[pick]
    end

    local function _rparams(slot,epoch)
        local z=_rmix(_RZ~epoch~((slot+1)*-7046029254386353131))
        local pair=_RP[(z&15)+1]
        return pair[1],_rmix(z~-2960836687051489901),pair[2]
    end

    local function _rnext(slot,salt)
        _RX[1]=((_RX[1] or 0)-7046029254386353131+slot+(salt or 0))&-1
        return _rmix(_RX[1]~_RZ~(_SY and (_SS[1] or 0) or 0))
    end

    local function _rpos_at(kind,slot,generation)
        local map=_MP[kind]
        return (slot*map[1]+map[2]+generation*map[3])&0x3FF
    end

    local function _rpositions_at(slot,generation)
        return _rpos_at(1,slot,generation),_rpos_at(2,slot,generation),
               _rpos_at(3,slot,generation),_rpos_at(4,slot,generation)
    end

    local function _rmap_offsets()
        local generation=_MG[1]
        for kind=1,5 do
            local map=_MP[kind]
            _MG[kind+2]=(map[2]+generation*map[3])&0x3FF
        end
    end

    local function _rpos(kind,slot)
        return (slot*_MP[kind][1]+_MG[kind+2])&0x3FF
    end

    local function _rpositions(slot)
        return (slot*_MP[1][1]+_MG[3])&0x3FF,
               (slot*_MP[2][1]+_MG[4])&0x3FF,
               (slot*_MP[3][1]+_MG[5])&0x3FF,
               (slot*_MP[4][1]+_MG[6])&0x3FF
    end

    _rmap_offsets()

    local function _rstore(slot,encoded,epoch,kind)
        _PD[_rpos(5,slot)]=nil
        local share=_rmix(epoch~_RZ~((slot+3)*-3372029247567499371))
        local p1,p2,p3,p4=_rpositions(slot)
        regs[p1]=encoded-share
        _RS[p2]=share
        _RE[p3]=epoch
        if kind~=nil then _RT[p4]=kind end
        _RL[slot]=true
        _ss_value(slot,encoded,epoch,kind)
    end

    local function _rdecode(encoded,kind)
        if kind==1 then return encoded end
        if kind==2 then return encoded~=0 end
        if kind==3 then return nil end
        return _RO[encoded]
    end

    local function _rvalue(v,epoch)
        if math.type(v)=="integer" then return v,1 end
        if type(v)=="boolean" then return v and 1 or 0,2 end
        if v==nil then return _rmix(epoch~_RZ~0x4E494C),3 end
        local id
        if not (type(v)=="number" and v~=v) then id=_RI[v] end
        if id==nil then
            _RX[2]=(_RX[2] or 0)+1; id=_RX[2]; _RO[id]=v
            if not (type(v)=="number" and v~=v) then _RI[v]=id end
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
        return _rdecode(((regs[p1]+_RS[p2])-b)*inv,_RT[p4])
    end
    --<<ENDRGET>>

    --<<RSET>>
    local function rset(i,v)
        local seal=_seal_next
        _seal_next=nil
        local salt=0
        if seal then
            local desc=seal[1]
            salt=desc[2]~desc[3]~(seal[2] or 0)~seal[3]
        end
        local epoch=_rnext(i,salt)
        local payload,kind=_rvalue(v,epoch)
        local a,b=_rparams(i,epoch)
        _rstore(i,a*payload+b,epoch,kind)
    end
    --<<ENDRSET>>

    local function _rrotate(slot,salt)
        local p1,p2,p3=_rpositions(slot)
        local old_epoch=_RE[p3]
        if old_epoch==nil then return end
        local _,old_b,old_inv=_rparams(slot,old_epoch)
        local new_epoch=_rnext(slot,salt)
        local new_a,new_b=_rparams(slot,new_epoch)
        local alpha=new_a*old_inv
        local beta=new_b-alpha*old_b
        local delta=_rmix(new_epoch~salt~_RZ)
        regs[p1]=alpha*regs[p1]+delta
        _RS[p2]=alpha*_RS[p2]+beta-delta
        _RE[p3]=new_epoch
    end

    local function _rmap_rotate(salt)
        local old_generation=_MG[1]
        local step=(_rmix(_RZ~salt~old_generation)&0x3FF)|1
        local new_generation=(old_generation+step)&0x3FF
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
        if _MG[2]<=2 or (_MG[2]&1023)==0 then
            _rmap_rotate(salt~(_SY and (_SS[1] or 0) or 0))
        end
    end

    local function _split_set(v)
        local epoch=_rnext(-7,0x53504C49)
        local payload,kind=_rvalue(v,epoch)
        local a,b=_rparams(-7,epoch)
        local encoded=a*payload+b
        _split_share=_rmix(epoch~_RZ~0x544D5053)
        _split_tmp=encoded-_split_share
        _split_epoch=epoch
        _split_kind=kind
    end

    local function _split_get()
        if _split_epoch==nil then return _split_tmp end
        local _,b,inv=_rparams(-7,_split_epoch)
        return _rdecode(((_split_tmp+_split_share)-b)*inv,_split_kind)
    end

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
            _S[611]=((_S[611] or 0)~v~slot)
            _XF[1]=((_XF[1] or 0)~v~slot)
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
            local epoch=_rmix(_RZ~_UC~(_SS[1] or 0)~(_XF[2] or 0)~__VM_UV_SEED__)
            local payload,kind
            if math.type(v)=="integer" then payload,kind=v,1
            elseif type(v)=="boolean" then payload,kind=(v and 1 or 0),2
            elseif v==nil then payload,kind=_rmix(epoch~__VM_UV_NIL__),3
            else
                if not (type(v)=="number" and v~=v) then payload=_UI[v] end
                if payload==nil then
                    payload=#_UO+1; _UO[payload]=v
                    if not (type(v)=="number" and v~=v) then _UI[v]=payload end
                end
                kind=4
            end
            local pair=_RP[(epoch&15)+1]
            -- Closed boxes cross VM frame boundaries.  Derive their representation
            -- from the box epoch rather than the current frame's register seed so
            -- every closure sharing the box can decode the same payload.
            local bias=_rmix(epoch~__VM_UV_BIAS__)
            local encoded=pair[1]*payload+bias
            local share=_rmix(epoch~__VM_UV_SHARE__)
            q={[__VM_UV_LEFT__]=encoded-share,[__VM_UV_RIGHT__]=share,
               [__VM_UV_EPOCH__]=epoch,[__VM_UV_KIND__]=kind}
            _UV[box]=q; box.v=nil
            _ss_value(-31,encoded,epoch,kind)
        end
        local epoch=q[__VM_UV_EPOCH__]
        local pair=_RP[(epoch&15)+1]
        local bias=_rmix(epoch~__VM_UV_BIAS__)
        local payload=((q[__VM_UV_LEFT__]+q[__VM_UV_RIGHT__])-bias)*pair[2]
        local kind=q[__VM_UV_KIND__]
        if kind==1 then return payload end
        if kind==2 then return payload~=0 end
        if kind==3 then return nil end
        return _UO[payload]
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
        local salt=_rmix(_TC~(_SS[1] or 0)~(_XF[2] or 0)~
                         _RZ~__VM_TABLE_SEED__)
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
        local physical=_rmix(m[__VM_TB_SALT__]~id~__VM_TABLE_KEY__)
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
           type(right)=="number" then return left+right end
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
            local share=_rmix(m[__VM_TB_SALT__]~physical~
                              (_SS[1] or 0)~__VM_TABLE_SHARE__)
            m[__VM_TB_LEFT__][physical]=v-share
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
                   type(right)=="number" then x=x+right end
                v[_texpose(k,seen)]=_texpose(x,seen)
            end
        end
        return v
    end

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
        local fn=function(...)
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
        _VF[fn]={[__VM_META_PROTO__]=sub,[__VM_META_UPVALS__]=new_uv}
        return fn
    end

    local _carry

    local function _frame(a,c,parent)
        if proto.max_stack_size>0 then
            local slot=((pc~a~c~(_S[611] or 0))&0x7FFFFFFF)%proto.max_stack_size
            _rrotate(slot,pc~a~c)
        end
        _rmap_tick(pc~a~c~(_S[611] or 0))
        local m=(_S[611] or 0)~(_XF[1] or 0)~((_st<<8)|(_st&0xFF))
        for slot in pairs(_AA) do
            local p1=_rpos(1,slot); m=m~regs[p1]~slot
        end
        return {[__VM_FR_REGS__]=regs,[__VM_FR_BOXES__]=boxes,
                [__VM_FR_MASK__]=m,[__VM_FR_PC__]=pc~m,
                [__VM_FR_TOP__]=top~m,
                [__VM_FR_STATE__]=_st~(m&0xFF),[__VM_FR_VARARG__]=_va,
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
                [__VM_FR_UPVALS__]=upvals,[__VM_FR_A__]=a~m,
                [__VM_FR_C__]=c~m,[__VM_FR_PARENT__]=parent}
    end

    local function _leave(r,n,av,tag)
        local q={
            [__VM_Q_KIND__]=__VM_CALL_LEAVE__,[__VM_Q_CONT__]=_kk,
            [__VM_Q_RESULT__]={[__VM_RES_VALUES__]=r,[__VM_RES_COUNT__]=n},
            [__VM_Q_FLOW__]=_S[611] or 0,[__VM_Q_LEDGER__]=_XF}
        return _CG[__VM_ROUTE_LEAVE__](_NX,_carry(q,av,tag))
    end

    local function _int2(a, b)
        local _t0=type(a)
        local _t1=type(b)
        local _mt=math.type
        local _m0=(_t0=="number" and 1) or 0
        local _m1=(_t1=="number" and 1) or 0
        local _m2=(_mt and 1) or 0
        local _m3=(_mt and _mt(a)=="integer" and 1) or 0
        local _m4=(_mt and _mt(b)=="integer" and 1) or 0
        local _r0=(_m0&_m2)*(_m1&_m4)
        local _r1=(_m3~1)~1
        return 1+((_r0&_r1)&1)
    end

    local function _int1(a)
        local _mt=math.type
        local _m0=(type(a)=="number" and 1) or 0
        local _m1=(_mt and 1) or 0
        local _m2=(_mt and _mt(a)=="integer" and 1) or 0
        local _r=(_m0&_m1)*((_m2~1)~1)
        return 1+(_r&1)
    end

    local function _cross(delta)
        _XF[1]=((_XF[1] or 0)~delta)&-1
        local k=_kk
        if not k then return end
        local old=k[__VM_FR_MASK__]
        local new=(old~delta)&-1
        k[__VM_FR_PC__]=(k[__VM_FR_PC__]~old)~new
        k[__VM_FR_TOP__]=(k[__VM_FR_TOP__]~old)~new
        k[__VM_FR_STATE__]=(k[__VM_FR_STATE__]~(old&0xFF))~(new&0xFF)
        k[__VM_FR_A__]=(k[__VM_FR_A__]~old)~new
        k[__VM_FR_C__]=(k[__VM_FR_C__]~old)~new
        k[__VM_FR_MASK__]=new
    end

    _carry=function(v,av,tag)
        if not av then
            _S[1731]=((_S[1731] or 0)~tag~(pc&0xFF))
            return v
        end
        _cross((tag~pc~(_S[611] or 0))&-1)
        local pick=_poly_pick(2,tag~pc~0x56414C55,(((tag*5+3)&1)+1))
        return _GV[pick](v,_S,av,rset,_AA,boxes,tag)
    end

    --<<FLOW>>
    local function _flow(q,av,tag)
        q=_carry(q,av,tag)
        if av then
            local site=((pc-1)<<8)~tag
            if not _FC[site] then
                _FC[site]=true
                local base=((tag~pc~proto.vm_id~(_S[611] or 0))&1)+1
                local pick=_poly_pick(2,site~tag~0x464C4F57,base)
                q=_FG[pick](q,_S)
            end
        end
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then return q end
        local site=desc[2]
        local hit=_GC[site] or 0
        _GC[site]=hit+1
        local live=((_S[desc[4]] or 0)~(_S[611] or 0)~(_XF[1] or 0)~
                    desc[2]~desc[3]~_st~hit~tag)&-1
        _S[desc[4]]=live
        local old=q[__VM_CF_KEY__]
        local key=(live~desc[2]~desc[3]~tag)&-1
        for _,f in ipairs(q[__VM_CF_FIELDS__]) do q[f]=(q[f]~old)~key end
        q[__VM_CF_KEY__]=nil
        q[__VM_CF_SEAL__]=desc
        local mixed=(live~hit~tag)&-1
        if (desc[5]&1)~=0 then _S[611]=((_S[611] or 0)~mixed)&-1 end
        if (desc[5]&2)~=0 then _XF[1]=((_XF[1] or 0)~mixed)&-1 end
        if proto.max_stack_size>0 then
            _rrotate((site~tag~hit)%proto.max_stack_size,mixed)
        end
        _rmap_tick(mixed~site~tag)
        return q
    end
    --<<ENDFLOW>>

    local function _cf(q,field,tag)
        local desc=q[__VM_CF_SEAL__]
        if not desc then return q[field]~q[__VM_CF_KEY__] end
        local key=((_S[desc[4]] or 0)~desc[2]~desc[3]~tag)&-1
        return q[field]~key
    end

    local function _branch(v,expected,av,tag)
        if not _BY then return v==expected end
        local k=(_S[611] or 0)~(_SS[1] or 0)~(_XF[2] or 0)~
                (pc<<17)~tag~__VM_BRANCH_SEED__
        local bit=(v==expected) and 1 or 0
        local q={[__VM_CF_KEY__]=k,[__VM_CF_TAKE__]=bit~k,
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
        local site=((pc-1)<<32)~tag
        local route=((_DG[2][tag]~_DG[3][tag]~pc~(_S[611] or 0))&1)+1
        local semantic=_DG[1][route]
        local bank=semantic[1][semantic[2][tag]~semantic[3][tag]]
        local hit=_SC[site] or 0
        _SC[site]=hit+1
        local base=hit==0 and 1 or 2
        local pick=_poly_pick(2,site~tag~hit~0x53454D41,base)
        return bank[pick](x,y,z,_S)
    end
    --<<ENDSEM>>

    local function _touch(av,tag)
        _carry(nil,av,tag)
    end

    local function _graph_for(desc)
        if not desc or desc[1]==0 then return nil,nil end
        local site=desc[2]
        local hit=_GC[site] or 0
        _GC[site]=hit+1
        if hit==0 or (((hit~desc[3]~(_S[611] or 0)~_st)&15)==0) then
            return _OG[desc[1]],hit
        end
        return false,hit
    end

    local function _couple_direct(v,desc,hit)
        local rv=0
        if math.type(v)=="integer" then rv=v end
        local mixed=(desc[2]~desc[3]~rv~_st~(hit or 0))&-1
        local key=desc[4]
        _S[key]=((_S[key] or 0)~mixed)&-1
        local policy=desc[5]
        if (policy&1)~=0 then
            _S[611]=((_S[611] or 0)~mixed~desc[2])&-1
        end
        if (policy&2)~=0 then
            _XF[1]=((_XF[1] or 0)~mixed~desc[3])&-1
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
        local base=((pc~slot~proto.vm_id~(_S[611] or 0))&1)+1
        local route=((_AR[2][slot]~_AR[3][slot]~pc~(_S[611] or 0))&1)+1
        local arithmetic=_AR[1][route]
        local semantic_index=arithmetic[3][slot]~arithmetic[4][slot]
        local graph,hit=_graph_for(desc)
        if graph then
            local pick=_poly_pick(4,slot~pc~0x41524932,base)
            local bank=arithmetic[_int2(a,b)][semantic_index]
            local out=graph(bank,pick,a,b,_S,av,rset,_AA,boxes,_XF,_st,
                            desc[2],desc[3],desc[4],desc[5])
            return _seal_result(out,desc,hit)
        end
        local pick=_poly_pick(2,slot~pc~0x41524932,base)
        local out=arithmetic[1][semantic_index][pick](a,b)
        if graph==false then
            out=_couple_direct(out,desc,hit)
            return out
        end
        return out
    end

    local function _arith1(a,av,slot,desc)
        local base=((pc~slot~proto.vm_id~(_S[611] or 0))&1)+1
        local route=((_AR[2][slot]~_AR[3][slot]~pc~(_S[611] or 0))&1)+1
        local arithmetic=_AR[1][route]
        local semantic_index=arithmetic[3][slot]~arithmetic[4][slot]
        local graph,hit=_graph_for(desc)
        if graph then
            local pick=_poly_pick(4,slot~pc~0x41524931,base)
            local bank=arithmetic[_int1(a)][semantic_index]
            local out=graph(bank,pick,a,a,_S,av,rset,_AA,boxes,_XF,_st,
                            desc[2],desc[3],desc[4],desc[5])
            return _seal_result(out,desc,hit)
        end
        local pick=_poly_pick(2,slot~pc~0x41524931,base)
        local out=arithmetic[1][semantic_index][pick](a)
        if graph==false then
            out=_couple_direct(out,desc,hit)
            return out
        end
        return out
    end

    local function _elinear2(dst,lhs,rhs,sign)
        if _PD[_rpos(5,lhs)]~=nil then _pending_finish(lhs) end
        if _PD[_rpos(5,rhs)]~=nil then _pending_finish(rhs) end
        local l1,l2,l3,l4=_rpositions(lhs)
        local r1,r2,r3,r4=_rpositions(rhs)
        local le,re=_RE[l3],_RE[r3]
        if le==nil or re==nil or _RT[l4]~=1 or _RT[r4]~=1 then return false end
        local _,lb,li=_rparams(lhs,le)
        local _,rb,ri=_rparams(rhs,re)
        local epoch=_rnext(dst,sign~lhs~(rhs<<8))
        local oa,ob=_rparams(dst,epoch)
        local encoded=oa*li*(regs[l1]+_RS[l2]-lb)+
                      sign*oa*ri*(regs[r1]+_RS[r2]-rb)+ob
        _rstore(dst,encoded,epoch,1)
        return true
    end

    local function _elinear1(dst,src,sign)
        if _PD[_rpos(5,src)]~=nil then _pending_finish(src) end
        local p1,p2,p3,p4=_rpositions(src)
        local se=_RE[p3]
        if se==nil or _RT[p4]~=1 then return false end
        local _,sb,si=_rparams(src,se)
        local epoch=_rnext(dst,sign~src)
        local oa,ob=_rparams(dst,epoch)
        _rstore(dst,sign*oa*si*(regs[p1]+_RS[p2]-sb)+ob,epoch,1)
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
        local share=_rmix(snapshot[3]~salt~_RZ)
        return scale*inverse*(snapshot[1]+snapshot[2]-bias)-share,share
    end

    _pending_finish=function(dst)
        local physical=_rpos(5,dst)
        local q=_PD[physical]
        if q==nil then return end
        _PD[physical]=nil
        local encoded=q[2]+q[3]
        if q[1]==__VM_PENDING_UNM__ then
            encoded=-encoded
        else
            local right=q[4]+q[5]
            encoded=encoded+(q[1]==__VM_PENDING_ADD__ and right or -right)
        end
        _rstore(dst,encoded+q[7],q[6],1)
    end

    local function _defer2r(dst,lhs,rhs,av,slot,token)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then
            local left=_pending_snapshot(lhs)
            local right=_pending_snapshot(rhs)
            if left and right and _poly_lazy(token~dst~lhs~(rhs<<8)) then
                local epoch=_rnext(dst,token~lhs~(rhs<<8))
                local scale,bias=_rparams(dst,epoch)
                local l1,l2=_pending_fragment(left,scale,epoch~token)
                local r1,r2=_pending_fragment(right,scale,epoch~token~1)
                _PD[_rpos(5,dst)]={token,l1,l2,r1,r2,epoch,bias}
                _RL[dst]=true
                return
            end
        end
        rset(dst,_arith2(rget(lhs),rget(rhs),av,slot,desc))
    end

    local function _defer1r(dst,src,av,slot,token)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if not desc or desc[1]==0 then
            local value=_pending_snapshot(src)
            if value and _poly_lazy(token~dst~src) then
                local epoch=_rnext(dst,token~src)
                local scale,bias=_rparams(dst,epoch)
                local p1,p2=_pending_fragment(value,scale,epoch~token)
                _PD[_rpos(5,dst)]={token,p1,p2,nil,nil,epoch,bias}
                _RL[dst]=true
                return
            end
        end
        rset(dst,_arith1(rget(src),av,slot,desc))
    end

    local function _arith2r(dst,lhs,rhs,av,slot,linear)
        _gq=(_gq or 0)+1
        local desc=_gsl and _gsl[_gq]
        if linear and (not desc or desc[1]==0) and
           _elinear2(dst,lhs,rhs,linear) then return end
        rset(dst,_arith2(rget(lhs),rget(rhs),av,slot,desc))
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
        local _ra=_fr[__VM_FR_A__]~_fm
        local _rc=_fr[__VM_FR_C__]~_fm
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
        local key=(_S[611] or 0)~pc~sbx
        local packet={[__VM_CF_KEY__]=key,
                      [__VM_CF_TARGET__]=(pc+sbx)~key,
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
        local key=(_S[611] or 0)~pc~a
        local packet={[__VM_CF_KEY__]=key,
                      [__VM_CF_TARGET__]=(pc+sbx)~key,
                      [__VM_CF_FIELDS__]={__VM_CF_TARGET__}}
        packet[__VM_CF_VALUE__]=rget(a)
        packet[__VM_CF_STEP__]=step
        packet[__VM_CF_LIMIT__]=limit
        packet=_flow(packet,av,tag)
        local site=((pc-1)<<8)~__VM_LOOP_FORLOOP__
        if not _LC[site] then
            _LC[site]=true
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

    for i in setmetatable({},{__call=function(t)return t end}) do
        --<<FETCH>>
        _av_read(); local _ip=pc; _gsl=_gsd[_ip]; _gq=0; local _dk=(_S[611] or 0)~(_XF[1] or 0); local ins=(code[pc]~_ksm(pc))~_dk; local _av=_avd[_ip]; local op,A,B,C,Bx,sBx=decode(ins,_dk); pc=pc+1; _route_step(_ip,op,A,B,C); _ss_step(_ip,op,A,B,C)
        --<<ENDFETCH>>

        if     op==0  then rset(A,_carry(_sem(__VM_DATA_VALUE__,rget(B),nil,nil),_av,0))
        elseif op==1  then rset(A,_carry(_sem(__VM_DATA_VALUE__,kval(consts[Bx+1],proto),nil,nil),_av,1))
        elseif op==2  then
            local ei=((code[pc]~_ksm(pc))~_dk)~_dk; pc=pc+1
            local ax=(((ei>>_SH_A)&0xFF)<<18)|(((ei>>_SH_B)&0x1FF)<<9)|((ei>>_SH_C)&0x1FF)
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
        elseif op==30 then pc=_jump(sBx,_av,30)
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
            local r,n=_return_values(A,B)
            return _leave(r,n,_av,38)

        elseif op==39 then _forloop(A,sBx,_av,39)

        elseif op==40 then
            local k=(_S[611] or 0)~pc~A
            local q={[__VM_CF_KEY__]=k,[__VM_CF_TARGET__]=(pc+sBx)~k,[__VM_CF_A__]=A~k,[__VM_CF_FIELDS__]={__VM_CF_TARGET__,__VM_CF_A__}}
            q=_flow(q,_av,40); local qa=_cf(q,__VM_CF_A__,40)
            q[__VM_CF_VALUE__]=rget(qa); q[__VM_CF_STEP__]=rget(qa+2)
            q=_LG[__VM_LOOP_FORPREP__](q,_S)
            rset(qa,q[__VM_CF_VALUE__]); pc=_cf(q,__VM_CF_TARGET__,40)

        elseif op==41 then
            local k=(_S[611] or 0)~pc~A~C
            local q={[__VM_CF_KEY__]=k,[__VM_CF_A__]=A~k,[__VM_CF_C__]=C~k,[__VM_CF_FIELDS__]={__VM_CF_A__,__VM_CF_C__}}
            q=_flow(q,_av,41); local qa=_cf(q,__VM_CF_A__,41)
            local qc=_cf(q,__VM_CF_C__,41)
            local _it=rget(qa); local _is=_texpose(rget(qa+1)); local _ic=_texpose(rget(qa+2))
            local res=table.pack(_it(_is,_ic))
            for i=1,qc do rset(qa+2+i,res[i]) end

        elseif op==42 then
            local k=(_S[611] or 0)~pc~A
            local q={[__VM_CF_KEY__]=k,[__VM_CF_TARGET__]=(pc+sBx)~k,[__VM_CF_A__]=A~k,[__VM_CF_FIELDS__]={__VM_CF_TARGET__,__VM_CF_A__}}
            q=_flow(q,_av,42); local qa=_cf(q,__VM_CF_A__,42)
            q[__VM_CF_VALUE__]=rget(qa+1)
            local _ls=((pc-1)<<8)~__VM_LOOP_TFORLOOP__
            if not _LC[_ls] then
                _LC[_ls]=true; q=_LG[__VM_LOOP_TFORLOOP__](q,_S)
            else
                q[__VM_CF_TAKE__]=(q[__VM_CF_VALUE__]~=nil)
            end
            if q[__VM_CF_TAKE__] then rset(qa,q[__VM_CF_VALUE__]);
                pc=_cf(q,__VM_CF_TARGET__,42) end

        elseif op==43 then
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
            local k=(_S[611] or 0)~pc~A~B~_vn
            local q={[__VM_CF_KEY__]=k,[__VM_CF_A__]=A~k,[__VM_CF_B__]=B~k,[__VM_CF_COUNT__]=_vn~k,[__VM_CF_FIELDS__]={__VM_CF_A__,__VM_CF_B__,__VM_CF_COUNT__}}
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
        elseif op==48 then rset(A,_IT.script&0xFFFFFFFF)
        elseif op==49 then rset(A,_IT.vmc&0xFFFFFFFF)
        elseif op==50 then rset(A,_IT.layout&0xFFFFFFFF)
        elseif op==51 then rset(A,_IT.seed&0xFFFFFFFF)
        elseif op==52 then rset(A,proto.vm_id&0xFFFFFFFF)
        elseif op==53 then rset(A,#proto.code&0xFFFFFFFF)
        elseif op==54 then rset(A,(rget(B) or 0)~(rget(C) or 0))
        elseif op==55 then rset(A,((rget(B) or 0)+(rget(C) or 0))&0xFFFFFFFF)
        elseif op==56 then rset(A,((rget(B) or 0)*((rget(C) or 0)|1))&0xFFFFFFFF)
        elseif op==57 then rset(A,consts[Bx+1][2])
        elseif op==58 then pc=_poly_route(_brd[A+1],A~pc~proto.vm_id)
        elseif op==59 then pc=Bx+1
        else error("unknown op "..op) end
    end
    return _leave({},0,nil,138)
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

local function run(blob,rand_tail,self_func)
    local dump=string.dump(self_func,true)
    local dump_crc=_crc32(dump)
    local crc=(dump_crc~(_LS or 0))&0xFFFFFFFF
    -- anti-tamper: 변조 신호를 키에 섞는다. clean이면 _t==0 -> crc 불변
    -- -> 팩 타임 키와 일치. 변조 시 _t~=0 -> 키 교란 -> garbage(분기 없음, 패치 불가).
    -- 아래 블록(마커 사이)은 파이프라인이 per-run 랜덤화한다(검사 항목/순서/가중치/
    -- 혼합식). clean일 때 _t==0 -> crc 항등을 항상 보존한다. def는 standalone 기본값.
    --<<TAMPER>>
    -- (1) debug hook(single-step/덤프 후킹) 감지
    local _hk,_hm,_hc=debug.gethook()
    local _t=0
    if _hk~=nil          then _t=_t+1 end
    if _hm and #_hm>0    then _t=_t+2 end
    if _hc and _hc~=0    then _t=_t+4 end
    -- (2) 보안 핵심 내장함수가 진짜 C 함수인지 검사(Lua 함수로 바꿔치기 감지).
    -- getinfo 자신도 포함(체커 자기보호). 하나라도 비-C면 해당 비트 set.
    local function _isC(f)
        local ok,info=pcall(debug.getinfo,f,"S")
        return ok and info~=nil and info.what=="C"
    end
    if not _isC(debug.getinfo) then _t=_t+8 end
    if not _isC(string.dump)   then _t=_t+16 end
    if not _isC(debug.gethook) then _t=_t+32 end
    if not _isC(string.byte)   then _t=_t+64 end
    if not _isC(string.char)   then _t=_t+128 end
    if not _isC(string.format) then _t=_t+256 end
    if not _isC(table.unpack)  then _t=_t+512 end
    crc=(crc~((_t*0x9E3779B1)&0xFFFFFFFF))&0xFFFFFFFF
    --<<ENDTAMPER>>
    _IT.script=crc
    _IT.line=_LS or 0
    _ksd=dump_crc
    local key="karityObfuscator/"..string.format("%08x",crc).."/"..rand_tail
    blob=kae_decrypt(from_base36(blob),key)
    local r=make_reader(blob)
    local seed=r.u16()
    _IT.seed=seed; _IT.layout=r.u32(); _IT.vmc=r.u16()
    _PE=_PE+1
    local _pa=tostring({})
    local _pf=tostring(self_func)
    local _aa=tonumber(_pa:match("(%x+)$") or "0",16) or 0
    local _af=tonumber(_pf:match("(%x+)$") or "0",16) or 0
    local _clock=math.floor(((os.clock and os.clock()) or 0)*1000000000)
    local _wall=(os.time and os.time()) or 0
    _PN=_pmix(_aa~_af~_clock~(_wall<<21)~crc~seed~_PE)
    _PX=_pmix(_PN~seed~crc)
    _PBC=0; _PBH=_pmix(_PN~0x424C4F434B)
    local acc_state={seed,0}
    -- 가짜 상수 풀 스킵
    local _fn=r.u32()
    for _=1,_fn do
        local _ft=r.u8()
        if     _ft==CTAG_NIL then
        elseif _ft==CTAG_BOOL then r.u8()
        elseif _ft==CTAG_INT then r.i64()
        elseif _ft==CTAG_FLOAT then r.f64()
        elseif _ft==CTAG_STR then r.str()
        elseif _ft==CTAG_IEXPR then
            r.i64(); local _pn=r.u8()
            for _j=1,_pn do local _op=r.u8(); if _op==1 then r.u32() end end
        end
    end
    local proto=read_proto(r,acc_state)
    local env_box={v=_ENV}
    --<<RUN_ENTRY>>
    _CG[__VM_ROUTE_ENTER__](_NX[proto.vm_id+1],
        {[__VM_Q_KIND__]=__VM_CALL_ENTER__,[__VM_Q_PROTO__]=proto,
         [__VM_Q_UPVALS__]={env_box},[__VM_Q_ARGS__]=_apack({},0,crc)})
    --<<ENDRUN_ENTRY>>
    if _PTRACE then
        io.stderr:write("karity-vm-trace:",string.format("%016x",_PX),
                        " blocks:",_PBC," blocktrace:",
                        string.format("%016x",_PBH),"\n")
    end
end

if arg and arg[0] and arg[0]:match("vm") then
    local f=assert(io.open(arg[1],"rb"))
    local blob=f:read("*a"); f:close()
    run(blob)
else
    return {run=run}
end
