-- Lua 5.3 VM (standalone)

----------------------------------------
local _s   = string
local _sc  = _s["char"]
local _sub = _s["sub"]
local _sbyte = _s["byte"]
local _sfind = _s["find"]
local _sunpack = _s["unpack"]
local _sformat = _s["format"]
local _sdump = _s["dump"]
local _t   = table
local _ti  = _t["insert"]
local _tu  = _t["unpack"]
local _tp  = _t["pack"]
local _tc  = _t["concat"]
local _ip  = _ENV["ipairs"]
local _sm  = _ENV["setmetatable"]
local _ts  = _ENV["tostring"]
local _err = _ENV["error"]
local _load = _ENV["load"]
local _loads = _ENV["loadstring"]

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
    for i=1,8 do nonce[i]=_sbyte(blob,i) end
    local n=#blob-8
    local key_ints={}
    for i=1,#key do key_ints[i]=_sbyte(key,i) end
    local blended={}
    for i=0,n+7 do
        blended[i+1]=(key_ints[i%#key_ints+1]~nonce[i%8+1]~_KAE_SBOX[i&0xFF])&0xFF
    end
    local RK=_kae_derive(blended,n)
    local pt={}
    for i=1,n do pt[i]=_sbyte(blob,8+i)~RK[i] end
    return _sc(_tu(pt))
end

----------------------------------------

local _CRC_TABLE
local function _crc32(data)
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
        local b=_sbyte(data,i)
        crc=_CRC_TABLE[(crc~b)&0xFF]~(crc>>8)
    end
    return crc~0xFFFFFFFF
end

----------------------------------------

local function from_base36(s)
    if _sub(s,1,7) ~= "KARITY/" then _err("invalid blob") end
    s = _sub(s,8)
    local sep = _sfind(s,':',1,true)
    local length = 0
    for i=1,sep-1 do
        local c=_sbyte(s,i)
        length=length*36+(c>=48 and c<=57 and c-48 or c-55)
    end
    local bytes={}
    local i=sep+1
    while i+6<=#s do
        local n=0
        for j=i,i+6 do
            local c=_sbyte(s,j)
            n=n*36+(c>=48 and c<=57 and c-48 or c-55)
        end
        bytes[#bytes+1]= n     &0xFF
        bytes[#bytes+1]=(n>> 8)&0xFF
        bytes[#bytes+1]=(n>>16)&0xFF
        bytes[#bytes+1]=(n>>24)&0xFF
        i=i+7
    end
    while #bytes>length do bytes[#bytes]=nil end
    return _sc(_tu(bytes))
end

local function make_reader(blob)
    local pos=1; local r={}
    function r.u8() local v=_sbyte(blob,pos); pos=pos+1; return v end
    function r.u16()
        local a,b=_sbyte(blob,pos,pos+1); pos=pos+2
        return a|(b<<8)
    end
    function r.u32()
        local a,b,c,d=_sbyte(blob,pos,pos+3); pos=pos+4
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
    function r.f64() local v=_sunpack('<d',blob,pos); pos=pos+8; return v end
    function r.str()
        local len=r.u32(); if len==0 then return nil end
        local sv=_sub(blob,pos,pos+len-1); pos=pos+len; return sv
    end
    return r
end

local CTAG_NIL=0;local CTAG_BOOL=1;local CTAG_INT=2;local CTAG_FLOAT=3;local CTAG_STR=4

local function read_proto(r, acc_state)
    local p={}
    p.num_params=r.u8(); p.is_vararg=r.u8(); p.max_stack_size=r.u8()
    local n=r.u32(); p.code={}
    for i=1,n do
        local raw64=r.u64()
        local enc_op      = raw64 & 0x7F
        local enc_variant = (raw64>>40) & 0xFF
        local acc=acc_state[1]; local idx=acc_state[2]
        local actual_op      = enc_op      ~ (acc & 0x7F)
        local actual_variant = enc_variant ~ ((acc>>7) & 0xFF)
        local actual_vop     = actual_op | (actual_variant<<7)
        acc_state[1] = (acc + actual_vop + idx) & 0xFFFF
        acc_state[2] = idx + 1
        raw64 = (raw64 & ~0xFF000000007F) | actual_op | (actual_variant<<40)
        p.code[i]=raw64
    end
    n=r.u32(); p.constants={}
    for i=1,n do
        local tag=r.u8()
        if     tag==CTAG_NIL   then p.constants[i]={0}
        elseif tag==CTAG_BOOL  then p.constants[i]={1,r.u8()~=0}
        elseif tag==CTAG_INT   then p.constants[i]={2,r.i64()}
        elseif tag==CTAG_FLOAT then p.constants[i]={3,r.f64()}
        elseif tag==CTAG_STR   then p.constants[i]={4,r.str()}
        else _err("bad const tag ".._ts(tag)) end
    end
    n=r.u32(); p.upvalues={}
    for i=1,n do p.upvalues[i]={instack=r.u8(),idx=r.u8()} end
    n=r.u32(); p.protos={}
    for i=1,n do p.protos[i]=read_proto(r,acc_state) end
    return p
end

local function kval(k)
    if not k then return nil end
    if k[1]==0 then return nil end
    return k[2]
end

local function decode(ins)
    local op     =  ins        & 0x7F
    local A      = (ins >> 32) & 0xFF
    local B      = (ins >> 23) & 0x1FF
    local C      = (ins >> 14) & 0x1FF
    local variant= (ins >> 40) & 0xFF
    local Bx     = (ins >> 14) & 0x3FFFF
    local sBx    = Bx - 131071
    local vop    = op | (variant << 7)
    return vop,A,B,C,Bx,sBx
end

local exec

exec = function(proto, upvals, args, va_in)
    local regs   = {}
    local boxes  = {}
    local consts = proto["constants"]
    local code   = proto["code"]
    local pc     = 1
    local top    = -1
    local _st    = 0
    local _va    = va_in or {}

    args = args or {}
    for i=1,proto.num_params do regs[i-1]=args[i] end
    if proto.is_vararg==1 then
        for i=proto.num_params+1,#args do _va[#_va+1]=args[i] end
    end

    local function rget(i) return regs[i] end
    local function rset(i,v)
        regs[i]=v
        if boxes[i] then boxes[i].v=v end
    end

    local function rk(x)
        if x>=256 then return kval(consts[x-255]) else return regs[x] end
    end

    local function get_uv(i) return upvals[i].v end
    local function set_uv(i,v) upvals[i].v=v end

    local function get_box(slot)
        if not boxes[slot] then
            boxes[slot]={v=regs[slot]}
        else
            boxes[slot].v=regs[slot]
        end
        return boxes[slot]
    end

    local function make_closure(sub)
        local new_uv={}
        for i,uv in _ip(sub.upvalues) do
            if uv.instack==1 then
                new_uv[i]=get_box(uv.idx)
            else
                new_uv[i]=upvals[uv.idx+1]
            end
        end
        -- exec는 {r=테이블, n=개수} wrapper를 단일값으로 반환.
        -- 래퍼는 이를 받아 native처럼 다중반환으로 변환.
        return function(...)
            local w=exec(sub, new_uv, {...})
            return _tu(w.r, 1, w.n)
        end
    end

    for i in _sm({},{__call=function(t)return t end}) do
        local ins=code[pc]; local op,A,B,C,Bx,sBx=decode(ins); pc=pc+1

        if     op==0  then rset(A,regs[B])
        elseif op==1  then rset(A,kval(consts[Bx+1]))
        elseif op==2  then
            local ei=code[pc]; pc=pc+1
            local ax=(((ei>>32)&0xFF)<<18)|(((ei>>23)&0x1FF)<<9)|((ei>>14)&0x1FF)
            rset(A,kval(consts[ax+1]))
        elseif op==3  then rset(A,(B~=0)); if C~=0 then pc=pc+1 end
        elseif op==4  then for i=A,A+B do rset(i,nil) end
        elseif op==5  then rset(A,get_uv(B+1))
        elseif op==6  then rset(A,get_uv(B+1)[rk(C)])
        elseif op==7  then rset(A,regs[B][rk(C)])
        elseif op==8  then get_uv(A+1)[rk(B)]=rk(C)
        elseif op==9  then set_uv(B+1,regs[A])
        elseif op==10 then regs[A][rk(B)]=rk(C)
        elseif op==11 then rset(A,{})
        elseif op==12 then local t=regs[B]; rset(A+1,t); rset(A,t[rk(C)])
        elseif op==13 then rset(A,rk(B)+rk(C))
        elseif op==14 then rset(A,rk(B)-rk(C))
        elseif op==15 then rset(A,rk(B)*rk(C))
        elseif op==16 then rset(A,rk(B)%rk(C))
        elseif op==17 then rset(A,rk(B)^rk(C))
        elseif op==18 then rset(A,rk(B)/rk(C))
        elseif op==19 then rset(A,rk(B)//rk(C))
        elseif op==20 then rset(A,rk(B)&rk(C))
        elseif op==21 then rset(A,rk(B)|rk(C))
        elseif op==22 then rset(A,rk(B)~rk(C))
        elseif op==23 then rset(A,rk(B)<<rk(C))
        elseif op==24 then rset(A,rk(B)>>rk(C))
        elseif op==25 then rset(A,-regs[B])
        elseif op==26 then rset(A,~regs[B])
        elseif op==27 then rset(A,not regs[B])
        elseif op==28 then rset(A,#regs[B])
        elseif op==29 then
            local t={}; for i=B,C do t[#t+1]=_ts(regs[i]) end
            rset(A,_tc(t))
        elseif op==30 then pc=pc+sBx
        elseif op==31 then if (rk(B)==rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==32 then if (rk(B)<rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==33 then if (rk(B)<=rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==34 then if (not not regs[A])~=(C~=0) then pc=pc+1 end
        elseif op==35 then
            if (not not regs[B])==(C~=0) then rset(A,regs[B]) else pc=pc+1 end

        elseif op==36 then
            local fn=regs[A]; local ca={}; local ca_n=0
            if B==0 then
                for i=A+1,top do ca_n=ca_n+1; ca[ca_n]=regs[i] end
            elseif B>1 then
                for i=A+1,A+B-1 do ca_n=ca_n+1; ca[ca_n]=regs[i] end
            end
            local res=_tp(fn(_tu(ca,1,ca_n)))
            if C==0 then
                for i=1,res.n do rset(A+i-1,res[i]) end; top=A+res.n-1
            elseif C>1 then
                for i=1,C-1 do rset(A+i-1,res[i]) end
            end

        elseif op==37 then
            local fn=regs[A]; local ca={}; local ca_n=0
            if B>1 then
                for i=A+1,A+B-1 do ca_n=ca_n+1; ca[ca_n]=regs[i] end
            elseif B==0 then
                for i=A+1,top do ca_n=ca_n+1; ca[ca_n]=regs[i] end
            end
            local res = _tp(fn(_tu(ca,1,ca_n)))
            return {r=res, n=res.n}

        elseif op==38 then
            if B==1 then return {r={},n=0}
            elseif B==0 then
                local r={}; local n=0
                for i=A,top do n=n+1; r[n]=regs[i] end
                return {r=r,n=n}
            else
                local n=B-1; local r={}
                for i=A,A+n-1 do r[i-A+1]=regs[i] end
                return {r=r,n=n}
            end

        elseif op==39 then
            local step=regs[A+2]; local limit=regs[A+1]
            local idx=regs[A]+step
            rset(A,idx)
            if (step>0 and idx<=limit) or (step<=0 and idx>=limit) then
                pc=pc+sBx; rset(A+3,idx)
            end

        elseif op==40 then rset(A,regs[A]-regs[A+2]); pc=pc+sBx

        elseif op==41 then
            local res=_tp(regs[A](regs[A+1],regs[A+2]))
            for i=1,C do rset(A+2+i,res[i]) end

        elseif op==42 then
            if regs[A+1]~=nil then rset(A,regs[A+1]); pc=pc+sBx end

        elseif op==43 then
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B
            local tbl=regs[A]
            for i=1,cnt do tbl[base+i]=regs[A+i] end

        elseif op==44 then
            boxes[A] = {v=nil}
            local fn=make_closure(proto.protos[Bx+1])
            regs[A]=fn; boxes[A].v=fn

        elseif op==45 then
            if B==0 then
                for i=1,#_va do rset(A+i-1,_va[i]) end; top=A+#_va-1
            else
                for i=1,B-1 do rset(A+i-1,_va[i]) end
            end

        elseif op==46 then _err("unexpected EXTRAARG")
        else _err("unknown op "..op) end
    end
    return {r={},n=0}
end

local function run(blob,rand_tail,self_func)
    local dump=_sdump(self_func,true)
    local crc=_crc32(dump)
    local key="karityObfuscator/".._sformat("%08x",crc).."/"..rand_tail
    blob=kae_decrypt(from_base36(blob),key)
    local r=make_reader(blob)
    local seed=r.u16()
    local acc_state={seed,0}
    -- 가짜 상수 풀 스킵
    local _fn=r.u32()
    for _=1,_fn do
        local _ft=r.u8()
        if     _ft==1 then r.u8()
        elseif _ft==2 then r.i64()
        elseif _ft==3 then r.f64()
        elseif _ft==4 then r.str()
        end
    end
    local proto=read_proto(r,acc_state)
    local env_box={v=_ENV}
    exec(proto,{env_box},{})
end

if arg and arg[0] and arg[0]:match("vm") then
    local f=assert(io.open(arg[1],"rb"))
    local blob=f:read("*a"); f:close()
    run(blob)
else
    return {run=run}
end