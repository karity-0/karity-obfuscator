-- Lua 5.3 VM (standalone)

----------------------------------------
local _s   = string
local _sc  = _s["char"]
local _sub = _s["sub"]
local _sbyte = _s["byte"]
local _sfind = _s["find"]
local _sunpack = _s["unpack"]
local _t   = table
local _ti  = _t["insert"]
local _tu  = _t["unpack"]
local _tp  = _t["pack"]
local _tc  = _t["concat"]
local _ip  = ipairs
local _sm  = setmetatable
local _ts  = tostring
local _err = error

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

local function from_base36(s)
    if _sub(s,1,7) ~= "KARITY/" then
        _err("invalid blob")
    end
    s = _sub(s,8)
    local sep=_sfind(s,':',1,true)
    local length=0
    for i=1,sep-1 do
        local c=_sbyte(_sub(s,i,i),1)
        length=length*36+(c>=48 and c<=57 and c-48 or c-55)
    end
    local d={}
    for i=sep+1,#s do
        local c=_sbyte(_sub(s,i,i),1)
        d[#d+1]=c>=48 and c<=57 and c-48 or c-55
    end
    local bytes={}
    local function is_zero()
        for _,v in _ip(d) do if v~=0 then return false end end
        return true
    end
    while not is_zero() do
        local rem=0
        for i=1,#d do
            local val=rem*36+d[i]
            d[i]=val//256; rem=val%256
        end
        _ti(bytes,1,rem)
    end
    while #bytes<length do _ti(bytes,1,0) end
    return _sc(_tu(bytes))
end

local function make_reader(blob)
    local pos=1; local r={}
    function r.u8() local v=_sbyte(blob,pos); pos=pos+1; return v end
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

local function read_proto(r)
    local p={}
    p.num_params=r.u8(); p.is_vararg=r.u8(); p.max_stack_size=r.u8()
    local n=r.u32(); p.code={}
    for i=1,n do p.code[i]=r.u64() end
    n=r.u32(); p.constants={}
    for i=1,n do
        local tag=r.u8()
        if     tag==CTAG_NIL   then p.constants[i]={tag='nil'}
        elseif tag==CTAG_BOOL  then p.constants[i]={tag='bool',v=(r.u8()~=0)}
        elseif tag==CTAG_INT   then p.constants[i]={tag='int', v=r.i64()}
        elseif tag==CTAG_FLOAT then p.constants[i]={tag='flt', v=r.f64()}
        elseif tag==CTAG_STR   then p.constants[i]={tag='str', v=r.str()}
        else _err("bad const tag ".._ts(tag)) end
    end
    n=r.u32(); p.upvalues={}
    for i=1,n do p.upvalues[i]={instack=r.u8(),idx=r.u8()} end
    n=r.u32(); p.protos={}
    for i=1,n do p.protos[i]=read_proto(r) end
    return p
end

local function kval(k)
    if not k then return nil end
    if k.tag=='nil' then return nil end
    return k.v
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
        return function(...)
            return exec(sub, new_uv, {...})
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
            local fn=regs[A]; local ca={}
            if B==0 then
                for i=A+1,top do ca[#ca+1]=regs[i] end
            elseif B>1 then
                for i=A+1,A+B-1 do ca[#ca+1]=regs[i] end
            end
            local res=_tp(fn(_tu(ca)))
            if C==0 then
                for i=1,res.n do rset(A+i-1,res[i]) end; top=A+res.n-1
            elseif C>1 then
                for i=1,C-1 do rset(A+i-1,res[i]) end
            end

        elseif op==37 then
            local fn=regs[A]; local ca={}
            if B>1 then for i=A+1,A+B-1 do ca[#ca+1]=regs[i] end end
            return fn(_tu(ca))

        elseif op==38 then
            if B==1 then return
            elseif B==0 then
                local ret={}; for i=A,top do ret[#ret+1]=regs[i] end
                return _tu(ret)
            else
                local ret={}; for i=A,A+B-2 do ret[#ret+1]=regs[i] end
                return _tu(ret)
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
            if not boxes[A] then boxes[A]={v=nil} end
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
end

local function run(blob,key)
    blob=kae_decrypt(from_base36(blob),key)
    local r=make_reader(blob)
    local proto=read_proto(r)
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