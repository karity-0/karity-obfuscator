-- Lua 5.3 VM (standalone)

local function make_reader(blob)
    local pos=1; local r={}
    function r.u8() local v=blob:byte(pos); pos=pos+1; return v end
    function r.u32()
        local a,b,c,d=blob:byte(pos,pos+3); pos=pos+4
        return a|(b<<8)|(c<<16)|(d<<24)
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
        local s=blob:sub(pos,pos+len-1); pos=pos+len; return s
    end
    return r
end

local CTAG_NIL=0;local CTAG_BOOL=1;local CTAG_INT=2;local CTAG_FLOAT=3;local CTAG_STR=4

local function read_proto(r)
    local p={}
    p.num_params=r.u8(); p.is_vararg=r.u8(); p.max_stack_size=r.u8()
    local n=r.u32(); p.code={}
    for i=1,n do p.code[i]=r.u32() end
    n=r.u32(); p.constants={}
    for i=1,n do
        local tag=r.u8()
        if     tag==CTAG_NIL   then p.constants[i]={tag='nil'}
        elseif tag==CTAG_BOOL  then p.constants[i]={tag='bool',v=(r.u8()~=0)}
        elseif tag==CTAG_INT   then p.constants[i]={tag='int', v=r.i64()}
        elseif tag==CTAG_FLOAT then p.constants[i]={tag='flt', v=r.f64()}
        elseif tag==CTAG_STR   then p.constants[i]={tag='str', v=r.str()}
        else error("bad const tag "..tag) end
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
    local op=ins&0x3F; local A=(ins>>6)&0xFF
    local C=(ins>>14)&0x1FF; local B=(ins>>23)&0x1FF
    local Bx=(ins>>14)&0x3FFFF; local sBx=Bx-131071
    return op,A,B,C,Bx,sBx
end

local exec

exec = function(proto, upvals, args, va_in)
    local regs   = {}   -- slot → plain value
    local boxes  = {}   -- slot → {v=value}  (upvalue로 캡처된 슬롯만)
    local consts = proto["constants"]
    local code   = proto["code"]
    local pc     = 1
    local top    = -1
    local _va    = va_in or {}

    -- 인자 세팅
    args = args or {}
    for i=1,proto.num_params do regs[i-1]=args[i] end
    if proto.is_vararg==1 then
        for i=proto.num_params+1,#args do _va[#_va+1]=args[i] end
    end

    -- regs 읽기/쓰기: 박스가 있으면 박스도 동기화
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

    -- 슬롯을 박스로 승격 (upvalue 캡처 시점)
    local function get_box(slot)
        if not boxes[slot] then
            boxes[slot]={v=regs[slot]}
        else
            boxes[slot].v=regs[slot]  -- 현재 값 동기화
        end
        return boxes[slot]
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
        return function(...)
            return exec(sub, new_uv, {...})
        end
    end

    while true do
        local ins=code[pc]; local op,A,B,C,Bx,sBx=decode(ins); pc=pc+1

        if     op==0  then rset(A,regs[B])
        elseif op==1  then rset(A,kval(consts[Bx+1]))
        elseif op==2  then
            local ax=(code[pc]>>6)&0x3FFFFFF; pc=pc+1
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
            local t={}; for i=B,C do t[#t+1]=tostring(regs[i]) end
            rset(A,table.concat(t))
        elseif op==30 then pc=pc+sBx
        elseif op==31 then if (rk(B)==rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==32 then if (rk(B)<rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==33 then if (rk(B)<=rk(C))~=(A~=0) then pc=pc+1 end
        elseif op==34 then if (not not regs[A])~=(C~=0) then pc=pc+1 end
        elseif op==35 then
            if (not not regs[B])==(C~=0) then rset(A,regs[B]) else pc=pc+1 end

        elseif op==36 then  -- CALL
            local fn=regs[A]; local ca={}
            if B==0 then
                for i=A+1,top do ca[#ca+1]=regs[i] end
            elseif B>1 then
                for i=A+1,A+B-1 do ca[#ca+1]=regs[i] end
            end
            local res=table.pack(fn(table.unpack(ca)))
            if C==0 then
                for i=1,res.n do rset(A+i-1,res[i]) end; top=A+res.n-1
            elseif C>1 then
                for i=1,C-1 do rset(A+i-1,res[i]) end
            end

        elseif op==37 then  -- TAILCALL
            local fn=regs[A]; local ca={}
            if B>1 then for i=A+1,A+B-1 do ca[#ca+1]=regs[i] end end
            return fn(table.unpack(ca))

        elseif op==38 then  -- RETURN
            if B==1 then return
            elseif B==0 then
                local ret={}; for i=A,top do ret[#ret+1]=regs[i] end
                return table.unpack(ret)
            else
                local ret={}; for i=A,A+B-2 do ret[#ret+1]=regs[i] end
                return table.unpack(ret)
            end

        elseif op==39 then  -- FORLOOP
            local step=regs[A+2]; local limit=regs[A+1]
            local idx=regs[A]+step
            rset(A,idx)
            if (step>0 and idx<=limit) or (step<=0 and idx>=limit) then
                pc=pc+sBx; rset(A+3,idx)
            end

        elseif op==40 then  -- FORPREP
            rset(A,regs[A]-regs[A+2]); pc=pc+sBx

        elseif op==41 then  -- TFORCALL
            local res=table.pack(regs[A](regs[A+1],regs[A+2]))
            for i=1,C do rset(A+2+i,res[i]) end

        elseif op==42 then  -- TFORLOOP
            if regs[A+1]~=nil then rset(A,regs[A+1]); pc=pc+sBx end

        elseif op==43 then  -- SETLIST
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B
            local tbl=regs[A]
            for i=1,cnt do tbl[base+i]=regs[A+i] end

        elseif op==44 then  -- CLOSURE
            -- 먼저 박스 확보 (재귀 자기 캡처 대비)
            if not boxes[A] then boxes[A]={v=nil} end
            local fn=make_closure(proto.protos[Bx+1])
            regs[A]=fn; boxes[A].v=fn

        elseif op==45 then  -- VARARG
            if B==0 then
                for i=1,#_va do rset(A+i-1,_va[i]) end; top=A+#_va-1
            else
                for i=1,B-1 do rset(A+i-1,_va[i]) end
            end

        elseif op==46 then error("unexpected EXTRAARG")
        else error("unknown op "..op) end
    end
end

local function run(blob)
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