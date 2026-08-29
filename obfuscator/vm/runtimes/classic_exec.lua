local exec, _EX
local _PTRACE=false
local _PN,_PX,_PE,_PBC,_PBH=0,0,0,0,0
local function _pmix(x)
    x=(x~(x>>30))*-4658895280553007687
    x=(x~(x>>27))*-7723592293110705685
    return (x~(x>>31))&-1
end

--<<EXEC>>
exec = function(proto, upvals, args, va_in)
    local regs   = {}
    local boxes  = {}
    local consts = proto["constants"]
    local _subs  = proto["protos"]
    local _brd   = proto["block_routes"]
    local code   = proto["code"]
    local _avd   = proto["avalanche"]
    local _cd    = code   -- rename되지 않는 code 별칭 (fused 핸들러가 다음 슬롯을 읽을 때 사용)
    local pc     = 1
    local top    = -1
    local _st    = 0
    local _va    = va_in or {n=0}
    local _split_tmp
    local _S={[611]=(proto.vm_id~#code)&-1}
    local _XF={0,0}
    local _PR={0,0}
    local _SS={0,0}
    local _MG={0}

    args = args or {}
    local _argc=args.n or #args
    for i=1,proto.num_params do regs[i-1]=args[i] end
    if proto.is_vararg==1 then
        local n=0; _va={}
        for i=proto.num_params+1,_argc do n=n+1; _va[n]=args[i] end
        _va.n=n
    end

    --<<RGET>>
    local function rget(i) return regs[i] end
    --<<ENDRGET>>
    --<<RSET>>
    local function rset(i,v)
        regs[i]=v
        local box=boxes[i]
        if box and not box.set then box.v=v end
    end
    --<<ENDRSET>>

    local function _acount(q) return q and (q.n or #q) or 0 end
    local function _aget(q,i) return q and q[i] or nil end
    local function _av_read() end
    local function _carry(v) return v end
    --<<FLOW>>
    local function _flow(q) return q end
    --<<ENDFLOW>>
    local function _branch(v,expected) return v==expected end
    local function _touch() end
    local function _split_set(v) _split_tmp=v end
    local function _split_get() return _split_tmp end
    local function _tnew() return {} end
    local function _tget(t,k) return t[k] end
    local function _tset(t,k,v) t[k]=v end
    local function _tlen(t) return #t end

    --<<SEM>>
    local function _sem(tag,x,y,z)
        if tag==__VM_DATA_VALUE__ then return x
        elseif tag==__VM_DATA_GET__ then return x[y]
        elseif tag==__VM_DATA_SET__ then x[y]=z; return z
        elseif tag==__VM_CMP_EQ__ then return x==y
        elseif tag==__VM_CMP_LT__ then return x<y
        elseif tag==__VM_CMP_LE__ then return x<=y
        elseif tag==__VM_CMP_TRUTH__ then return not not x
        elseif tag==__VM_OP_MOD__ then return x%y
        elseif tag==__VM_OP_POW__ then return x^y
        elseif tag==__VM_OP_DIV__ then return x/y
        elseif tag==__VM_OP_IDIV__ then return x//y
        elseif tag==__VM_OP_NOT__ then return not x
        elseif tag==__VM_OP_LEN__ then return #x
        elseif tag==__VM_OP_CONCAT__ then
            local out=x[z]; for i=z-1,1,-1 do out=x[i]..out end; return out
        elseif tag==__VM_OP_NEWTABLE__ then return {}
        elseif tag==__VM_OP_SETLIST__ then
            for i=1,z[2] do x[z[1]+i]=y[i] end; return x
        elseif tag==__VM_OP_CLOSURE__ then return x(y)
        elseif tag==__VM_OP_VARARG__ then
            for i=1,z[1] do x(y+i-1,z[2][i]) end; return z[1]
        end
        return x
    end
    --<<ENDSEM>>

    local function _arith2(a,b,av,slot)
        if slot==__VM_SLOT_ADD__ then return a+b
        elseif slot==__VM_SLOT_SUB__ then return a-b
        elseif slot==__VM_SLOT_MUL__ then return a*b
        elseif slot==__VM_SLOT_BAND__ then return a&b
        elseif slot==__VM_SLOT_BOR__ then return a|b
        elseif slot==__VM_SLOT_BXOR__ then return a~b
        elseif slot==__VM_SLOT_SHL__ then return a<<b
        elseif slot==__VM_SLOT_SHR__ then return a>>b end
        error("unknown arithmetic slot")
    end
    local function _arith1(a,av,slot)
        if slot==__VM_SLOT_UNM__ then return -a
        elseif slot==__VM_SLOT_BNOT__ then return ~a end
        error("unknown unary slot")
    end
    local function _arith2r(dst,lhs,rhs,av,slot)
        rset(dst,_arith2(rget(lhs),rget(rhs),av,slot))
    end
    local function _arith1r(dst,src,av,slot)
        rset(dst,_arith1(rget(src),av,slot))
    end
    local function _arith2s(a,b,av,slot) return _arith2(a,b,av,slot) end
    local function _arith1s(a,av,slot) return _arith1(a,av,slot) end
    local function _poly_route(route) return route[1] end

    local function _route_step(ip,op,a,b,c)
        local x=((_PR[1] or 0)~(ip<<17)~(op<<9)~(a<<5)~b~c~_st)&-1
        _PR[1]=x; _SS[1]=((_SS[1] or 0)~x~op)&-1
        _XF[1]=((_XF[1] or 0)~x~pc)&-1; _MG[1]=((_MG[1] or 0)+1)&0x3FF
        _S[611]=((_S[611] or 0)~x)&-1
    end

    -- 상수 풀을 register 파일 상위(256+)에 미리 풀어 넣는다.
    -- RK operand는 reg(0~255) / const(256~) 를 같은 인덱스 공간에서 가리키므로
    -- 이후 모든 rk 접근이 분기 없는 단일 테이블 인덱스(regs[x])로 처리된다.
    for _ci=1,256 do
        local _c=consts[_ci]
        if not _c then break end
        if _c[1]==CK_STR then
            if _c[2] then regs[255+_ci]=_kss(_c[2]) end
        elseif _c[1]~=CK_NIL then
            regs[255+_ci]=kval(_c,proto)
        end
    end

    local function get_box(slot)
        if not boxes[slot] then
            boxes[slot]={
                get=function() return regs[slot] end,
                set=function(v) regs[slot]=v end,
            }
        end
        return boxes[slot]
    end

    local function get_upvalue(box)
        if box.get then return box.get() end
        return box.v
    end

    local function set_upvalue(box,v)
        if box.set then box.set(v) else box.v=v end
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
        return function(...)
            local w=_EX[sub.vm_id+1](sub, new_uv, table.pack(...))
            return table.unpack(w.r, 1, w.n)
        end
    end

    for i in setmetatable({},{__call=function(t)return t end}) do
        --<<FETCH>>
        local _ip=pc; local op,A,B,C,Bx,sBx=decode(code[pc],_ksm(pc));
        local _av=nil; pc=pc+1; _route_step(_ip,op,A,B,C)
        --<<ENDFETCH>>

        if     op==0  then rset(A,rget(B))
        elseif op==1  then rset(A,kval(consts[Bx+1],proto))
        elseif op==2  then
            local ei=code[pc]~_ksm(pc); pc=pc+1
            local ax=(((ei>>_SH_A)&0xFF)<<18)|(((ei>>_SH_B)&0x1FF)<<9)|((ei>>_SH_C)&0x1FF)
            rset(A,kval(consts[ax+1],proto))
        elseif op==3  then rset(A,(B~=0)); if C~=0 then pc=pc+1 end
        elseif op==4  then for i=A,A+B do rset(i,nil) end
        elseif op==5  then rset(A,get_upvalue(upvals[B+1]))
        elseif op==6  then rset(A,get_upvalue(upvals[B+1])[rget(C)])
        elseif op==7  then rset(A,rget(B)[rget(C)])
        elseif op==8  then get_upvalue(upvals[A+1])[rget(B)]=rget(C)
        elseif op==9  then set_upvalue(upvals[B+1],rget(A))
        elseif op==10 then rget(A)[rget(B)]=rget(C)
        elseif op==11 then rset(A,{})
        elseif op==12 then local t=rget(B); rset(A+1,t); rset(A,t[rget(C)])
        elseif op==13 then _arith2r(A,B,C,_av,__VM_SLOT_ADD__)
        elseif op==14 then _arith2r(A,B,C,_av,__VM_SLOT_SUB__)
        elseif op==15 then _arith2r(A,B,C,_av,__VM_SLOT_MUL__)
        elseif op==16 then rset(A,rget(B)%rget(C))
        elseif op==17 then rset(A,rget(B)^rget(C))
        elseif op==18 then rset(A,rget(B)/rget(C))
        elseif op==19 then rset(A,rget(B)//rget(C))
        elseif op==20 then _arith2r(A,B,C,_av,__VM_SLOT_BAND__)
        elseif op==21 then _arith2r(A,B,C,_av,__VM_SLOT_BOR__)
        elseif op==22 then _arith2r(A,B,C,_av,__VM_SLOT_BXOR__)
        elseif op==23 then _arith2r(A,B,C,_av,__VM_SLOT_SHL__)
        elseif op==24 then _arith2r(A,B,C,_av,__VM_SLOT_SHR__)
        elseif op==25 then _arith1r(A,B,_av,__VM_SLOT_UNM__)
        elseif op==26 then _arith1r(A,B,_av,__VM_SLOT_BNOT__)
        elseif op==27 then rset(A,not rget(B))
        elseif op==28 then rset(A,#rget(B))
        elseif op==29 then
            local out=rget(C); for i=C-1,B,-1 do out=rget(i)..out end
            rset(A,out)
        elseif op==30 then pc=pc+sBx
        elseif op==31 then if (rget(B)==rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==32 then if (rget(B)<rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==33 then if (rget(B)<=rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==34 then if (not not rget(A))~=(C~=0) then pc=pc+1 end
        elseif op==35 then
            if (not not rget(B))==(C~=0) then rset(A,rget(B)) else pc=pc+1 end

        elseif op==36 then
            local fn=rget(A); local ca={}; local ca_n=0
            if B==0 then
                for i=A+1,top do ca_n=ca_n+1; ca[ca_n]=rget(i) end
            elseif B>1 then
                for i=A+1,A+B-1 do ca_n=ca_n+1; ca[ca_n]=rget(i) end
            end
            local res=table.pack(fn(table.unpack(ca,1,ca_n)))
            if C==0 then
                for i=1,res.n do rset(A+i-1,res[i]) end; top=A+res.n-1
            elseif C>1 then
                for i=1,C-1 do rset(A+i-1,res[i]) end
            end

        elseif op==37 then
            local fn=rget(A); local ca={}; local ca_n=0
            if B>1 then
                for i=A+1,A+B-1 do ca_n=ca_n+1; ca[ca_n]=rget(i) end
            elseif B==0 then
                for i=A+1,top do ca_n=ca_n+1; ca[ca_n]=rget(i) end
            end
            local res = table.pack(fn(table.unpack(ca,1,ca_n)))
            return {r=res, n=res.n}

        elseif op==38 then
            if B==1 then return {r={},n=0}
            elseif B==0 then
                local r={}; local n=0
                for i=A,top do n=n+1; r[n]=rget(i) end
                return {r=r,n=n}
            else
                local n=B-1; local r={}
                for i=A,A+n-1 do r[i-A+1]=rget(i) end
                return {r=r,n=n}
            end

        elseif op==39 then
            local step=rget(A+2); local limit=rget(A+1)
            local idx=rget(A)+step
            rset(A,idx)
            if (step>0 and idx<=limit) or (step<=0 and idx>=limit) then
                pc=pc+sBx; rset(A+3,idx)
            end

        elseif op==40 then rset(A,rget(A)-rget(A+2)); pc=pc+sBx

        elseif op==41 then
            local res=table.pack(rget(A)(rget(A+1),rget(A+2)))
            for i=1,C do rset(A+2+i,res[i]) end

        elseif op==42 then
            if rget(A+1)~=nil then rset(A,rget(A+1)); pc=pc+sBx end

        elseif op==43 then
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B
            local tbl=rget(A)
            for i=1,cnt do tbl[base+i]=rget(A+i) end

        elseif op==44 then
            get_box(A)
            local fn=make_closure(_subs[Bx+1])
            rset(A,fn)

        elseif op==45 then
            if B==0 then
                local n=_acount(_va)
                for i=1,n do rset(A+i-1,_va[i]) end; top=A+n-1
            else
                for i=1,B-1 do rset(A+i-1,_va[i]) end
            end

        elseif op==46 then error("unexpected EXTRAARG")
        elseif op==47 then rset(A,kval(consts[Bx+1],proto))
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
        elseif op==58 then pc=_poly_route(_brd[A+1])
        elseif op==59 then pc=Bx+1
        else error("unknown op "..op) end
    end
    return {r={},n=0}
end
--<<ENDEXEC>>
_EX={exec}
