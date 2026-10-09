-- Lua 5.1 target runtime template; maintained independently from Lua 5.3.
local exec, _EX
local _VF=setmetatable({},{__mode="kv"})
local _PN,_PE=0,0
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

--<<EXEC>>
--<<TARGET_CLASSIC_EXEC_NATIVE>>
exec = function(proto, upvals, args, va_in, _source_parents)
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
    -- Classic keeps its routing state in exact 32-bit native limbs.  Source
    -- values never enter these helpers; the generated executor only feeds
    -- decoded fields, program counters, and its own routing state.
    local function _c_u32(value) return value%4294967296 end
    local function _c_xor(a,b) return _ixor(_c_u32(a),_c_u32(b)) end
    local function _c_and(a,b) return _pand_limb(_c_u32(a),_c_u32(b)) end
    local function _c_or(a,b) return _por_limb(_c_u32(a),_c_u32(b)) end
    local function _c_not(a) return 4294967295-_c_u32(a) end
    local _c_shl,_c_shr
    _c_shl=function(a,b)
        if b<0 then return _c_shr(a,-b) end
        if b>=32 then return 0 end
        return (_c_u32(a)%2^(32-b))*2^b
    end
    _c_shr=function(a,b)
        if b<0 then return _c_shl(a,-b) end
        if b>=32 then return 0 end
        return math.floor(_c_u32(a)/2^b)
    end
    local _S={[611]=_c_xor(proto.vm_id,#code)}
    local _MJ={}
    _MJ._c_u32=_c_u32;_MJ._c_xor=_c_xor;_MJ._c_and=_c_and;_MJ._c_or=_c_or
    _MJ._c_not=_c_not;_MJ._c_shl=_c_shl;_MJ._c_shr=_c_shr
    local _XF={0,0}
    local _PR={0,0}
    local _SS={0,0}
    local _MG={0}

    --<<TARGET_USER_STATEMENT>>
    args = args or {}
    local _argc=args.n or #args
    for i=1,proto.num_params do regs[i-1]=args[i] end
    if proto.is_vararg==1 then
        local n=0; _va={}
        for i=proto.num_params+1,_argc do n=n+1; _va[n]=args[i] end
        _va.n=n
    end
    --<<ENDTARGET_USER_STATEMENT>>

    --<<RGET>>
    local function rget(i) return regs[i] end
    --<<ENDRGET>>
    --<<RSET>>
    local function rset(i,v)
        if i<proto.max_stack_size then v=_source_value(v) end
        regs[i]=v
        local box=boxes[i]
        if box and not box.set then box.v=v end
    end
    --<<ENDRSET>>

    --<<TARGET_USER_STATEMENT>>
    local function _acount(q) return q and (q.n or #q) or 0 end
    local function _aget(q,i) if q then return q[i] end; return nil end
    local function _collect_values(first,count)
        if count==nil then count=top-first+1 end
        if count<0 then count=0 end
        local values={n=count}
        for i=1,count do values[i]=rget(first+i-1) end
        return values
    end
    local function _store_values(first,values,count)
        for i=1,count do rset(first+i-1,values[i]) end
    end
    --<<ENDTARGET_USER_STATEMENT>>
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
        elseif tag==__VM_DATA_SET__ then
            x[y]=z
            return z
        elseif tag==__VM_CMP_EQ__ then return x==y
        elseif tag==__VM_CMP_LT__ then return x<y
        elseif tag==__VM_CMP_LE__ then return x<=y
        elseif tag==__VM_CMP_TRUTH__ then return not not x
        elseif tag==__VM_OP_MOD__ then return x%y
        elseif tag==__VM_OP_POW__ then return x^y
        elseif tag==__VM_OP_DIV__ then return x/y
        elseif tag==__VM_OP_IDIV__ then return math.floor(x/y)
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
        elseif slot==__VM_SLOT_BAND__ then return _c_and(a,b)
        elseif slot==__VM_SLOT_BOR__ then return _c_or(a,b)
        elseif slot==__VM_SLOT_BXOR__ then return _c_xor(a,b)
        elseif slot==__VM_SLOT_SHL__ then return _c_shl(a,b)
        elseif slot==__VM_SLOT_SHR__ then return _c_shr(a,b) end
        error("unknown arithmetic slot")
    end
    local function _arith1(a,av,slot)
        if slot==__VM_SLOT_UNM__ then return -a
        elseif slot==__VM_SLOT_BNOT__ then return _c_not(a) end
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
        local x=_PR[1] or 0
        x=_c_xor(x,_c_shl(ip,17));x=_c_xor(x,_c_shl(op,9))
        x=_c_xor(x,_c_shl(a,5));x=_c_xor(x,b);x=_c_xor(x,c);x=_c_xor(x,_st)
        _PR[1]=x; _SS[1]=_c_xor(_c_xor(_SS[1] or 0,x),op)
        _XF[1]=_c_xor(_c_xor(_XF[1] or 0,x),pc); _MG[1]=((_MG[1] or 0)+1)%1024
        _S[611]=_c_xor(_S[611] or 0,x)
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

    --<<TARGET_USER_STATEMENT>>
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
        local metadata={sub,new_uv}
        local fn=function(...)
            local sub,new_uv=metadata[1],metadata[2]
            local w=_EX[sub.vm_id+1](sub, new_uv, _pack_values(...),nil,{})
            return _unpack_values(w.r, 1, w.n)
        end
        _VF[fn]=metadata
        return bind_environment(fn,new_uv,upvals)
    end
    --<<ENDTARGET_USER_STATEMENT>>

    --[[VM_DISPATCH_ENTRY]] while true do
        --<<FETCH>>
        local _ip=pc; local op,A,B,C,Bx,sBx=decode(code[pc],_ksm(pc));
        local _av=nil; pc=pc+1; _route_step(_ip,op,A,B,C)
        --<<ENDFETCH>>

        if     op==0  then rset(A,rget(B))
        elseif op==1  then rset(A,kval(consts[Bx+1],proto))
        elseif op==2  then
            local ei=_ixor(code[pc],_ksm(pc)); pc=pc+1
            local ax=_c_or(_c_or(_c_shl(_ifield48(ei,_SH_A,256),18),_c_shl(_ifield48(ei,_SH_B,512),9)),_ifield48(ei,_SH_C,512))
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
        elseif op==19 then rset(A,math.floor(rget(B)/rget(C)))
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
        elseif op==30 then if A>0 then close_upvalues(A-1) end; pc=pc+sBx
        elseif op==31 then if (rget(B)==rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==32 then if (rget(B)<rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==33 then if (rget(B)<=rget(C))~=(A~=0) then pc=pc+1 end
        elseif op==34 then if (not not rget(A))~=(C~=0) then pc=pc+1 end
        elseif op==35 then
            if (not not rget(B))==(C~=0) then rset(A,rget(B)) else pc=pc+1 end

        elseif op==36 then
            local fn=rget(A); local ca
            if B==0 then ca=_collect_values(A+1)
            else ca=_collect_values(A+1,B-1) end
            local ca_n=ca.n
            local vm=_VF[fn];local res
            if vm and _source_parents then
                local parents={upvals.environment}
                for i=1,#(_source_parents or {}) do parents[#parents+1]=_source_parents[i] end
                local w=_EX[vm[1].vm_id+1](vm[1],vm[2],_pack_values(_unpack_values(ca,1,ca_n)),nil,parents)
                res=w.r;res.n=w.n
            else res=_pack_values(_source_call(fn,upvals,_source_parents,_unpack_values(ca,1,ca_n))) end
            if C==0 then
                _store_values(A,res,res.n); top=A+res.n-1
            elseif C>1 then
                _store_values(A,res,C-1)
            end

        elseif op==37 then
            close_upvalues(0)
            local fn=rget(A); local ca
            if B==0 then ca=_collect_values(A+1)
            else ca=_collect_values(A+1,B-1) end
            local ca_n=ca.n
            --<<VM_TAIL_DISPATCH>>
            local vm=_VF[fn];local res
            if vm and _source_parents then
                local w=_EX[vm[1].vm_id+1](vm[1],vm[2],_pack_values(_unpack_values(ca,1,ca_n)),nil,_source_parents)
                res=w.r;res.n=w.n
            else res=_pack_values(_source_call(fn,upvals,_source_parents,_unpack_values(ca,1,ca_n))) end
            --<<ENDVM_TAIL_DISPATCH>>
            return {r=res, n=res.n}

        elseif op==38 then
            close_upvalues(0)
            if B==1 then return {r={},n=0}
            elseif B==0 then
                local n=top-A+1; local r=_collect_values(A,n)
                return {r=r,n=n}
            else
                local n=B-1; local r=_collect_values(A,n)
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
            local res=_pack_values(rget(A)(rget(A+1),rget(A+2)))
            _store_values(A+3,res,C)

        elseif op==42 then
            if rget(A+1)~=nil then rset(A,rget(A+1)); pc=pc+sBx end

        elseif op==43 then
            if C==0 then
                local ei=_ixor(code[pc],_ksm(pc)); pc=pc+1
                C=_c_or(_c_or(_c_shl(_ifield48(ei,_SH_A,256),18),_c_shl(_ifield48(ei,_SH_B,512),9)),_ifield48(ei,_SH_C,512))
            end
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
                _store_values(A,_va,n); top=A+n-1
            else
                _store_values(A,_va,B-1)
            end

        elseif op==46 then error("unexpected EXTRAARG")
        elseif op==47 then rset(A,kval(consts[Bx+1],proto))
        elseif op==48 then rset(A,_c_u32(_IT.script))
        elseif op==49 then rset(A,_c_u32(_IT.vmc))
        elseif op==50 then rset(A,_c_u32(_IT.layout))
        elseif op==51 then rset(A,_c_u32(_IT.seed))
        elseif op==52 then rset(A,_c_u32(proto.vm_id))
        elseif op==53 then rset(A,_c_u32(#proto.code))
        elseif op==54 then rset(A,_integrity_xor((rget(B) or 0),(rget(C) or 0)))
        elseif op==55 then rset(A,_c_u32((rget(B) or 0)+(rget(C) or 0)))
        elseif op==56 then rset(A,_c_u32((rget(B) or 0)*_c_or(rget(C) or 0,1)))
        elseif op==57 then rset(A,consts[Bx+1][2])
        elseif op==58 then pc=_poly_route(_brd[A+1])
        elseif op==59 then pc=Bx+1
        elseif op==60 then rset(A,get_environment(upvals)[kval(consts[Bx+1],proto)])
        elseif op==61 then get_environment(upvals)[kval(consts[Bx+1],proto)]=rget(A)
        elseif op==62 then
            local n=_acount(_va);local t={n=_source_value(n)}
            for i=1,n do t[i]=_aget(_va,i) end;rset(A,t)
        else error("unknown op "..op) end
    end
    return {r={},n=0}
end
--<<ENDTARGET_CLASSIC_EXEC_NATIVE>>
--<<ENDEXEC>>
_EX={exec}
