local exec, _EX
local function _call_packet(packet,fn,...)
    for key in pairs(packet) do packet[key]=nil end
    return fn(...)
end
local function _invoke_closure(metadata,values)
    local w=_EX[metadata[1].vm_id+1](metadata[1],metadata[2],values,nil,nil)
    return table.unpack(w.r,1,w.n)
end
local _VF=setmetatable({},{__mode="kv"})
local _PN,_PE=0,0
--<<TARGET_PRIVATE_MIX>>
local function _pmix(x)
    x=(x~(x>>30))*-4658895280553007687
    x=(x~(x>>27))*-7723592293110705685
    return (x~(x>>31))&-1
end
--<<ENDTARGET_PRIVATE_MIX>>

local _for_api={tonumber,math.type,math.floor,math.ceil,math.tointeger,math.mininteger,math.maxinteger}
-- Match Lua 5.3 FORPREP, including integer-limit rounding and saturation.
local function _for_values(initial,limit,step)
    local bound=_for_api[1](limit)
    if _for_api[2](initial)=="integer" and _for_api[2](step)=="integer" and bound then
        local rounded=step<0 and _for_api[4](bound) or _for_api[3](bound)
        local integer=_for_api[5](rounded)
        if integer==nil then
            if bound>0 then
                integer=_for_api[7]
                if step<0 then initial=0 end
            else
                integer=_for_api[6]
                if step>=0 then initial=0 end
            end
        end
        return initial,integer,step
    end
    if bound==nil then error("'for' limit must be a number") end
    step=_for_api[1](step)
    if step==nil then error("'for' step must be a number") end
    initial=_for_api[1](initial)
    if initial==nil then error("'for' initial value must be a number") end
    return initial*1.0,bound*1.0,step*1.0
end

--<<EXEC>>
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
    local _open_values={}
    local _split_tmp
    local _S={[611]=(proto.vm_id~#code)&-1}
    local _MJ={}
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
    for key in pairs(args) do args[key]=nil end
    args=nil
    --<<ENDTARGET_USER_STATEMENT>>

    --<<RGET>>
    local function rget(i)
        local box=boxes[i]; if box then return box.v end
        return regs[i]
    end
    --<<ENDRGET>>
    --<<RSET>>
    local function rset(i,v)
        regs[i]=v
        local box=boxes[i]
        if box then box.v=v; regs[i]=nil end
    end
    --<<ENDRSET>>

    local function _open_get(i)
        if i<256 then return rget(i) end
        return _open_values[i]
    end
    local function _open_set(i,v)
        if i<256 then rset(i,v) else _open_values[i]=v end
    end

    local function _stack_trim(first)
        for i=first,math.min(255,math.max(proto.max_stack_size-1,top)) do
            if not boxes[i] then rset(i,nil) end
        end
        _split_tmp=nil
        for key in pairs(_open_values) do _open_values[key]=nil end
    end

    --<<TARGET_USER_STATEMENT>>
    local function _acount(q) return q and (q.n or #q) or 0 end
    local function _aget(q,i) if q then return q[i] end; return nil end
    local function _collect_values(first,count)
        if count==nil then count=top-first+1 end
        if count<0 then count=0 end
        local values={n=count}
        for i=1,count do values[i]=_open_get(first+i-1) end
        return values
    end
    local function _store_values(first,values,count)
        for i=1,count do _open_set(first+i-1,values[i]) end
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
        elseif tag==__VM_DATA_GET__ then return (--<<TARGET_USER_EXPRESSION>>
            x[y]
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif tag==__VM_DATA_SET__ then
            --<<TARGET_USER_STATEMENT>>
            x[y]=z
            --<<ENDTARGET_USER_STATEMENT>>
            return z
        elseif tag==__VM_CMP_EQ__ then return (--<<TARGET_USER_EXPRESSION>>
            x==y
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif tag==__VM_CMP_LT__ then return (--<<TARGET_USER_EXPRESSION>>
            x<y
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif tag==__VM_CMP_LE__ then return (--<<TARGET_USER_EXPRESSION>>
            x<=y
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif tag==__VM_CMP_TRUTH__ then return not not x
        elseif tag==__VM_OP_MOD__ then return (--<<TARGET_USER_EXPRESSION>>
            x%y
            --<<ENDTARGET_USER_EXPRESSION>>
        )
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
        if slot==__VM_SLOT_ADD__ then return (--<<TARGET_USER_EXPRESSION>>
            a+b
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif slot==__VM_SLOT_SUB__ then return (--<<TARGET_USER_EXPRESSION>>
            a-b
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif slot==__VM_SLOT_MUL__ then return (--<<TARGET_USER_EXPRESSION>>
            a*b
            --<<ENDTARGET_USER_EXPRESSION>>
        )
        elseif slot==__VM_SLOT_BAND__ then return a&b
        elseif slot==__VM_SLOT_BOR__ then return a|b
        elseif slot==__VM_SLOT_BXOR__ then return a~b
        elseif slot==__VM_SLOT_SHL__ then return a<<b
        elseif slot==__VM_SLOT_SHR__ then return a>>b end
        error("unknown arithmetic slot")
    end
    local function _arith1(a,av,slot)
        if slot==__VM_SLOT_UNM__ then return (--<<TARGET_USER_EXPRESSION>>
            -a
            --<<ENDTARGET_USER_EXPRESSION>>
        )
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

    --<<TARGET_USER_STATEMENT>>
    local function get_box(slot)
        if not boxes[slot] then
            -- A cell owns only its captured value, never the entire frame.
            boxes[slot]={v=rget(slot)}
            regs[slot]=nil
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
                boxes[slot]=nil
                rset(slot,value)
                box.get=nil; box.set=nil
                set_upvalue(box,value)
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
            return _invoke_closure(metadata,table.pack(...))
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
            _stack_trim(A)
            local vm=_VF[fn];local res
            if vm then
                local parents
                if _source_parents then
                    parents={upvals.environment}
                    for i=1,#_source_parents do parents[#parents+1]=_source_parents[i] end
                end
                local w=_EX[vm[1].vm_id+1](vm[1],vm[2],ca,nil,parents)
                res=w.r;res.n=w.n
            else res=table.pack(_call_packet(ca,fn,table.unpack(ca,1,ca_n))) end
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
            _stack_trim(A)
            --<<VM_TAIL_DISPATCH>>
            local vm=_VF[fn];local res
            if vm then
                local w=_EX[vm[1].vm_id+1](vm[1],vm[2],ca,nil,_source_parents)
                res=w.r;res.n=w.n
            else res=table.pack(_call_packet(ca,fn,table.unpack(ca,1,ca_n))) end
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

        elseif op==40 then
            local initial,limit,step=_for_values(rget(A),rget(A+1),rget(A+2))
            rset(A,initial-step); rset(A+1,limit); rset(A+2,step); pc=pc+sBx

        elseif op==41 then
            local res=table.pack(rget(A)(rget(A+1),rget(A+2)))
            _store_values(A+3,res,C)

        elseif op==42 then
            if rget(A+1)~=nil then rset(A,rget(A+1)); pc=pc+sBx end

        elseif op==43 then
            if C==0 then
                local ei=_ixor(code[pc],_ksm(pc)); pc=pc+1
                C=(((ei>>_SH_A)&0xFF)<<18)|(((ei>>_SH_B)&0x1FF)<<9)|((ei>>_SH_C)&0x1FF)
            end
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B
            local tbl=rget(A)
            for i=1,cnt do tbl[base+i]=_open_get(A+i) end

        elseif op==44 then
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
        elseif op==48 then rset(A,_IT.script&0xFFFFFFFF)
        elseif op==49 then rset(A,_IT.vmc&0xFFFFFFFF)
        elseif op==50 then rset(A,_IT.layout&0xFFFFFFFF)
        elseif op==51 then rset(A,_IT.seed&0xFFFFFFFF)
        elseif op==52 then rset(A,proto.vm_id&0xFFFFFFFF)
        elseif op==53 then rset(A,#proto.code&0xFFFFFFFF)
        elseif op==54 then rset(A,_integrity_xor((rget(B) or 0),(rget(C) or 0)))
        elseif op==55 then rset(A,((rget(B) or 0)+(rget(C) or 0))&0xFFFFFFFF)
        elseif op==56 then rset(A,((rget(B) or 0)*((rget(C) or 0)|1))&0xFFFFFFFF)
        elseif op==57 then rset(A,consts[Bx+1][2])
        elseif op==58 then pc=_poly_route(_brd[A+1])
        elseif op==59 then pc=Bx+1
        elseif op==60 then rset(A,get_environment(upvals)[kval(consts[Bx+1],proto)])
        elseif op==61 then get_environment(upvals)[kval(consts[Bx+1],proto)]=rget(A)
        elseif op==62 then
            local n=_acount(_va);local t={n=_source_value(n)}
            for i=1,n do t[i]=_aget(_va,i) end;rset(A,t)
        elseif op==63 then _IT.fail("VM execution failed",0)
        elseif op==64 then _IT.invalid=true; _IT.fail("VM execution failed",0)
        elseif op==65 then
            local condition=rget(A); _stack_trim(B)
            if not condition then _IT.fail("VM execution failed",0) end
            condition=nil
            if C==0 then top=B-1 else for i=B,B+C-2 do rset(i,nil) end end
        else error("unknown op "..op) end
    end
    return {r={},n=0}
end
--<<ENDEXEC>>
_EX={exec}
