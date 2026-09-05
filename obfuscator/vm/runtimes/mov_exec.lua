-- MOV runtime fragments. Host Lua handlers are wired by mov/builder.py.
--<<SHARED>>
local _mov_kits
local _mov_closures=setmetatable({},{__mode="k"})
local function _mov_uint(r)
    local __VM_HOT_LOOP__=true
    local value,shift=0,0
    for i=1,5 do
        local b=r.u8()
        if i==5 and b>15 then error("MOV field overflow") end
        value=value|((b&127)<<shift)
        if b<128 then return value end
        shift=shift+7
    end
    error("invalid MOV field")
end
local function _mov_read(r, root)
    assert(r.u8()==77 and r.u8()==79 and r.u8()==86 and r.u8()==4,"bad MOV version")
    _mov_kits={}
    for vm=1,r.u16() do
        local kit={banks={},encode={},decode={},nonzero={}}
        _mov_kits[vm]=kit
        for i=0,15 do
            local digit=r.u8()
            assert(digit<16 and kit.decode[digit]==nil,"bad MOV alphabet")
            kit.encode[i]=digit; kit.decode[digit]=i; kit.nonzero[digit]=i~=0
        end
        for k=1,r.u8() do
            local count=r.u8()
            local bank={}; kit.banks[k]=bank
            for x=0,15 do
                local ys={}; bank[x]=ys
                for y=0,15 do
                    local states={}; ys[y]=states
                    for c=0,count-1 do states[c]={r.u8(),r.u8()} end
                end
            end
        end
        kit.tape={}
        for i=1,r.u32() do
            kit.tape[i]={r.u16(),_mov_uint(r),_mov_uint(r),_mov_uint(r),_mov_uint(r),_mov_uint(r)}
        end
    end
    local remaining=r.u32()
    local function attach(p)
        remaining=remaining-1
        assert(r.u16()==p.vm_id and _mov_kits[p.vm_id+1],"bad MOV VM assignment")
        local ne=r.u32()
        assert(ne==#p.code+1,"bad MOV entry count")
        local entries={}
        for i=1,ne do entries[i]=_mov_uint(r) end
        p.mov_entries=entries
        for _,sub in ipairs(p.protos) do attach(sub) end
    end
    attach(root)
    assert(remaining==0,"bad MOV prototype count")
end
--<<REGISTERS>>
    -- Native values and encoded integer digits live in separate slot banks.
    local _mkit=_mov_kits[proto.vm_id+1]
    local _mov_banks=_mkit.banks
    local _mencode,_mdecode=_mkit.encode,_mkit.decode
    local _mdigits={}
    local function rget(i)
        local d=_mdigits[i]
        if d then
            if regs[i]~=nil then return regs[i] end
            local v=0
            for j=15,0,-1 do v=(v<<4)|_mdecode[d[j]] end
            regs[i]=v
            return v
        end
        return regs[i]
    end
    local function rset(i,v)
        _mdigits[i]=nil; regs[i]=v
    end
    local function _mov_digits(i)
        local d=_mdigits[i]
        if d then return d end
        local v=regs[i]
        if math.type(v)~="integer" then return nil end
        d={}
        for j=0,15 do d[j]=_mencode[(v>>(j*4))&15] end
        _mdigits[i]=d
        return d
    end
    local function _mov_copy(a,b)
        regs[a]=regs[b]; _mdigits[a]=_mdigits[b]
    end
    local function _mov_close(first)
        for slot,box in pairs(boxes) do
            if slot>=first then
                box.v=rget(slot); box.get=nil; box.set=nil; boxes[slot]=nil
            end
        end
    end
--<<FRAME>>
    local _mentry=proto.mov_entries
    local _mtape=_mkit.tape
    local _mp=_mentry[1]
    local _ms={[1]=0,[17]=1,[18]=2,[21]=_mencode[0],
               [24]=_mov_banks[8],[25]=_mov_banks[1],
               [27]=_mkit.nonzero,[28]=_mencode,[29]=_mdecode,[30]=true}
    for i=0,15 do _ms[32+i]=i end
    local _mzero,_mones={},{}
    for i=0,15 do _mzero[i]=_mencode[0]; _mones[i]=_mencode[15] end
    local _mbank={[13]=1,[14]=2,[15]=8,[20]=3,[21]=4,[22]=5,[23]=9,[24]=10,[25]=2,[26]=5,
                  [31]=6,[32]=6,[33]=6}
    local _mtruth={
        [31]={[0]=true,[1]=false,[2]=false},
        [32]={[0]=false,[1]=true,[2]=false},
        [33]={[0]=true,[1]=true,[2]=false},
    }
    local _ma,_mresume
    local _mselect={}
--<<LOOP>>
    for i in setmetatable({},{__call=function(t)return t end}) do
        local q=_mtape[_mp]; _mp=_mp+1
        local kind=q[1]
        if kind==__MOV_MOVE__ then
            _ms[q[2]]=_ms[q[3]]
        elseif kind==__MOV_LOOKUP__ then
            _ms[q[2]]=_ms[q[3]][_ms[q[4]]]
        elseif kind==__MOV_SELECT__ then
            _mselect[true]=q[3]; _mselect[false]=q[4]
            local target=_mselect[_ms[q[2]]]
            if q[6]==1 then target=_ms[target] end
            _mp=target
        elseif kind==__MOV_HOST__ and q[2]==1 then
            local ip=q[3]
            local op,A,B,C=decode(code[ip],_ksm(ip))
            _ma=A; _mresume=_mentry[ip+1]
            local x,y
            if op==25 then x=_mzero; y=_mov_digits(B)
            elseif op==26 then x=_mov_digits(B); y=_mones
            else x=_mov_digits(B); y=_mov_digits(C) end
            _ms[11]=x~=nil and y~=nil
            if _ms[11] then
                _ms[2]=x; _ms[3]=y; _ms[4]=0; _ms[5]=_mov_banks[_mbank[op]]
                _ms[16]=_mov_banks[7]; _ms[15]=_mtruth[op]
                if op==23 or op==24 then
                    -- Shift magnitude changes addressing only. Nibble values
                    -- are combined exclusively by the shift lookup recipe.
                    local count=rget(C)
                    if count>=64 or count<=-64 then
                        _ms[2]=_mzero; _ms[3]=_mzero
                    else
                        local left=op==23
                        if count<0 then count=-count; left=not left end
                        local whole=count//4
                        local a,b={},{}
                        for j=0,15 do
                            local index=left and (j-whole) or (j+whole)
                            local neighbor=left and (index-1) or (index+1)
                            a[j]=x[index] or _mencode[0]
                            b[j]=x[neighbor] or _mencode[0]
                        end
                        _ms[2]=a; _ms[3]=b; _ms[4]=count%4
                        _ms[5]=_mov_banks[left and 9 or 10]
                    end
                elseif op>=31 then
                    local nextpc=ip+1
                    _ms[19]=_mentry[({[true]=nextpc,[false]=nextpc+1})[A~=0]]
                    _ms[20]=_mentry[({[false]=nextpc,[true]=nextpc+1})[A~=0]]
                end
            end
        elseif kind==__MOV_HOST__ and q[2]==2 then
            local d={}
            for j=0,15 do d[j]=_ms[64+j] end
            _mdigits[_ma]=d; regs[_ma]=nil
            _mp=_mresume
        elseif kind==__MOV_HOST__ and q[2]==3 then
            local ip=q[3]
            local op,A,B=decode(code[ip],_ksm(ip))
            _mov_copy(A,B); _mp=_mentry[ip+1]
        elseif kind==__MOV_HOST__ and q[2]==4 then
            local ip=q[3]
            local op,A,B,C=decode(code[ip],_ksm(ip))
            local value
            if op==34 then value=rget(A) else value=rget(B) end
            _ms[11]=(not not value)==(C~=0)
            if op==35 and _ms[11] then _mov_copy(A,B) end
            _ms[19]=_mentry[ip+1]; _ms[20]=_mentry[ip+2]
        elseif kind==__MOV_HOST__ and q[2]==5 then
            local op,A=decode(code[q[3]],_ksm(q[3]))
            _mov_close(A-1)
        elseif kind==__MOV_HOST__ and q[2]==0 then
            pc=q[3]
            if pc>#code then error("MOV instruction pointer out of range") end
            local _ip=pc; local op,A,B,C,Bx,sBx=decode(code[pc],_ksm(pc))
            local _av=nil; pc=pc+1; _route_step(_ip,op,A,B,C)
            --<<HOST_HANDLERS>>
            _mp=_mentry[pc]
        else error("bad MOV instruction") end
    end
--<<END>>
