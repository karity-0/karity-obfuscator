-- MOV runtime fragments. Host Lua handlers are wired by mov/builder.py.
--<<SHARED>>
local _mov_kits
local _mov_div_steps=__MOV_DIV_STEPS__
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
    assert(r.u8()==77 and r.u8()==79 and r.u8()==86 and r.u8()==11,"bad MOV version")
    _mov_kits={}
    for vm=1,r.u16() do
        local kit={banks={},encode={},decode={},nonzero={},sign={}}
        _mov_kits[vm]=kit
        for i=0,15 do
            local digit=r.u8()
            assert(digit<16 and kit.decode[digit]==nil,"bad MOV alphabet")
            kit.encode[i]=digit; kit.decode[digit]=i; kit.nonzero[digit]=i~=0
            kit.sign[digit]=i>=8
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
    local _mstrings={}
    local function rget(i)
        local node=_mstrings[i]
        if node then
            if regs[i]~=nil then return regs[i] end
            local bytes={}; local n=0
            while node[1] do
                n=n+1; bytes[n]=string.char(_mdecode[node[2]]|(_mdecode[node[3]]<<4))
                node=node[4]
            end
            regs[i]=table.concat(bytes)
            return regs[i]
        end
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
        _mdigits[i]=nil; _mstrings[i]=nil; regs[i]=v
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
        regs[a]=regs[b]; _mdigits[a]=_mdigits[b]; _mstrings[a]=_mstrings[b]
    end
    local function _mov_float_digits(v)
        local bits=string.unpack("<i8",string.pack("<d",v))
        local d={}
        for j=0,15 do d[j]=_mencode[(bits>>(j*4))&15] end
        return d
    end
    local function _mov_string_nodes(s)
        local node={false}
        for i=#s,1,-1 do
            local byte=string.byte(s,i)
            node={true,_mencode[byte&15],_mencode[byte>>4],node}
        end
        return node
    end
    local function _mov_is_string(i)
        return _mstrings[i]~=nil or type(regs[i])=="string"
    end
    local function _mov_string_copy(i)
        local node=_mstrings[i]
        if not node then return _mov_string_nodes(regs[i]) end
        local root={}; local tail=root
        while node[1] do
            local copy={true,node[2],node[3]}
            tail[4]=copy; tail=copy; node=node[4]
        end
        tail[4]={false}
        return root[4]
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
    _ms[162]=_mov_banks[2]; _ms[163]=false; _ms[164]=_mkit.sign
    _ms[165]=_mov_div_steps; _ms[173]=64
    _ms[168]={[false]={[false]=false,[true]=true},[true]={[false]=true,[true]=false}}
    _ms[172]={[0]=true,[1]=false}
    _ms[175]={[false]=true,[true]=false}
    _ms[321]={[0]=true,[1]=false,[2]=false}
    _ms[326]=_mencode[8]; _ms[327]=_mov_banks[5]
    --<<FLOAT_TABLES>>
    --<<MIXED_TABLES>>
    --<<SHIFT_TABLES>>
    local _mexpected={
        [0]={[false]=true,[true]=false},
        [1]={[false]=false,[true]=true},
    }
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
            if q[6]==1 then
                _ms[q[2]][_ms[q[3]]]=_ms[q[4]]
            else
                _ms[q[2]]=_ms[q[3]]
            end
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
            _ms[170]=op==16
            _ms[325]=false
            _ms[333]=op==23
            local x,y
            if op==28 then
                if _mov_is_string(B) then
                    x=_mstrings[B] or _mov_string_nodes(regs[B]); y=x
                end
            elseif op==29 then
                local strings=true
                for slot=B,C do if not _mov_is_string(slot) then strings=false; break end end
                if strings then
                    x={false}
                    for slot=C,B,-1 do x={true,_mov_string_copy(slot),x} end
                    y=x; _ms[322]={false}; _ms[324]={false}
                end
            elseif op==25 then
                x=_mzero; y=_mov_digits(B)
                if not y and math.type(rget(B))=="float" then
                    x=_mov_float_digits(rget(B)); y=x; _ms[325]=true
                end
            elseif op==26 then x=_mov_digits(B); y=_mones
            else x=_mov_digits(B); y=_mov_digits(C) end
            _ms[176]=false
            _ms[192]=false
            _ms[320]=false
            if op>=31 then
                local left,right=math.type(rget(B)),math.type(rget(C))
                if left and right then
                    _ms[198]=left=="float"; _ms[199]=right=="float"
                    if _ms[198] then x=_mov_float_digits(rget(B)) end
                    if _ms[199] then y=_mov_float_digits(rget(C)) end
                    _ms[176]=_ms[198] and _ms[199]
                    _ms[192]=_ms[198]~=_ms[199]
                elseif type(rget(B))=="string" and type(rget(C))=="string" then
                    local collate
                    if op~=31 and type(os)=="table" and type(os.setlocale)=="function" then
                        collate=os.setlocale(nil,"collate")
                    end
                    if op==31 or collate=="C" or collate=="POSIX" then
                        x=_mov_string_nodes(rget(B)); y=_mov_string_nodes(rget(C))
                        _ms[320]=true
                    end
                end
            end
            _ms[11]=x~=nil and y~=nil
            if _ms[11] then
                _ms[2]=x; _ms[3]=y; _ms[4]=0; _ms[5]=_mov_banks[_mbank[op]]
                _ms[16]=_mov_banks[7]; _ms[15]=_mtruth[op]
                if op>=31 then
                    local nextpc=ip+1
                    _ms[19]=_mentry[({[true]=nextpc,[false]=nextpc+1})[A~=0]]
                    _ms[20]=_mentry[({[false]=nextpc,[true]=nextpc+1})[A~=0]]
                end
            end
        elseif kind==__MOV_HOST__ and q[2]==2 then
            local d={}
            for j=0,15 do d[j]=_ms[64+j] end
            _mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil
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
            -- Classify the native value at the representation boundary.
            -- NOT and expected-truth comparison happen in lookup microcode.
            _ms[11]=value~=nil and value~=false
            _ms[174]=_mexpected[C]
            _ma=A; _mresume=_mentry[ip+1]
            _ms[19]=_mentry[ip+1]; _ms[20]=_mentry[ip+2]
        elseif kind==__MOV_HOST__ and q[2]==5 then
            local op,A=decode(code[q[3]],_ksm(q[3]))
            _mov_close(A-1)
        elseif kind==__MOV_HOST__ and q[2]==6 then
            if _ms[170] then error("attempt to perform 'n%0'") end
            error("attempt to divide by zero")
        elseif kind==__MOV_HOST__ and q[2]==7 then
            rset(_ma,_ms[11]); _mp=_mresume
        elseif kind==__MOV_HOST__ and q[2]==8 then
            _mstrings[_ma]=_ms[322][4]; _mdigits[_ma]=nil; regs[_ma]=nil
            _mp=_mresume
        elseif kind==__MOV_HOST__ and q[2]==9 then
            local bits=0
            for j=15,0,-1 do bits=(bits<<4)|_mdecode[_ms[64+j]] end
            rset(_ma,(string.unpack("<d",string.pack("<i8",bits))))
            _mp=_mresume
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
