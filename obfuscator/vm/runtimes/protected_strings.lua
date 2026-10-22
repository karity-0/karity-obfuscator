-- This factory uses portable exact arithmetic on Lua 5.1 and 5.3.
--<<SECURITY_VALUES>>
_PS=(function()
    local S={api={byte=string.byte,char=string.char,sub=string.sub,concat=table.concat,
        info=debug.getinfo,hook=debug.gethook,dump=string.dump,format=string.format,
        match=string.match,len=string.len,unpack=__PS_UNPACK__,select=select,
        type=type,rawget=rawget,rawequal=rawequal,error=error,floor=math.floor,tonumber=tonumber,
        tostring=tostring,getmetatable=getmetatable,max=math.max,min=math.min}}
    local A=S.api
    local counter,ticks,failed=0,0,false
    local raw,throw,hook0,kind,next0,same=A.rawget,A.error,A.hook,A.type,next,A.rawequal
    local trusted={}
    local M=2147483647
    local objects=setmetatable({},{__mode='k'})
    local cells=setmetatable({},{__mode='k'})
    local bindings=__PS_BINDINGS__
    local function fail()
        failed=true
        throw(nil,0)
    end
    --<<SHARED_HOST_GUARD>>
    function S.watched(t,k)
        for i=1,#bindings do local b=bindings[i]
            if same(b[1],t) and same(b[2],k) then return true end
        end
        return false
    end
    function S.write(t,k,v)
        if _ENV_REFRESH then _ENV_REFRESH(t,false) end
        t[k]=v
        if _ENV_REFRESH then _ENV_REFRESH(t,true) end
        for i=1,#bindings do local b=bindings[i]
            if same(b[1],t) and same(b[2],k) then b[3]=t[k] end
        end
    end
    local function key(seed)
        return (seed+(_IT.script or 0)%M+((_IT.line or 0)%M)*17)%(M-1)+1
    end
    local function tag(data,seed)
        local h=(key(seed)+#data)%M
        for i=1,#data do
            local b=data[i]
            if A.type(b)~='number' or b<0 or b>255 or b%1~=0 then fail() end
            h=(_ixor(h,b)*65599)%M
        end
        return h
    end
    function S.is(v) return A.type(v)=='table' and objects[v]~=nil end
    local function checked(v)
        local r=objects[v]
        if not r or A.type(r[1])~='number' or A.type(r[2])~='table' or r[3]~=tag(r[2],r[1]) then fail() end
        return r
    end
    function S.check(v) if S.is(v) then checked(v) end;return v end
    local function new(n,get)
        counter=(counter+1)%(M-1)
        local seed=(counter*65537+(_IT.seed or 0)*257)% (M-1)+1
        local state=key(seed)
        local data={}
        for i=1,n do
            state=state*48271%M
            data[i]=(get(i)+state%251+1)%256
        end
        local v={}
        objects[v]={seed,data,tag(data,seed)}
        return v
    end
    local function bytes(v)
        if not S.is(v) then
            if A.type(v)~='string' then return nil end
            return #v,function(i) return A.byte(v,i) end
        end
        local r=checked(v)
        local state=key(r[1]);local position=0
        return #r[2],function(i)
            if i<=position then state=key(r[1]);position=0 end
            while position<i do state=state*48271%M;position=position+1 end
            return (r[2][i]-state%251-1)%256
        end
    end
    function S.seal(v)
        if S.is(v) then return S.check(v) end
        if A.type(v)~='string' then return v end
        return new(#v,function(i) return A.byte(v,i) end)
    end
    function S.constant(k)
        if k[3] then
            if not S.is(k[3]) then fail() end
            if cells[k] then return S.cell_get(k,k[3]) end
            return S.cell_set(k,k[3])
        end
        local envelope=_kss(k[2])
        if #envelope<8 then fail() end
        local function u32(offset)
            local a,b,c,d=A.byte(envelope,offset,offset+3)
            return a+b*256+c*65536+d*16777216
        end
        local seed,expected=u32(1),u32(5)
        if seed<=0 or seed>=M then fail() end
        local state=key(seed)
        local h=(state+#envelope-8)%M
        for i=9,#envelope do h=(_ixor(h,A.byte(envelope,i))*65599)%M end
        if h~=expected then fail() end
        local value=new(#envelope-8,function(i)
            state=state*48271%M
            return (A.byte(envelope,i+8)-state%251-1)%256
        end)
        k[3]=S.cell_set(k,value)
        return value
    end
    function S.open(v)
        if not S.is(v) then return v end
        local n,get=bytes(v)
        local out,chunks={},{}
        for i=1,n do
            out[#out+1]=A.char(get(i))
            if #out==4096 then chunks[#chunks+1]=A.concat(out);out={} end
        end
        if #out>0 then chunks[#chunks+1]=A.concat(out) end
        return A.concat(chunks)
    end
    function S.equal(a,b)
        local n,ga=bytes(a);local m,gb=bytes(b)
        if not n or not m then return false end
        if n~=m then return false end
        local difference=0
        for i=1,n do
            local delta=ga(i)-gb(i)
            difference=difference+delta*delta
        end
        return difference==0
    end
    function S.eq(a,b)
        if S.is(a) or S.is(b) then return S.equal(a,b) end
        return a==b
    end
    function S.lt(a,b) return S.open(a)<S.open(b) end
    function S.le(a,b) return S.open(a)<=S.open(b) end
    function S.length(v) local n=bytes(v);return n end
    function S.join(values,n,separator)
        if separator==nil then separator='' end
        local sn,sg=bytes(separator)
        if not sn then return nil end
        local parts,total={},0
        for i=1,n do
            local len,get=bytes(values[i])
            if not len then return nil end
            if i>1 and sn>0 then parts[#parts+1]={sn,sg};total=total+sn end
            parts[#parts+1]={len,get};total=total+len
        end
        local p,offset=1,0
        return new(total,function()
            while parts[p] and offset==parts[p][1] do p=p+1;offset=0 end
            offset=offset+1
            return parts[p][2](offset)
        end)
    end
    function S.cell_set(box,v)
        v=S.seal(v)
        cells[box]=S.is(v) and v or nil
        return v
    end
    function S.cell_get(box,v)
        local expected=cells[box]
        if expected and not same(expected,v) then fail() end
        return S.check(v)
    end
    function S.native(fn,args,count,get,length)
        if fn==A.concat and A.type(args[1])=='table' and not S.is(args[1]) and count<=4 then
            local t=args[1]
            -- Metamethod-bearing native tables retain Lua's own evaluation.
            if A.getmetatable(t)~=nil then return false end
            local first,last=args[3],args[4]
            if first==nil then first=1 end
            if last==nil then last=length(t) end
            if A.type(first)~='number' or A.type(last)~='number' or first%1~=0 or last%1~=0 then return false end
            local values={}
            for i=first,last do values[#values+1]=get(t,i) end
            local out=S.join(values,A.max(0,last-first+1),args[2])
            if out then return true,out end
        elseif fn==A.char then
            for i=1,count do
                local b=args[i]
                if A.type(b)~='number' or b<0 or b>255 or b%1~=0 then return false end
            end
            return true,new(count,function(i) return args[i] end)
        elseif fn==A.len and count==1 and S.is(args[1]) then
            return true,S.length(args[1])
        elseif fn==A.sub and S.is(args[1]) and count>=2 and count<=3 then
            local n,getbyte=bytes(args[1])
            local first,last=args[2],args[3]
            if last==nil then last=-1 end
            if A.type(first)~='number' or A.type(last)~='number' or first%1~=0 or last%1~=0 then return false end
            if first<0 then first=n+first+1 end
            if last<0 then last=n+last+1 end
            first=A.max(first,1);last=A.min(last,n)
            return true,new(A.max(0,last-first+1),function(i) return getbyte(first+i-1) end)
        end
        return false
    end
    -- Validate mutable dispatch tables through immutable captured primitives.
    -- Entry points hold guard itself in a lexical binding, not a table slot.
    for name,value in next0,S do
        if kind(value)=='function' then trusted[#trusted+1]={S,name,value} end
    end
    for name,value in next0,A do
        if kind(value)=='function' then trusted[#trusted+1]={A,name,value} end
    end
    if _PS_CORE then
        for name,value in next0,_PS_CORE do
            trusted[#trusted+1]={_PS_CORE,name,value}
        end
    end
    trusted[#trusted+1]={S,'api',A}
    return S
end)()
_PS_GUARD=_PS.guard
--<<ENDSECURITY_VALUES>>
