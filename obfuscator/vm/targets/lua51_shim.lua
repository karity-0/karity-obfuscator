-- The caller supplies the exact-integer module as I and dump normalizer as N.
local T={}
local native_type,native_tostring,native_tonumber=type,tostring,tonumber
local function numeric(x) return I.isint(x) and I.number(x) or x end
local literals={}
T.integer=function(text)
    local value=literals[text]
    if not value then value=I.parse(text);literals[text]=value end
    return value
end
T.integer_number=I.from
T.number=numeric
local keys=setmetatable({}, {__mode="v"})
function T.key(x)
    if not I.isint(x) then return x end
    if (x.hi<2097152) or (x.hi>=4292870144) then return I.number(x) end
    local key=I.text(x)
    if not keys[key] then keys[key]=x end
    return keys[key]
end
function T.add(a,b) if I.isint(a) and I.isint(b) then return I.add(a,b) end;return numeric(a)+numeric(b) end
function T.sub(a,b) if I.isint(a) and I.isint(b) then return I.sub(a,b) end;return numeric(a)-numeric(b) end
function T.mul(a,b) if I.isint(a) and I.isint(b) then return I.mul(a,b) end;return numeric(a)*numeric(b) end
function T.neg(a) if I.isint(a) then return I.neg(a) end;return -a end
function T.div(a,b) return numeric(a)/numeric(b) end
function T.pow(a,b) return numeric(a)^numeric(b) end
function T.idiv(a,b)
    if I.isint(a) and I.isint(b) then local q=I.divmod(a,b);return q end
    return math.floor(numeric(a)/numeric(b))
end
function T.mod(a,b)
    if I.isint(a) and I.isint(b) then local _,r=I.divmod(a,b);return r end
    return numeric(a)%numeric(b)
end
T.band,T.bor,T.bxor,T.bnot,T.shl,T.shr=I.band,I.bor,I.bxor,I.bnot,I.shl,I.shr
local function integer_float_order(a,b)
    if b~=b then return nil end
    if b>=9223372036854775808 then return -1 end
    if b< -9223372036854775808 then return 1 end
    local whole=math.floor(b)
    local value=I.from(whole)
    if I.lt(a,value) then return -1 end
    if not I.eq(a,value) then return 1 end
    return b==whole and 0 or -1
end
function T.eq(a,b)
    if I.isint(a) and I.isint(b) then return I.eq(a,b) end
    if I.isint(a) then return native_type(b)=="number" and integer_float_order(a,b)==0 end
    if I.isint(b) then return T.eq(b,a) end
    return a==b
end
function T.lt(a,b)
    if I.isint(a) and I.isint(b) then return I.lt(a,b) end
    if I.isint(a) and native_type(b)=="number" then local order=integer_float_order(a,b);return order~=nil and order<0 end
    if I.isint(b) and native_type(a)=="number" then local order=integer_float_order(b,a);return order~=nil and order>0 end
    return numeric(a)<numeric(b)
end
function T.le(a,b) return T.lt(a,b) or T.eq(a,b) end
function T.gt(a,b) return T.lt(b,a) end
function T.ge(a,b) return T.le(b,a) end
function T.ne(a,b) return not T.eq(a,b) end
function T.concat(a,b) return (I.isint(a) and I.text(a) or a)..(I.isint(b) and I.text(b) or b) end
function T.type(x) return I.isint(x) and "number" or native_type(x) end
function T.tostring(x) return I.isint(x) and I.text(x) or native_tostring(x) end
function T.tonumber(x,base)
    if I.isint(x) then return x end
    if native_type(x)=="string" and not base and (x:match("^%-?%d+$") or x:match("^%-?0[xX][%da-fA-F]+$")) then return I.parse(x) end
    return native_tonumber(x,numeric(base))
end
local native_unpack=unpack
local function args(...) return {n=select('#',...),...} end
local function call_numeric(fn,...)
    local values=args(...)
    for i=1,values.n do values[i]=numeric(values[i]) end
    return fn(native_unpack(values,1,values.n))
end
local function integer_result(fn,...)
    local values=args(call_numeric(fn,...))
    for i=1,values.n do if native_type(values[i])=="number" then values[i]=I.from(values[i]) end end
    return native_unpack(values,1,values.n)
end
T.math={}
for key,value in pairs(math) do
    if native_type(value)=="function" then T.math[key]=function(...) return call_numeric(value,...) end
    else T.math[key]=value end
end
T.math.type=function(x) return I.isint(x) and "integer" or native_type(x)=="number" and "float" or nil end
T.math.tointeger=function(x)
    if I.isint(x) then return x end
    if native_type(x)=="number" and x==math.floor(x) and x>=-9223372036854775808 and x<9223372036854775808 then return I.from(x) end
end
for _,name in ipairs({'floor','ceil'}) do
    local fn=math[name]
    T.math[name]=function(x)
        if I.isint(x) then return x end
        local value=fn(x)
        return T.math.tointeger(value) or value
    end
end
T.math.abs=function(x) if I.isint(x) then return x.hi>=2147483648 and I.neg(x) or x end;return math.abs(x) end
T.math.max=function(...)
    local values=args(...);local best=values[1]
    for i=2,values.n do if T.lt(best,values[i]) then best=values[i] end end
    return best
end
T.math.min=function(...)
    local values=args(...);local best=values[1]
    for i=2,values.n do if T.lt(values[i],best) then best=values[i] end end
    return best
end
T.math.maxinteger=I.parse('9223372036854775807')
T.math.mininteger=I.parse('-9223372036854775808')
T.string={}
for key,value in pairs(string) do
    if native_type(value)=="function" then T.string[key]=function(...) return call_numeric(value,...) end
    else T.string[key]=value end
end
T.string.dump=function(fn,strip)
    local raw=string.dump(fn)
    return strip and N(raw) or raw
end
for _,name in ipairs({'byte','len','find'}) do
    local fn=string[name]
    T.string[name]=function(...) return integer_result(fn,...) end
end
T.string.format=function(format,...)
    local values=args(...)
    if values.n==1 and I.isint(values[1]) then
        local value=values[1]
        if format=='%016x' then return string.format('%08x',value.hi)..string.format('%08x',value.lo) end
        if format=='%08x' and value.hi~=0 then return string.format('%x',value.hi)..string.format('%08x',value.lo) end
        if format=='%d' or format=='%s' then return I.text(value) end
    end
    return call_numeric(string.format,format,...)
end
local function bytes32(value)
    local out={}
    for i=1,4 do out[i]=string.char(value%256);value=math.floor(value/256) end
    return table.concat(out)
end
function T.string.pack(format,value)
    if format=='<I8' or format=='<i8' then local x=I.from(value);return bytes32(x.lo)..bytes32(x.hi) end
    if format~='<d' then error('unsupported target pack format: '..format,0) end
    value=numeric(value)
    local sign=(value<0 or (value==0 and 1/value<0)) and 2147483648 or 0
    value=math.abs(value)
    local exponent,fraction=0,0
    if value~=value then exponent=2047;fraction=2251799813685248
    elseif value==math.huge then exponent=2047
    elseif value~=0 then
        local mantissa,power=math.frexp(value)
        exponent=power+1022
        if exponent<=0 then exponent=0;fraction=math.ldexp(value,1074)
        else fraction=(mantissa*2-1)*4503599627370496 end
    end
    return bytes32(fraction%4294967296)..bytes32(sign+exponent*1048576+math.floor(fraction/4294967296))
end
function T.string.unpack(format,data,position)
    position=numeric(position or 1)
    local lo,hi=0,0
    for i=3,0,-1 do lo=lo*256+string.byte(data,position+i);hi=hi*256+string.byte(data,position+4+i) end
    local next_position=I.from(position+8)
    if format=='<I8' or format=='<i8' then return I.make(hi,lo),next_position end
    if format~='<d' then error('unsupported target unpack format: '..format,0) end
    local sign=hi>=2147483648 and -1 or 1
    local exponent=math.floor(hi/1048576)%2048
    local fraction=(hi%1048576)*4294967296+lo
    local value
    if exponent==2047 then value=fraction==0 and math.huge or 0/0
    elseif exponent==0 then value=math.ldexp(fraction,-1074)
    else value=math.ldexp(1+fraction/4503599627370496,exponent-1023) end
    return sign*value,next_position
end
T.table={}
for key,value in pairs(table) do T.table[key]=value end
T.table.pack=function(...) return {n=I.from(select('#',...)),...} end
T.table.unpack=function(t,i,j) return native_unpack(t,numeric(i or 1),numeric(j or #t)) end
T.table.insert=function(t,a,b)
    if b==nil then return table.insert(t,a) end
    return table.insert(t,numeric(a),b)
end
T.table.remove=function(t,i) return table.remove(t,numeric(i or #t)) end
T.table.concat=function(t,sep,i,j)
    local values={}
    for index=numeric(i or 1),numeric(j or #t) do
        local value=t[index];values[#values+1]=I.isint(value) and I.text(value) or value
    end
    return table.concat(values,sep)
end
T.select=function(index,...)
    if index=='#' then return I.from(select('#',...)) end
    return select(numeric(index),...)
end
T.rawget=function(t,key) return rawget(t,T.key(key)) end
T.rawset=function(t,key,value) return rawset(t,T.key(key),value) end
T.error=function(value,level) local depth=numeric(level or 1);return error(value,depth==0 and 0 or depth+1) end
T.len=function(value) return I.from(#value) end
local native_getfenv,native_setfenv=getfenv,setfenv
T.invoke=function(fn,environment,...)
    if fn~=native_getfenv and fn~=native_setfenv then return fn(...) end
    local subject,value=...
    local level=subject==nil and 1 or native_tonumber(subject)
    if level then level=level<0 and math.ceil(level) or math.floor(level) end
    if fn==native_getfenv and level==1 then return native_getfenv(environment) end
    if fn==native_setfenv and level==1 then return native_setfenv(environment,value) end
    return fn(...)
end
-- Preserve the native dependency checked by the generated integrity probes.
-- Only wrappers created in this lexical scope are registered.
local dependencies={}
for _,pair in ipairs({{T.math,math},{T.string,string},{T.table,table},{T,_G}}) do
    for name,wrapper in pairs(pair[1]) do
        local original=pair[2][name]
        if native_type(wrapper)=="function" and native_type(original)=="function" then
            dependencies[wrapper]=original
        end
    end
end
dependencies[T.table.unpack]=unpack
dependencies[T.table.pack]=select
T.debug={}
for name,value in pairs(debug) do T.debug[name]=value end
T.debug.getinfo=function(subject,options)
    if native_type(subject)=="function" then return debug.getinfo(dependencies[subject] or subject,options) end
    return debug.getinfo(numeric(subject)+1,options)
end
dependencies[T.debug.getinfo]=debug.getinfo
T.getfenv=function(subject)
    subject=numeric(subject or 1)
    if native_type(subject)=="number" and subject>0 then subject=subject+1 end
    return getfenv(subject)
end
return T
