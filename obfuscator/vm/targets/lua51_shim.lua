-- The caller supplies the exact-integer module as I.
local T={}
local native_type=type
local function numeric(x) return I.isint(x) and I.number(x) or x end
local literals={}
T.integer=function(text)
    local value=literals[text]
    if not value then value=I.parse(text);literals[text]=value end
    return value
end
T.number=numeric
local keys=setmetatable({}, {__mode="v"})
function T.key(x)
    if not I.isint(x) then return x end
    if (x.hi<2097152) or (x.hi>=4292870144) then return I.number(x) end
    local key=I.text(x)
    if not keys[key] then keys[key]=x end
    return keys[key]
end
function T.add(a,b) if I.isint(a) or I.isint(b) then return I.add(a,b) end;return a+b end
function T.sub(a,b) if I.isint(a) or I.isint(b) then return I.sub(a,b) end;return a-b end
function T.mul(a,b) if I.isint(a) or I.isint(b) then return I.mul(a,b) end;return a*b end
function T.neg(a) if I.isint(a) then return I.neg(a) end;return -a end
function T.idiv(a,b)
    if I.isint(a) and I.isint(b) then local q=I.divmod(a,b);return q end
    return math.floor(numeric(a)/numeric(b))
end
function T.mod(a,b)
    if I.isint(a) and I.isint(b) then local _,r=I.divmod(a,b);return r end
    return numeric(a)%numeric(b)
end
local U32=4294967296
local function bit32(a,b,mode)
    a,b=a%U32,b%U32
    local value,p=0,1
    for _=1,32 do
        local x,y=a%2,b%2
        if (mode==1 and x==1 and y==1) or
           (mode==2 and x~=y) or (mode==3 and (x==1 or y==1)) then
            value=value+p
        end
        a=(a-x)/2;b=(b-y)/2;p=p*2
    end
    return value
end
function T.band(a,b)
    if I.isint(a) or I.isint(b) then return I.band(a,b) end
    return bit32(a,b,1)
end
function T.bxor(a,b)
    if I.isint(a) or I.isint(b) then return I.bxor(a,b) end
    return bit32(a,b,2)
end
function T.bor(a,b)
    if I.isint(a) or I.isint(b) then return I.bor(a,b) end
    return bit32(a,b,3)
end
function T.bnot(a)
    if I.isint(a) then return I.bnot(a) end
    return U32-1-(a%U32)
end
local shl32,shr32
shl32=function(a,n)
    n=numeric(n)
    if n<0 then return shr32(a,-n) end
    if n>=32 then return 0 end
    return ((a%U32)*2^n)%U32
end
shr32=function(a,n)
    n=numeric(n)
    if n<0 then return shl32(a,-n) end
    if n>=32 then return 0 end
    return math.floor((a%U32)/2^n)
end
function T.shl(a,n)
    if I.isint(a) or I.isint(n) then return I.shl(a,n) end
    return shl32(a,n)
end
function T.shr(a,n)
    if I.isint(a) or I.isint(n) then return I.shr(a,n) end
    return shr32(a,n)
end
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
return T
