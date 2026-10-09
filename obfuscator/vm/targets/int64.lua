-- Exact signed 64-bit arithmetic for targets without native integer operators.
-- This module is Lua 5.1 syntax. Limbs remain exact binary64 integers.
local floor,abs=math.floor,math.abs
local U32,U16=4294967296,65536
local M={}
local mt={}
local private_marker={}
local function make(hi,lo)
    return setmetatable({hi=hi%U32,lo=lo%U32},mt)
end
local function isint(x)
    return getmetatable(x)==mt or (type(x)=="table" and x._private_word==private_marker)
end
local function neg(x)
    local lo=(-x.lo)%U32
    return make(U32-1-x.hi+(lo==0 and 1 or 0),lo)
end
local function from(x)
    if isint(x) then return x end
    if type(x)~="number" or x~=floor(x) or x==math.huge or x==-math.huge then
        error("number has no integer representation",0)
    end
    if x<0 then return neg(from(-x)) end
    return make(floor(x/U32),x%U32)
end
local function add(a,b)
    a,b=from(a),from(b)
    local lo=a.lo+b.lo
    return make(a.hi+b.hi+floor(lo/U32),lo)
end
local function sub(a,b) return add(a,neg(from(b))) end
local function mul(a,b)
    a,b=from(a),from(b)
    local x={a.lo%U16,floor(a.lo/U16),a.hi%U16,floor(a.hi/U16)}
    local y={b.lo%U16,floor(b.lo/U16),b.hi%U16,floor(b.hi/U16)}
    local result,carry={},0
    for i=1,4 do
        local value=carry
        for j=1,i do value=value+x[j]*y[i-j+1] end
        result[i]=value%U16;carry=floor(value/U16)
    end
    return make(result[3]+result[4]*U16,result[1]+result[2]*U16)
end
local function unsigned_lt(a,b) return a.hi<b.hi or (a.hi==b.hi and a.lo<b.lo) end
local function eq(a,b) a,b=from(a),from(b);return a.hi==b.hi and a.lo==b.lo end
local function lt(a,b)
    a,b=from(a),from(b)
    local sa,sb=a.hi>=2147483648,b.hi>=2147483648
    if sa~=sb then return sa end
    return unsigned_lt(a,b)
end
local function number(a)
    if not isint(a) then return a end
    if a.hi>=2147483648 then local n=neg(a);return -(n.hi*U32+n.lo) end
    return a.hi*U32+a.lo
end
local bit_tables={}
for op=1,3 do
    local tab={}
    for a=0,15 do
        local row={};tab[a]=row
        for b=0,15 do
            local x,y,p,result=a,b,1,0
            for _=1,4 do
                local ax,by=x%2,y%2
                if (op==1 and ax==1 and by==1) or (op==2 and ax~=by) or (op==3 and (ax==1 or by==1)) then result=result+p end
                x=floor(x/2);y=floor(y/2);p=p*2
            end
            row[b]=result
        end
    end
    bit_tables[op]=tab
end
local function bit_limb(a,b,tab)
    local value,p=0,1
    for _=1,8 do
        value=value+tab[a%16][b%16]*p
        a=floor(a/16);b=floor(b/16);p=p*16
    end
    return value
end
local function bits(a,b,op)
    a,b=from(a),from(b)
    return make(bit_limb(a.hi,b.hi,bit_tables[op]),bit_limb(a.lo,b.lo,bit_tables[op]))
end
local shl,shr
shl=function(a,n)
    a=from(a);n=number(n)
    if n<0 then return shr(a,-n) end
    if n>=64 then return make(0,0) end
    if n==0 then return a end
    if n>=32 then return make((a.lo%2^(64-n))*2^(n-32),0) end
    return make((a.hi%2^(32-n))*2^n+floor(a.lo/2^(32-n)),(a.lo%2^(32-n))*2^n)
end
shr=function(a,n)
    a=from(a);n=number(n)
    if n<0 then return shl(a,-n) end
    if n>=64 then return make(0,0) end
    if n==0 then return a end
    if n>=32 then return make(0,floor(a.hi/2^(n-32))) end
    return make(floor(a.hi/2^n),floor(a.lo/2^n)+(a.hi%2^n)*2^(32-n))
end
local function udiv(a,b)
    if b.hi==0 and b.lo==0 then error("attempt to divide by zero",0) end
    local q,r=make(0,0),make(0,0)
    for bit=63,0,-1 do
        local overflow=r.hi>=2147483648
        r=shl(r,1)
        local digit=bit>=32 and floor(a.hi/2^(bit-32))%2 or floor(a.lo/2^bit)%2
        r.lo=r.lo+digit
        if overflow or not unsigned_lt(r,b) then
            r=sub(r,b)
            if bit>=32 then q.hi=q.hi+2^(bit-32) else q.lo=q.lo+2^bit end
        end
    end
    return q,r
end
local function divmod(a,b)
    a,b=from(a),from(b)
    local sa,sb=a.hi>=2147483648,b.hi>=2147483648
    local q,r=udiv(sa and neg(a) or a,sb and neg(b) or b)
    if sa~=sb then
        q=neg(q)
        if r.hi~=0 or r.lo~=0 then q=sub(q,1);r=sub(sb and neg(b) or b,r) end
    end
    if sb then r=neg(r) end
    return q,r
end
local function parse(text)
    local result=make(0,0)
    local sign=string.sub(text,1,1)=="-"
    if sign then text=string.sub(text,2) end
    local base=10
    if string.sub(text,1,2):lower()=="0x" then base=16;text=string.sub(text,3) end
    for i=1,#text do
        local c=string.byte(text,i)
        local digit=c>=48 and c<=57 and c-48 or c>=65 and c<=70 and c-55 or c>=97 and c<=102 and c-87 or nil
        if not digit or digit>=base then error("invalid integer literal",0) end
        result=add(mul(result,base),digit)
    end
    return sign and neg(result) or result
end
local function text(a)
    a=from(a)
    if a.hi==0 and a.lo==0 then return "0" end
    local negative=a.hi>=2147483648
    if negative then a=neg(a) end
    local digits={}
    while a.hi~=0 or a.lo~=0 do
        local hi=floor(a.hi/10)
        local remainder=(a.hi-hi*10)*U32+a.lo
        local lo=floor(remainder/10)
        digits[#digits+1]=string.char(48+remainder-lo*10)
        a=make(hi,lo)
    end
    local out=negative and "-" or ""
    for i=#digits,1,-1 do out=out..digits[i] end
    return out
end
M.make,M.from,M.isint,M.number,M.parse,M.text=make,from,isint,number,parse,text
M.private_marker=private_marker
M.add,M.sub,M.mul,M.neg,M.eq,M.lt=add,sub,mul,neg,eq,lt
M.band=function(a,b) return bits(a,b,1) end
M.bxor=function(a,b) return bits(a,b,2) end
M.bor=function(a,b) return bits(a,b,3) end
M.bnot=function(a) a=from(a);return make(U32-1-a.hi,U32-1-a.lo) end
M.shl,M.shr,M.divmod=shl,shr,divmod
return M
