-- Every declared prototype is exercised, including closures in other frames.
local shared=0x123456789abcdef
local function add(a,b)
    shared=shared+a
    return a+b
end
local function mul(a,b)
    shared=shared~b
    return a*b
end
local function shift(a,b)
    shared=shared-b
    return (a<<b)~(a>>-b)
end
local function factory(x)
    return function(y)
        x=mul(add(x,y),3)
        return shift(x,5),x,shared,nil
    end
end
local f=factory(0x7fffffffffffffff)
for i=1,12 do
    local p=table.pack(f(i))
    assert(p.n==4 and p[4]==nil)
    print(i,p[1],p[2],p[3])
end
local even,odd
even=function(n,a)
    if n==0 then return a,shared,nil end
    shared=shared+1
    return odd(n-1,mul(a,3))
end
odd=function(n,a)
    if n==0 then return a,shared,nil end
    shared=shared-1
    return even(n-1,add(a,2))
end
local result=table.pack(even(300,7))
assert(result.n==3 and result[3]==nil)
local co=coroutine.create(function()
    local a=add(7,8)
    local b=coroutine.yield(mul(a,9))
    return f(b)
end)
local ok1,a=coroutine.resume(co)
local ok2,b,c,d,e=coroutine.resume(co,11)
assert(ok1 and ok2 and a==135 and e==nil)
print("cross vm",result[1],result[2],b,c,d)
