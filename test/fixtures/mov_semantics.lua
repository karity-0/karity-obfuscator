-- MOV-specific conformance fixture; runtime operands prevent constant folding.
local values={0,1,-1,15,16,255,256,0x7fffffffffffffff,0x8000000000000000,
              0x123456789abcdef,0xfedcba9876543210}
local digest=0
local function mix(v)
    assert(math.type(v)=="integer")
    digest=(digest~v)*0x100000001b3
end
for _,a in ipairs(values) do
    mix(-a); mix(~a)
    for _,b in ipairs(values) do
        mix(a+b); mix(a-b); mix(a*b); mix(a&b); mix(a|b); mix(a~b)
        print(a==b,a<b,a<=b,a>b,a>=b)
    end
end
local state=0x918273645
for i=1,150 do
    state=state~(state<<13); state=state~(state>>7); state=state~(state<<17)
    local a=state
    local b=values[(i%#values)+1]
    mix(a+b); mix(a-b); mix(a*b); mix(a&b); mix(a|b); mix(a~b)
    print(a==b,a<b,a<=b)
end
local counts={0x8000000000000000,-65,-64,-63,-17,-5,-4,-3,-1,0,1,3,4,5,17,63,64,65,
              0x7fffffffffffffff}
for _,a in ipairs(values) do
    for _,b in ipairs(counts) do mix(a<<b); mix(a>>b) end
end
local function aliases(a)
    a=a*a
    a=a<<a
    a=a>>a
    return a
end
for _,a in ipairs(values) do mix(aliases(a)) end
print("digest",string.format("%016x",digest))

local function arithmetic(a,b)
    print(a+b,a-b,a*b,a&b,a|b,a~b,a<<b,a>>b,-a,~a,a==b,a<b,a<=b)
end
arithmetic(3.0,2.0)
arithmetic("12","3")
local function floats(a,b) print(a+b,a-b,a==b,a<b,a<=b) end
floats(0/0,1); floats(math.huge,-math.huge)
floats(0x7fffffffffffffff,9223372036854775808.0)
local effects={}
local mt={}
for _,event in ipairs({"__add","__sub","__mul","__band","__bor","__bxor","__shl","__shr","__unm","__bnot"}) do
    local name=event
    mt[name]=function() effects[#effects+1]=name; return 7 end
end
for _,event in ipairs({"__eq","__lt","__le"}) do
    local name=event
    mt[name]=function() effects[#effects+1]=name; return true end
end
arithmetic(setmetatable({},mt),setmetatable({},mt))
print("effects",table.concat(effects,","))
local ok=pcall(function() local x={}; return x+1 end)
assert(not ok)
local function shifts(a,b) return a<<b,a>>b end
local ok_shift=pcall(shifts,1,1.5)
assert(not ok_shift)
print("shift coercion",shifts("-16","2"))
local function multiply(a,b) return a*b end
print("multiply coercion",multiply("2.5",4),multiply(3.0,2))

local counter=0
local function hit() counter=counter+1; return "hit" end
local falsey=false and hit()
local truthy=0 or hit()
local nilvalue=nil or hit()
assert(falsey==false and truthy==0 and nilvalue=="hit" and counter==1)
local f={}
for i=1,4 do local x=i+10; f[i]=function(v) x=x+v; return x end end
assert(f[1](1)==12 and f[2](2)==14 and f[1](1)==13)
local x=2
local function update() x=x+3 end
update(); local y=x+4; update(); assert(x==8 and y==9)
local function tail(n,a)
    if n==0 then return a,nil,"tail",nil end
    return tail(n-1,a+1)
end
local packed=table.pack(tail(3000,0))
assert(packed.n==4 and packed[1]==3000 and packed[2]==nil and packed[3]=="tail")
local co=coroutine.create(function()
    local a=20+tonumber("2")
    local b=coroutine.yield(a+1)
    return a+b
end)
local ok1,v1=coroutine.resume(co)
local ok2,v2=coroutine.resume(co,5)
assert(ok1 and v1==23 and ok2 and v2==27)
print("mov semantics ok")
