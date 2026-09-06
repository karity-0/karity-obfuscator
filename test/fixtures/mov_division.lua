local function division(a,b)
    if b==0 then
        local q,qerr=pcall(function() return a//b end)
        local r,rerr=pcall(function() return a%b end)
        assert(not q and string.find(qerr,"divide by zero",1,true))
        assert(not r and string.find(rerr,"n%0",1,true))
        print(a,b,"zero")
    else
        print(a,b,a//b,a%b)
    end
end
local values={math.mininteger,math.mininteger+1,-4294967297,-17,-2,-1,
              0,1,2,17,4294967297,math.maxinteger}
for _,a in ipairs(values) do
    for _,b in ipairs(values) do division(a,b) end
end
local state=711253
local function next_integer()
    state=state~(state<<13)
    state=state~(state>>7)
    state=state~(state<<17)
    return state
end
for i=1,64 do division(next_integer(),next_integer()) end
-- Cached encoded results must be usable as future division operands.
local function repeated(a,b)
    local q=a//b
    local r=a%b
    return q//b,q%b,r//b,r%b
end
print("repeat",repeated(-1234567,31))
print("float",7.5//2,7.5%2)
local function coercion(a,b) return a//b,a%b end
print("coercion",coercion("7","2"))
local mt={__idiv=function() return "idiv" end,__mod=function() return "mod" end}
local a=setmetatable({},mt)
print("metamethod",coercion(a,2))
