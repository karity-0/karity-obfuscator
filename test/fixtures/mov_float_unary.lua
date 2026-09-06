local function negate(x) return -x end
local function bits(x) return string.unpack("<i8",string.pack("<d",x)) end
local patterns={
    0,0x8000000000000000,1,0x8000000000000001,
    0x000fffffffffffff,0x800fffffffffffff,
    0x0010000000000000,0x8010000000000000,
    0x3ff0000000000000,0xbff0000000000000,
    0x7fefffffffffffff,0xffefffffffffffff,
    0x7ff0000000000000,0xfff0000000000000,
    0x7ff8000000000001,0xfff8000000004321,
    0x7ff0000000000001,0xfff0000000000001,
}
local state=0x123456789abcdef
for i=1,128 do
    state=state~(state<<13); state=state~(state>>7); state=state~(state<<17)
    patterns[#patterns+1]=state
end
for i,raw in ipairs(patterns) do
    local x=string.unpack("<d",string.pack("<i8",raw))
    -- Some Lua builds quiet signaling NaNs while unpacking/returning values.
    local input=bits(x)
    local y=negate(x)
    assert(math.type(y)=="float")
    assert(bits(y)==(input~0x8000000000000000))
    assert(bits(negate(y))==input)
end
-- Reusing a register must clear its previous integer/string representation.
local function overwrite(x,y,a,b)
    local value=x+1
    value=-y
    assert(math.type(value)=="float" and value==1.5)
    value=a..b
    value=-y
    assert(math.type(value)=="float" and value==1.5)
    value=-value
    return value
end
assert(overwrite(3,-1.5,"a","b")==-1.5)
assert(negate(math.mininteger)==math.mininteger)
assert(negate("2.5")==-2.5)
local obj=setmetatable({},{__unm=function() return "unary effect" end})
assert(negate(obj)=="unary effect")
assert(not pcall(negate,{}))
local co=coroutine.create(function()
    return negate(setmetatable({},{__unm=function()
        coroutine.yield("unary yield")
        return 17
    end}))
end)
local ok,value=coroutine.resume(co)
assert(ok and value=="unary yield")
ok,value=coroutine.resume(co)
assert(ok and value==17)
print("float-unary-ok",#patterns)
