local patterns={
    0,0x8000000000000000,1,0x8000000000000001,
    0x000fffffffffffff,0x800fffffffffffff,
    0x0010000000000000,0x8010000000000000,
    0x3ff0000000000000,0xbff0000000000000,
    0x3fefffffffffffff,0x3ff0000000000001,
    0x7fefffffffffffff,0xffefffffffffffff,
    0x7ff0000000000000,0xfff0000000000000,
    0x7ff8000000000000,0xfff8000000000001,
    0x7ff0000000000001,0xfff0000000000001,
}
local function compare(a,b)
    return a==b,a~=b,a<b,a<=b,a>b,a>=b
end
for i,a in ipairs(patterns) do
    for j,b in ipairs(patterns) do
        local x=string.unpack("<d",string.pack("<I8",a))
        local y=string.unpack("<d",string.pack("<I8",b))
        assert(math.type(x)=="float" and math.type(y)=="float")
        print(i,j,compare(x,y))
    end
end
-- Mixed comparisons must retain Lua's exact integer/float boundary behavior.
print("mixed",compare(math.maxinteger,9223372036854775808.0))
print("mixed",compare(math.mininteger,-9223372036854775808.0))
print("mixed",compare(9007199254740993,9007199254740992.0))
print("mixed",compare(1,0/0))
local mt={__eq=function() return true end,__lt=function() return false end,
          __le=function() return true end}
print("objects",compare(setmetatable({},mt),setmetatable({},mt)))
