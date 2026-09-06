local integers={
    math.mininteger,math.mininteger+1,math.mininteger+1024,
    -9007199254740993,-9007199254740992,-9007199254740991,
    -4294967297,-17,-2,-1,0,1,2,17,4294967297,
    9007199254740991,9007199254740992,9007199254740993,
    math.maxinteger-1024,math.maxinteger-1,math.maxinteger,
}
local patterns={
    0,0x8000000000000000,1,0x8000000000000001,
    0x000fffffffffffff,0x800fffffffffffff,
    0x0010000000000000,0x8010000000000000,
    0x3ff0000000000000,0xbff0000000000000,
    0x3fefffffffffffff,0x3ff0000000000001,
    0x3ff8000000000000,0xbff8000000000000,
    0x4340000000000000,0xc340000000000000,
    0x43dfffffffffffff,0x43e0000000000000,
    0xc3e0000000000000,0xc3e0000000000001,
    0x7fefffffffffffff,0xffefffffffffffff,
    0x7ff0000000000000,0xfff0000000000000,
    0x7ff8000000000000,0xfff8000000000001,
}
local function compare(a,b)
    return a==b,a~=b,a<b,a<=b,a>b,a>=b
end
local function check(a,b)
    print(compare(a,b))
    print(compare(b,a))
end
for _,integer in ipairs(integers) do
    for _,bits in ipairs(patterns) do
        check(integer,string.unpack("<d",string.pack("<I8",bits)))
    end
end
local state=9900
local function next_bits()
    state=state~(state<<13)
    state=state~(state>>7)
    state=state~(state<<17)
    return state
end
for i=1,128 do
    local integer=next_bits()
    local floating=string.unpack("<d",string.pack("<I8",next_bits()))
    check(integer,floating)
end
-- Exercise integers read from the encoded register cache after arithmetic.
local function cached(a,b)
    local x=a+1
    return compare(x,b)
end
print("cached",cached(9007199254740992,9007199254740992.0))
