local function shifts(x,n) return x<<n,x>>n end
local counts={math.mininteger,math.maxinteger}
for n=-70,70 do counts[#counts+1]=n end
for b=7,62 do
    counts[#counts+1]=1<<b
    counts[#counts+1]=-(1<<b)
end
local values={0,1,-1,math.mininteger,math.maxinteger,0x123456789abcdef,0xfedcba9876543210}
for _,x in ipairs(values) do
    for _,n in ipairs(counts) do
        local a,b=shifts(x,n)
        assert(math.type(a)=="integer" and math.type(b)=="integer")
        print(a,b)
    end
end
-- Counts and operands produced by previous lookup operations stay usable.
local x,n=0,0
for i=1,65 do
    x=x+17; n=n-1
    print(shifts(x,n))
end
-- Lua coercion, non-integral errors and metamethods retain their host path.
print(shifts(3.0,2.0))
print(shifts("3","-2"))
assert(not pcall(shifts,3,1.5))
local obj=setmetatable({},{__shl=function() return "left" end,
                            __shr=function() return "right" end})
print(shifts(obj,1))
