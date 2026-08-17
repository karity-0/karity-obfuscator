local function pack(...)
    return {n = select("#", ...), ...}
end

local list = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
}
assert(#list == 60 and list[1] == 1 and list[50] == 50 and list[60] == 60,
    "setlist")

local empty = {}
empty.answer = 42
assert(empty.answer == 42, "newtable")

assert("left" .. 17 .. ":right" == "left17:right", "concat primitive")

local events = {}
local mt
mt = {
    __concat = function(a, b)
        local av = type(a) == "table" and a.value or a
        local bv = type(b) == "table" and b.value or b
        events[#events + 1] = tostring(av) .. "+" .. tostring(bv)
        return setmetatable({value = tostring(av) .. tostring(bv)}, mt)
    end,
}
local a = setmetatable({value = "a"}, mt)
local b = setmetatable({value = "b"}, mt)
local c = setmetatable({value = "c"}, mt)
local joined = a .. b .. c
assert(joined.value == "abc", "concat metamethod result")
assert(#events == 2, "concat metamethod count")

local function relay(...)
    local values = pack(...)
    return values.n, values[1], values[2], values[3], values[4]
end
local n, v1, v2, v3, v4 = relay("x", nil, 3, nil)
assert(n == 4 and v1 == "x" and v2 == nil and v3 == 3 and v4 == nil, "vararg holes")

local function factory(seed)
    local value = seed
    return function(step)
        value = value + step
        return value
    end
end
local counter = factory(10)
assert(counter(2) == 12 and counter(3) == 15, "closure state")

for i = 1, 40 do
    assert((i % 7) == math.fmod(i, 7), "mod loop")
    assert((i // 3) <= (i / 3), "division loop")
    assert(not (i < 0), "not loop")
end

print("vm semantic ir ok", joined.value, counter(0))
