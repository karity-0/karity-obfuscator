local function eq(actual, expected, label)
    assert(actual == expected, label .. ": " .. tostring(actual))
end

local values = {0, 1, -1, 2, -2, 17, -31, 0x7fffffff, -0x80000000}
for _, a in ipairs(values) do
    for _, b in ipairs(values) do
        eq(a + b, a + b, "add")
        eq(a - b, a - b, "sub")
        eq(a * b, a * b, "mul")
        eq(a & b, a & b, "band")
        eq(a | b, a | b, "bor")
        eq(a ~ b, a ~ b, "bxor")
        eq(a << b, a << b, "shl")
        eq(a >> b, a >> b, "shr")
    end
    eq(-a, -a, "unm")
    eq(~a, ~a, "bnot")
end

eq(1.5 + 2.25, 3.75, "float add")
eq(5.5 - 2.25, 3.25, "float sub")
eq(1.5 * 4.0, 6.0, "float mul")
eq("12" + "8", 20, "numeric string add")
eq("12" - "8", 4, "numeric string sub")
eq(20 % 6, 2, "mod")
eq(2 ^ 10, 1024.0, "pow")
eq(7 / 2, 3.5, "div")
eq(7 // 2, 3, "idiv")

local calls = {}
local mt = {}
local function binary(name)
    return function(a, b)
        calls[#calls + 1] = name
        return setmetatable({value = a.value + b.value}, mt)
    end
end
mt.__add = binary("add")
mt.__sub = binary("sub")
mt.__mul = binary("mul")
mt.__mod = binary("mod")
mt.__pow = binary("pow")
mt.__div = binary("div")
mt.__idiv = binary("idiv")
mt.__band = binary("band")
mt.__bor = binary("bor")
mt.__bxor = binary("bxor")
mt.__shl = binary("shl")
mt.__shr = binary("shr")
mt.__unm = function(a) calls[#calls + 1] = "unm"; return a end
mt.__bnot = function(a) calls[#calls + 1] = "bnot"; return a end

local x = setmetatable({value = 4}, mt)
local y = setmetatable({value = 7}, mt)
local results = {
    x + y, x - y, x * y, x % y, x ^ y, x / y, x // y,
    x & y, x | y, x ~ y, x << y, x >> y, -x, ~x
}
assert(#results == 14, "metamethod result count: " .. #results)
local expected_calls = {
    "add", "sub", "mul", "mod", "pow", "div", "idiv",
    "band", "bor", "bxor", "shl", "shr", "unm", "bnot"
}
local call_pos = 1
for _, name in ipairs(calls) do
    if name == expected_calls[call_pos] then call_pos = call_pos + 1 end
end
assert(call_pos > #expected_calls, "metamethod calls: " .. table.concat(calls, ","))

local events = {}
local backing = {answer = 42}
local function proxy_index(_, key)
    events[#events + 1] = "get:" .. key
    return backing[key]
end
local function proxy_newindex(_, key, value)
    events[#events + 1] = "set:" .. key
    backing[key] = value
end
local function proxy_len()
    events[#events + 1] = "len"
    return 9
end
local function proxy_lt()
    events[#events + 1] = "lt"
    return true
end
local function proxy_le()
    events[#events + 1] = "le"
    return false
end
local proxy_mt = {
    __index = proxy_index,
    __newindex = proxy_newindex,
    __len = proxy_len,
    __lt = proxy_lt,
    __le = proxy_le,
}
local p = setmetatable({}, proxy_mt)
local q = setmetatable({}, proxy_mt)
assert(p.answer == 42, "__index result")
p.extra = 17
assert(backing.extra == 17, "__newindex result")
assert(#p == 9, "__len result")
assert(p < q, "__lt result")
assert(not (p <= q), "__le result")
assert(table.concat(events, ",") == "get:answer,set:extra,len,lt,le",
    "table events: " .. table.concat(events, ","))

local captured = 3
local function get_captured() return captured end
local function set_captured(value) captured = value end
assert(get_captured() == 3, "captured initial")
set_captured(8)
assert(get_captured() == 8, "captured update")

if math.maxinteger then
    eq(math.maxinteger + 1, math.mininteger, "add wrap")
    eq(math.mininteger - 1, math.maxinteger, "sub wrap")
    eq(-math.mininteger, math.mininteger, "unm wrap")
end

print("vm graph ops ok")
