local function f(a, ...)
    local t = {...}
    local sum = a
    for i = 1, #t do sum = sum + t[i] end
    return sum, function(x) return sum + x end
end
local a, g = f(1, 2, 3)
assert(a == 6 and g(4) == 10)
