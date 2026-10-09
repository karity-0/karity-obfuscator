local function pause(value)
    return coroutine.yield("pause", value)
end

local co = coroutine.create(function(value)
    return pause(value + 1)
end)
local ok, tag, value = coroutine.resume(co, 10)
assert(ok and tag == "pause" and value == 11, "direct call yield/resume")
local resumed, result = coroutine.resume(co, 40)
assert(resumed and result == 40, "direct call resumed result")

local repeated_number = 17
assert(repeated_number + repeated_number == 34, "same-register numeric operands")
local repeated_table = setmetatable({}, {
    __add = function(left, right)
        assert(left == right, "same-register metamethod operands")
        return 42
    end,
})
assert(repeated_table + repeated_table == 42, "same-register metamethod call")

local left = setmetatable({value = 40}, {
    __add = function(a, b)
        return a.value + b
    end,
})
assert(left + 2 == 42, "native metamethod dispatch")

local caught, message = pcall(function()
    error("call-failure", 0)
end)
assert(not caught and message == "call-failure", "pcall error boundary")
local handled, detail = xpcall(function()
    error("xpcall-failure", 0)
end, function(error_value)
    return "handled:" .. error_value
end)
assert(not handled and detail == "handled:xpcall-failure", "xpcall error boundary")

print(tag, value, result, caught, handled)
