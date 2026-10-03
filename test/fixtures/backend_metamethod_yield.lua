local left = setmetatable({}, {
    __add = function()
        return coroutine.yield("add")
    end,
})
local arithmetic = coroutine.create(function()
    return left + 1
end)
local ok, tag = coroutine.resume(arithmetic)
assert(ok and tag == "add", "Lua 5.3 metamethod yield")
local resumed, result = coroutine.resume(arithmetic, 42)
assert(resumed and result == 42, "Lua 5.3 metamethod resume")
print(tag, result)
