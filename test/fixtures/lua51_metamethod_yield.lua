local left = setmetatable({}, {
    __add = function()
        return coroutine.yield("add")
    end,
})
local arithmetic = coroutine.create(function()
    return left + 1
end)
local ok, message = coroutine.resume(arithmetic)
assert(not ok and type(message) == "string"
    and string.find(message, "attempt to yield across", 1, true),
    "Lua 5.1 rejects yield across metamethod boundary")
