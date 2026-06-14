local function factorial(n)
    if n <= 1 then
        return 1
    end

    return n * factorial(n - 1)
end

local function tail_sum(n, acc)
    acc = acc or 0

    if n == 0 then
        return acc
    end

    return tail_sum(n - 1, acc + n)
end

local function make_counter(start)
    local value = start or 0

    return function(step)
        step = step or 1
        value = value + step
        return value
    end
end

local function make_nested_closure(a)
    local outer = a

    return function(b)
        local middle = b

        return function(c)
            return outer + middle + c
        end
    end
end

local counterA = make_counter(10)
local counterB = make_counter(100)

local nested = make_nested_closure(5)(10)

local obj = {}
obj.__index = obj

function obj:new(name)
    local instance = {
        name = name,
        value = 0
    }

    setmetatable(instance, self)
    return instance
end

function obj:add(v)
    self.value = self.value + v
    return self.value
end

function obj:info()
    return self.name, self.value
end

local instance = obj:new("karity")

local config = {
    name = "karity",
    version = 1.23,
    flags = {
        debug = false,
        release = true
    }
}

local function calc(...)
    local sum = 0
    local args = {...}

    for _, v in ipairs(args) do
        sum = sum + v
    end

    return sum, #args
end

local function process(tbl)
    local result = {}

    for k, v in pairs(tbl) do
        if type(v) == "number" then
            result[k] = v * 2
        elseif type(v) == "string" then
            result[k] = v:reverse()
        else
            result[k] = v
        end
    end

    return result
end

local values = process({
    a = 10,
    b = "hello",
    c = true
})

local ok1, res1 = pcall(function()
    return factorial(6)
end)

local ok2, err2 = pcall(function()
    error("intentional error")
end)

local function error_handler(err)
    return "caught: " .. tostring(err)
end

local ok3, res3 = xpcall(function()
    error("xpcall test")
end, error_handler)

local co = coroutine.create(function(start)
    local value = start

    coroutine.yield(value)

    value = value + 10
    coroutine.yield(value)

    return value + 20
end)

local co_ok1, co_v1 = coroutine.resume(co, 5)
local co_ok2, co_v2 = coroutine.resume(co)
local co_ok3, co_v3 = coroutine.resume(co)

local weak_tbl = setmetatable({}, {
    __mode = "v"
})

weak_tbl.test = {
    hello = "world"
}

local mt = {
    __add = function(a, b)
        return setmetatable({
            value = a.value + b.value
        }, mt)
    end,

    __tostring = function(self)
        return "Value(" .. self.value .. ")"
    end
}

local v1 = setmetatable({ value = 10 }, mt)
local v2 = setmetatable({ value = 20 }, mt)
local v3 = v1 + v2

local function self_call(n)
    if n <= 0 then
        return "done"
    end

    return self_call(n - 1)
end

local results = {
    counterA_1 = counterA(),
    counterA_2 = counterA(5),
    counterB_1 = counterB(10),

    nested = nested(20),

    factorial = factorial(5),
    tail_sum = tail_sum(100),

    self_call = self_call(10),

    calc_sum = select(1, calc(1, 2, 3, 4, 5)),
    calc_count = select(2, calc(1, 2, 3, 4, 5)),

    pcall_ok = ok1,
    pcall_result = res1,

    pcall_error_ok = ok2,
    pcall_error = err2,

    xpcall_ok = ok3,
    xpcall_result = res3,

    coroutine1 = co_v1,
    coroutine2 = co_v2,
    coroutine3 = co_v3
}

instance:add(5)
instance:add(7)

print("=== RESULTS ===")

for k, v in ipairs(results) do
    print(k, v)
end

print("=== CONFIG ===")
print(config.name)
print(config.version)
print(config.flags.debug)
print(config.flags.release)

print("=== PROCESSED ===")

for k, v in ipairs(values) do
    print(k, v)
end

print("=== OBJECT ===")

local name, value = instance:info()
print(name, value)

print("=== METATABLE ===")
print(type(v3))

print("=== DONE ===")