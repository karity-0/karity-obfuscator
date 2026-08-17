local function pack(...)
    return {n = select("#", ...), ...}
end

local function multi(x)
    return x + 1, nil, x * 3, "done"
end

local function forward(...)
    return multi(...)
end

local m = pack(forward(7))
assert(m.n == 4 and m[1] == 8 and m[2] == nil and m[3] == 21 and m[4] == "done", "multi")

local function sum(n)
    if n == 0 then return 0 end
    return n + sum(n - 1)
end
assert(sum(250) == 31375, "recursive")

local function tail_sum(n, acc)
    if n == 0 then return acc, "tail" end
    return tail_sum(n - 1, acc + n)
end
local total, marker = tail_sum(500, 0)
assert(total == 125250 and marker == "tail", "tail")

local function vararg_count(head, ...)
    return head, select("#", ...), ...
end
local v = pack(vararg_count("v", 1, nil, 3, nil))
assert(v.n == 6 and v[1] == "v" and v[2] == 4, "vararg-head")
assert(v[3] == 1 and v[4] == nil and v[5] == 3 and v[6] == nil, "vararg-tail")

local seed = 9
local function make_counter(step)
    local value = seed
    return function(delta)
        value = value + step + delta
        return value
    end
end
local counter = make_counter(4)
assert(counter(1) == 14 and counter(2) == 20, "closure")

local callable = setmetatable({bias = 11}, {
    __call = function(self, a, b)
        return self.bias + a + b, nil
    end
})
local c = pack(callable(2, 5))
assert(c.n == 2 and c[1] == 18 and c[2] == nil, "callable")

local ok, err = pcall(function(a)
    local function fail(b)
        error("call-machine-" .. (a + b), 0)
    end
    return fail(3)
end, 8)
assert(not ok and err == "call-machine-11", "pcall")

local function choose(flag)
    if flag then return multi(4) end
    return "fallback"
end
local t = pack(choose(true))
assert(t.n == 4 and t[1] == 5 and t[3] == 12, "choose")

print("vm call machine ok", total, counter(0))
