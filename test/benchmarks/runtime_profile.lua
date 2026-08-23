-- karity runtime profiling workload
-- Run this file natively once, then obfuscate with the target profile and run again.
-- Compare each [BENCH] phase and TOTAL.

local clock = os.clock
local floor = math.floor
local concat = table.concat

local results = {}
local sink = 0

local function bench(name, fn)
    collectgarbage("collect")
    local t0 = clock()
    local value = fn()
    local dt = clock() - t0
    results[#results + 1] = {name, dt, value}
    sink = (sink ~ (tonumber(value) or 0)) & 0x7FFFFFFF
end

-- 1. Integer arithmetic / bitwise.
-- Heavy on ADD/SUB/MUL/BAND/BOR/BXOR/SHL/SHR style VM paths.
bench("arith_bitwise", function()
    local x = 0x12345678
    local y = 0x5A5A5A5A
    for i = 1, 20000 do
        x = (x + i * 13) & 0xFFFFFFFF
        x = x ~ ((x << 7) & 0xFFFFFFFF)
        x = x ~ (x >> 11)
        y = (y + (x ~ i)) & 0xFFFFFFFF
        y = ((y << 3) | (y >> 29)) & 0xFFFFFFFF
    end
    return (x ~ y) & 0x7FFFFFFF
end)

-- 2. Branch-heavy control flow.
-- Useful for measuring dispatcher/CFF/control-graph overhead.
bench("branches", function()
    local x = 0
    for i = 1, 30000 do
        local m = i % 7
        if m == 0 then
            x = x + i
        elseif m == 1 then
            x = x ~ i
        elseif m == 2 then
            x = x - (i % 19)
        elseif m == 3 then
            x = x + 3
        elseif m == 4 then
            x = x ~ 0x55
        elseif m == 5 then
            x = x + (i & 15)
        else
            x = x - 1
        end
    end
    return x & 0x7FFFFFFF
end)

-- 3. Numeric for-loop overhead.
bench("numeric_for", function()
    local s = 0
    for i = 1, 50000 do
        s = (s + i) & 0x7FFFFFFF
    end
    return s
end)

-- 4. Table read/write.
-- Exercises GETTABLE/SETTABLE and register traffic.
bench("table_rw", function()
    local t = {}
    for i = 1, 6000 do
        t[i] = (i * 17) ~ (i << 2)
    end

    local s = 0
    for i = 1, 6000 do
        s = (s + t[i]) & 0x7FFFFFFF
        t[i] = t[i] ~ (s & 0xFF)
    end
    return (s ~ t[4096]) & 0x7FFFFFFF
end)

-- 5. Generic iteration.
-- Separates FOR/iterator/CALL costs from plain numeric loops.
bench("generic_for", function()
    local t = {}
    for i = 1, 3000 do
        t[i] = i * 3
    end

    local s = 0
    for k, v in ipairs(t) do
        s = (s + k + v) & 0x7FFFFFFF
    end
    return s
end)

-- 6. Function calls.
-- Exercises CALL/RETURN routing without recursion.
bench("function_calls", function()
    local function f(a, b)
        return ((a ~ b) + ((a * 3) & 0xFFFF)) & 0x7FFFFFFF
    end

    local x = 1
    for i = 1, 12000 do
        x = f(x, i)
    end
    return x
end)

-- 7. Closures and upvalues.
bench("closures", function()
    local function make(seed)
        local state = seed
        return function(v)
            state = ((state ~ v) + 0x1234) & 0x7FFFFFFF
            return state
        end
    end

    local f = make(0x314159)
    local s = 0
    for i = 1, 8000 do
        s = s ~ f(i)
    end
    return s & 0x7FFFFFFF
end)

-- 8. String operations.
-- Keeps payload modest while exercising string constants and native calls.
bench("strings", function()
    local out = {}
    for i = 1, 1200 do
        local s = "Karity-" .. tostring(i) .. "-" .. string.char(65 + (i % 26))
        out[i] = string.sub(s, 1, 12)
    end
    local joined = concat(out, "|")
    return #joined
end)

-- 9. Mixed workload.
-- Gives a more realistic aggregate path with calls, branches, tables, and arithmetic.
bench("mixed", function()
    local function step(t, i, x)
        local v = t[(i % 128) + 1] or i
        if (v ~ x) & 1 == 0 then
            x = (x + v * 7) & 0x7FFFFFFF
        else
            x = (x ~ (v + i)) & 0x7FFFFFFF
        end
        t[(i % 128) + 1] = x & 0xFFFF
        return x
    end

    local t = {}
    for i = 1, 128 do
        t[i] = i * 11
    end

    local x = 0x13579B
    for i = 1, 10000 do
        x = step(t, i, x)
    end
    return x
end)

local total = 0
print("----- karity runtime profile -----")
for _, r in ipairs(results) do
    total = total + r[2]
    print(string.format("[BENCH] %-16s %.6fs  result=%s", r[1], r[2], tostring(r[3])))
end
print(string.format("[BENCH] %-16s %.6fs", "TOTAL", total))
print(string.format("[BENCH] sink             %d", sink))
print("success!")
