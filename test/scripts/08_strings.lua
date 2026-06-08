local s = "hello 12380483104afuqefanf0qe"

local s2 = [[long text 
21342u03143
\n
421414]]

--[[
MinifyPass cant handle it:
local s3 = [=[hello hello test
s3
[=====[ xvbsg ]=====]
]=]

]]
s = "zxcvbea"
function f(...)
    local s = "afergs"
    return s, ...
end

local a = "hello" .. "world"
print(a)
local b = "hello" .. tostring(123)
print(b)
local t = {
    ["key"] = "value",
    test = "abc"
}
print(t.key, t["key"], t.test)
local function outer()
    local s = "outer"
    return function()
        return s .. " inner"
    end
end
print(outer()())

local a = "same"
print(a)
local b = "same"
print(b)
local s = "\0\1\255\n\t\"\\"
print(s)
_G["test"] = "value"
print(test, _G["test"], _G.test)

return f("eqrtr", "ofenorneo", "banana")
