local arg = ...

k = arg and arg.m
l = global_data_read_only
n = global_data_write_read
global_data_write_read = 100

a = 123

local b = 234

a = 234

local b = 432

b = 5423

local c = 234

function f(a,b)
    return 123
end

local function ff(a, c, e)
    return 523
end

print("rename test a b c d e f")
-- local a = 123

local z=f(a,b)
local x             = 
            ff(c,f,ff)
print(z,x)

local mmm = function() print("mmm test") end

mmm()