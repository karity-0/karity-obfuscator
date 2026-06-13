function func1()
    local a = 123
    a = a + 123
    if a > 300 then
        a = a - 300
    else
        a = a + 100
    end
    return a
end

function func2(a)
    a = a + 200
    a = a + 100
    a = a + 300
    return a
end

function func3(a,b,c)
    return 3
end

function func4(...)
    return 4
end

function func5(a,b,c,d,...)
    return 5
end

local function func6()
    return 6
end

local func7 = function(a, b, ...)
    return 7, ...
end

func8 = function(a, b, c)
    return 8
end

local function func9  (      a,       b)
    return 1,2,3,4,5,6,7,8,9, a, b
end

--[=[
ERROR
local function func10(a, --[[b,c,)]] b, c)
    local function func11(a,b,c) end
    function func12() end
    return 10
end

]=]

print(func1(100), func2(100), func3(), func4(), func5(), func6(),
func7(), func8(), func9())