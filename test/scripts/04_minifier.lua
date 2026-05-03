-- 기본 연산자
local a = 10
local b = 20
local c = a + b
local d = a * b - c / 2

-- 비교/논리
if a > b then
    print("a is greater")
elseif a == b then
    print("equal")
else
    print("b is greater")
end

-- 반복
for i = 1, 10 do
    print(i)
end

local t = {1, 2, 3}
for k, v in pairs(t) do
    print(k, v)
end

while a > 0 do
    a = a - 1
end

-- 함수
local function add(x, y)
    return x + y
end

local mul = function(x, y)
    return x * y
end

print(add(1, 2))
print(mul(3, 4))

-- 테이블
local obj = {
    name = "test",
    value = 432,
}
print(obj.name, obj["value"])

-- 문자열 연결
local s = "hello" .. " " .. "world"
print(s)

print("hello--world")
print("hello -- world")
print("hello- -world")

if true then
    return
end
a = 1