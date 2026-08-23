local function delayed(a, b)
    local sum = a + b
    local marker = "interleaved"
    local difference = a - b
    local box = { marker = marker, input = a }
    local negative = -b
    box.ready = true
    return sum, difference, negative, box.marker, box.ready
end

local function bounce(value)
    return value * 2
end

local function across_call_and_branch(a, b)
    local pending = a + b
    local echoed = bounce(a)
    if echoed > 0 then
        echoed = echoed - b
    end
    return pending, echoed
end

local function overwritten(a, b)
    local value = a + b
    value = "replaced"
    return value
end

local metamethod_hits = 0
local wrapped = setmetatable({}, {
    __add = function()
        metamethod_hits = metamethod_hits + 1
        return 77
    end,
})
local metamethod_value = wrapped + wrapped
local hits_after_instruction = metamethod_hits

local total = 0
local checksum = 0
for i = 1, 64 do
    local sum, difference, negative, marker, ready = delayed(i * 3, i)
    total = total + sum
    checksum = checksum + difference - negative
    assert(marker == "interleaved")
    assert(ready == true)
end


local pending, echoed = across_call_and_branch(21, 8)
assert(pending == 29)
assert(echoed == 34)
assert(overwritten(10, 20) == "replaced")
assert(metamethod_value == 77)
assert(hits_after_instruction == 1)

print(total)
print(checksum)
