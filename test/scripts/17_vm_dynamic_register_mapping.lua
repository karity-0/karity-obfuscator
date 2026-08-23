local shared = {count = 0}

local function bounce(i)
    shared.count = shared.count + 1
    local value = i + 7
    value = value - 3
    value = -(-value)
    return value, shared, "mapped", (i % 2) == 0, 3.25, nil
end

local total = 0
local last_ref
local last_text
local last_bool
local last_float
local last_nil

for i = 1, 32 do
    local value, ref, text, flag, float_value, nil_value = bounce(i)
    total = total + value
    last_ref = ref
    last_text = text
    last_bool = flag
    last_float = float_value
    last_nil = nil_value
end

assert(total == 656, "mapped integer slots")
assert(shared.count == 32 and last_ref == shared, "mapped reference slots")
assert(last_text == "mapped", "mapped string handle")
assert(last_bool == true, "mapped boolean metadata")
assert(last_float == 3.25, "mapped float handle")
assert(last_nil == nil, "mapped nil metadata")

print("vm dynamic register mapping ok", total, shared.count)
