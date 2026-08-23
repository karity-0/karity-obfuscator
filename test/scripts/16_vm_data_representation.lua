local total = 0
local current = 41

for i = 1, 250 do
    current = current + i
    current = current - (i - 1)
    current = -(-current)
    total = total + current
end

local object = {name = "vault", value = current}
local alias = object
local truth = true
local falsity = false
local fraction = 12.5

local function make_counter(start)
    local captured = start
    return function(delta)
        captured = captured + delta
        return captured, object, truth, falsity, fraction, nil
    end
end

local counter = make_counter(100)
local value, same, yes, no, float_value, nil_value = counter(23)

local cross_frame = object
local function replace_cross_frame()
    cross_frame = {name = "rotated", value = value}
    return cross_frame
end
local replaced = replace_cross_frame()
local after_resume = {name = "after"}

assert(current == 291, "integer rotation")
assert(total == 41625, "encoded linear arithmetic")
assert(value == 123, "captured integer")
assert(same == alias and same.value == 291, "reference handle identity")
assert(yes == true and no == false, "boolean token")
assert(float_value == 12.5, "float handle")
assert(nil_value == nil, "nil token")
assert(replaced == cross_frame and cross_frame.name == "rotated", "cross-frame handle write")
assert(after_resume.name == "after" and cross_frame.value == 123, "resumed vault counter")

print("vm data representation ok", total, value, same.name)
