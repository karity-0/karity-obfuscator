local function double_add(value)
    local pending = value + value
    return pending + pending
end

assert(double_add(11) == 44, "same pending register as both deferred operands")
print(double_add(11))
