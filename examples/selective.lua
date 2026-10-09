local secret = STRING_OBF("secret")
local limit = NUMBER_OBF(123)
local enabled = BOOLEAN_OBF(true)
local values = TABLE_OBF({1, 2, 3})
local counter = 0

-- @FUNCTION_OBF(cff, wrapper, junk=false, nested=false)
local function check(value)
    local result = value + 1
    if result > limit then result = result * 2 end
    return result
end

local function partial(value, ...)
    local fast = value + 1
    -- @FUNCTION_OBF_START(cff, junk=false)
    local result = fast * 3
    if result > limit then return result, ... end
    -- @FUNCTION_OBF_END
    return result
end

-- @VM_START(profile="fast-vm")
local function protected(amount)
    counter = counter + amount
    -- @NO_VM_START
    counter = counter + 1
    -- @NO_VM_END
    return secret, counter
end
-- @VM_END

local function hot_path()
    counter = counter + 1
end

-- @NO_OBF_START
local readable = "plain text"
-- @NO_OBF_END

hot_path()
print(enabled, values[2], check(10), readable)
print(protected(3))
print(partial(5))

-- @VM_START(profile="fast-vm")
local computed = counter * 2
counter = computed + 1
-- @VM_END
print(computed, counter)
