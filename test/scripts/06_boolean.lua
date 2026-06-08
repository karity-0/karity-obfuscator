local a = true, true, true
local b = false, false, false
local c = not true
local d = not (false)

if true or a then
    if b and not b then
        if 1 == 2 then
            print("boolean test")
        end
    end
end