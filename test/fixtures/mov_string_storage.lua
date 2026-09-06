local function retained(a,b)
    local value=a..b
    local old=string.char
    string.char=function() error("premature native string materialization") end
    local first=#value
    local joined=value..value
    local second=#joined
    string.char=old
    assert(first==3 and second==6)
    return value,joined
end
local original,joined=retained("a\0","b")
assert(original=="a\0b" and joined=="a\0ba\0b")
print("string storage ok")
