local function length(s) return #s end
for _,n in ipairs({0,1,15,16,17,255,256,257,4095,4096,4097}) do
    local s=string.rep("\0",n)
    local count=length(s)
    assert(count==n and math.type(count)=="integer")
    print("length",count)
end
local function join(a,b,c) return a..b..c end
local function alias(a,b)
    local result=a..b
    local saved=result
    result=result.."\0tail"
    assert(#saved==#a+#b and #result==#saved+5)
    return saved,result
end
for _,a in ipairs({"","x","\0","\255\0"}) do
    for _,b in ipairs({"","y","\0","\128"}) do
        local result=join(a,b,"")
        assert(result==table.concat({a,b}) and #result==#a+#b)
        local saved,changed=alias(a,b)
        assert(saved==result and changed==table.concat({a,b,"\0tail"}))
        print("join",#result,#changed)
    end
end
-- Reusing the destination for another representation must drop the old cache.
local function reuse(a,b)
    local value=a..b
    local before=#value
    value=before+1
    assert(math.type(value)=="integer")
    value=join("",tostring(value),"")
    local capture=function() return value end
    value=value.."!"
    return capture()
end
assert(reuse("ab","cd")=="5!")
-- Both aliases must stay intact when a cached concatenation is concatenated.
local function chained(a,b)
    local x=a..b
    local y=x
    local z=x..x
    return x,y,z,#z
end
local x,y,z,n=chained("a\0","b")
assert(x=="a\0b" and y==x and z=="a\0ba\0b" and n==6)
print("coercion",join(12,"/",3.5))
local events={}
local mt={__concat=function(a,b) events[#events+1]="concat"; return "meta" end,
          __len=function(a) events[#events+1]="len"; return "custom-length" end}
local object=setmetatable({},mt)
assert(join("prefix",object,object)=="prefixmeta")
assert(length(object)=="custom-length")
assert(table.concat(events,",")=="concat,len")
assert(length({1,2,3})==3)
assert(not pcall(length,123))
assert(not pcall(join,{},"x","y"))
local yielding=setmetatable({}, {__concat=function(a,b)
    local resumed=coroutine.yield("concat")
    return resumed
end})
local co=coroutine.create(function() return join("a",yielding,"b") end)
local ok,value=coroutine.resume(co)
assert(ok and value=="concat")
ok,value=coroutine.resume(co,"done")
assert(ok and value=="adone")
print("string operations ok")
