assert(os.setlocale("C","collate"))
local function compare(a,b)
    return a==b,a~=b,a<b,a<=b,a>b,a>=b
end
local values={"","a","aa","ab","b","A","0","1","10","2",
              "\0","\0\0","\0a","a\0","a\0b","a\0a",
              "\127","\128","\255","\255\0"}
for _,a in ipairs(values) do
    for _,b in ipairs(values) do print(compare(a,b)) end
end
local bytes={}
for i=0,255 do bytes[#bytes+1]=string.char(i) end
local all=table.concat(bytes)
for i=0,255 do
    print(compare(string.char(i),string.char((i+1)%256)))
    print(compare(all,string.sub(all,1,i)))
end
local prefix=string.rep("same\0prefix",256)
print(compare(prefix.."a",prefix.."b"))
print(compare(prefix,prefix.."\0"))
print(compare(prefix,prefix))
-- Force the non-C query path without requiring optional locale packages.
local real=os.setlocale
_G.__mov_host_order_seen=false
os.setlocale=function(locale,category)
    if locale==nil and category=="collate" then return "test-non-C" end
    return real(locale,category)
end
print("other collation",compare("a\0b","a\0c"))
if _G.__mov_order_test then assert(_G.__mov_host_order_seen) end
os.setlocale=real
print("restored",compare("a\0b","a\0c"))
os.setlocale=nil
_G.__mov_host_order_seen=false
print("no query",compare("aa","ab"))
if _G.__mov_order_test then assert(_G.__mov_host_order_seen) end
os.setlocale=false
print("noncallable query",compare("aa","ab"))
os.setlocale=real
local library=os
os=1
print("no library",compare("aa","ab"))
os=library
local mt={__eq=function() return true end,__lt=function() return true end,
          __le=function() return false end}
print("objects",compare(setmetatable({},mt),setmetatable({},mt)))
print("mixed equality","1"==1,""==nil)
local ok=pcall(function() return "1"<1 end)
assert(not ok)
