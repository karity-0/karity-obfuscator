(function(f,s)
local d=string.dump(f,s)
if string.byte(d,6)==0 then return d end
assert(d:sub(1,6)=="\27Lua\83\2","Unsupported runtime dump format")
assert(d:sub(21,25)==string.char(4,8,4,8,8),"Unsupported runtime dump layout")
local seed=string.unpack("<I8",d,7)
local p=42
local out={d:sub(1,5).."\0"..d:sub(15,41)}
local function take(n)
assert(n>=0 and n<=#d-p+1,"Truncated runtime dump")
local bytes={}
for i=0,n-1 do
local key=(i%8==0) and 206 or ((seed>>(i%14))&255)
bytes[i+1]=string.char(string.byte(d,p+i)~key)
end
p=p+n
return table.concat(bytes)
end
local function put(n)
local v=take(n)
out[#out+1]=v
return v
end
local function count()
return string.unpack("<I4",put(4))
end
local function str()
local n=string.byte(put(1))
if n==255 then n=string.unpack("<I8",put(8)) end
if n>0 then put(n-1) end
end
local function proto()
str()
put(4);put(4);put(1);put(1);put(1)
local n=count()
local code=take(n*4)
local words={}
for i=0,n-1 do
local v=string.unpack("<I4",code,1+i*4)
words[i+1]=string.pack("<I4",(v-i%4)&0xffffffff)
end
out[#out+1]=table.concat(words)
for i=1,count() do
local tag=string.byte(put(1))
if tag==1 then put(1)
elseif tag==3 then put(8)
elseif tag==19 then
local v=string.unpack("<i8",take(8))
out[#out+1]=string.pack("<i8",v-8)
elseif tag==4 or tag==20 then str()
else assert(tag==0,"Unsupported runtime constant") end
end
for i=1,count() do put(1);put(1) end
for i=1,count() do proto() end
put(count()*4)
for i=1,count() do str();put(4);put(4) end
for i=1,count() do str() end
end
put(1)
proto()
assert(p==#d+1,"Unexpected runtime dump tail")
return table.concat(out)
end)
