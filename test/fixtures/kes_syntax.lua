-- Strings, comments, long strings and protection macros remain ordinary Lua.
local untouched = [=[a += 1; continue; nil ?? 8; t?.x; a ? b : c; 0b1_0]=]
assert(untouched:find('??',1,true)) -- ??= ?. += continue
local n = 0b10_10 + 1_000 + 0xF_F
assert(n == 1265)
assert(0b1111111111111111111111111111111111111111111111111111111111111111 == 0xffffffffffffffff)
assert(1_2.5_0e+1_0 == 12.5e10)
local __kes_1,__kes_2=7,8
local collision=nil ?? 9
assert(__kes_1==7 and __kes_2==8 and collision==9)
local a=3
a+=2; a-=1; a*=3; a/=2; a%=5; a^=2
assert(a==1)
local text='a'; text..='b'; assert(text=='ab')
local trace={}
local function log(s) trace[#trace+1]=s end
local backing={x=4}
local proxy=setmetatable({}, {
  __index=function(_,k) log('get:'..k);return backing[k] end,
  __newindex=function(_,k,v) log('set:'..k);backing[k]=v end,
})
local function receiver() log('receiver');return proxy end
local function key() log('key');return 'x' end
local function rhs() log('rhs');return 5 end
receiver()[key()] += rhs()
assert(backing.x==9)
assert(table.concat(trace,',')=='receiver,key,get:x,rhs,set:x')
trace={};receiver()[key()] ??= rhs()
assert(table.concat(trace,',')=='receiver,key,get:x')
backing.x=nil;trace={};receiver()[key()] ??= rhs()
assert(backing.x==5 and table.concat(trace,',')=='receiver,key,get:x,rhs,set:x')
local mt={__add=function(x,y) return {n=x.n+y} end}
local obj=setmetatable({n=4},mt);obj+=3;assert(obj.n==7)
local function fail() error('unexpected evaluation') end
assert((false ?? fail())==false)
assert((0 ?? fail())==0)
local nan=0/0;local kept=nan ?? fail();assert(kept~=kept)
assert((nil ?? 7)==7)
assert((nil ?? nil ?? 8)==8)
assert((false or nil ?? 9)==9)
assert((true ? false : fail())==false)
assert((false ? fail() : nil)==nil)
local function one() return 1,2 end
local function two() return 2,3 end
assert((true ? one() : two())==1)
assert((false ? one() : two())==2)
assert((true ? false ? 1 : 2 : 3)==2)
assert((nil ?? false ? 1 : 2)==2)
local methods={a=function() return 41 end,b=function() return 42 end}
assert((true ? methods:a() : methods:b())==41)
local function getmethods()return methods end
assert((false ? methods:a() : getmethods():b())==42)
local user=nil
assert(user?.profile?.name==nil)
user={profile={name=false}}
assert(user?.profile?.name==false)
assert(not pcall(function()local x=false;return x?.field end))
assert(not pcall(function()local x=0;return x?.field end))
local count=0
local function getuser() count+=1;return user end
assert(getuser()?.profile?.name==false and count==1)
local function arity(...) return select('#',...) end
assert(arity(nil ?? one())==1)
assert(arity(true ? one() : two())==1)
assert(arity(user?.profile)==1)
local function va(...)
  return (... ?? 4), (true ? select(2,...) : fail()), arity(...)
end
local x,y,z=va(nil,false,nil)
assert(x==4 and y==false and z==3)
local numbers={}
for i=1,6 do
  if i%2==0 then continue end
  if i==5 then break end
  numbers[#numbers+1]=i
end
assert(table.concat(numbers,',')=='1,3')
local sum=0
for _,v in ipairs({1,2,3,4}) do
  if v==2 then continue end
  for j=1,3 do
    if j==2 then continue end
    sum+=v*j
  end
end
assert(sum==32)
local i=0;sum=0
while i<4 do
  i+=1
  if i==2 then continue end
  sum+=i
end
assert(sum==8)
local checks=0
local function condition(value) checks+=1;return value==3 end
i=0
repeat
  i+=1
  if i<3 then continue end
  local value=i
until condition(value)
assert(i==3 and checks==3)
local outer=7;local captured={};i=0
repeat
  i+=1
  local outer=outer+i
  local function get() return outer end
  captured[i]=get
  outer+=1
  if i<3 then continue end
until outer>=11
assert(captured[1]()==9 and captured[2]()==10 and captured[3]()==11)
if _VERSION=='Lua 5.3' then
  local attempts=0
  repeat
    attempts+=1
    local _ENV=setmetatable({step_value=attempts},{__index=_G})
    if attempts<2 then continue end
    step_value+=1
  until step_value==3
  assert(attempts==2)
end
local function returns()
  for j=1,4 do
    if j<3 then continue end
    return j,nil,false
  end
end
x,y,z=returns();assert(x==3 and y==nil and z==false)
local co=coroutine.create(function()
  local result=0
  for j=1,3 do
    if j==2 then continue end
    result += (coroutine.yield(j) ?? 0)
  end
  return result
end)
local ok,v=coroutine.resume(co);assert(ok and v==1)
ok,v=coroutine.resume(co,10);assert(ok and v==3)
ok,v=coroutine.resume(co,20);assert(ok and v==30)
print('kes-syntax-ok',n,sum,checks)
