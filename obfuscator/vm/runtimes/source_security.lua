return function(P,self,payload,line)
 local E,raw,kind,throw,next0=P[1],P[2],P[3],P[4],P[5]
 local N,_ENV_CHECK,_ENV_REFRESH=P[11],P[12],P[13]
 local failed,ticks=false,0
 local function fail() failed=true;throw(nil,0);local n=nil;return n[n] end
 local A=__API__
 local hook0=A.hook
 local bindings=__BARE_NATIVE_BINDINGS__
 local S={}
 local trusted={}
 __SHARED_INSPECTOR__
 function S.guard(force) if not S.inspect(force) then fail() end end
 S.fail=fail
--<<write>>
 function S.write(t,k,v)
  _ENV_REFRESH(t,false);t[k]=v;_ENV_REFRESH(t,true)
  for i=1,#bindings do local b=bindings[i];if b[1]==t and b[2]==k then b[3]=t[k] end end
 end
--<<ENDwrite>>
--<<global_get>>
 local getfenv0=getfenv
 function S.global_get(k) return getfenv0(2)[k] end
--<<ENDglobal_get>>
--<<global_set>>
 function S.global_set(k,v) S.write(getfenv0(2),k,v) end
--<<ENDglobal_set>>
--<<setmeta>>
 local setmeta0=setmetatable
 function S.setmeta(t,m)
  _ENV_REFRESH(t,false);local value=setmeta0(t,m);_ENV_REFRESH(t,true);return value
 end
--<<ENDsetmeta>>
 local function isC(f)
  local ok,info=A.pcall(A.info,f,'S')
  return ok and info and info.what=='C'
 end
 for i=1,#bindings do local b=bindings[i]
  if kind(b[3])=='function' and not isC(b[3]) then fail() end
 end
 S.guard(true)
 local xor=P[9]
 local script=xor(P[8](P[7](self)),line)
 local M=2147483647
 local function key(seed) return (seed+script%M+(line%M)*17)%(M-1)+1 end
 local cache,expected={},{}
 local digits={};local alphabet=__ALPHABET__
 for i=1,16 do digits[A.byte(alphabet,i)]=i-1 end
 if kind(payload)~='string' or #payload%2~=0 then fail() end
 local size=#payload/2
 local function byte(i)
  local a,b=digits[A.byte(payload,i*2-1)],digits[A.byte(payload,i*2)]
  if a==nil or b==nil then fail() end
  return a*16+b
 end
 local function u32(i) return byte(i)+byte(i+1)*256+byte(i+2)*65536+byte(i+3)*16777216 end
 function S.constant(index)
  if failed then fail() end
  local c=cache[index]
  if c then if kind(c)~='table' or c[1]~=expected[index] then fail() end;return c[1] end
  local position=xor(index,__INDEX_MASK__)
  if position<1 or position>size then fail() end
  local tag=byte(position)
  local value
  if tag==__TNUMBER__ then
   if position+16>size then fail() end
   local seed=u32(position+1)
   if seed<1 or seed>=M then fail() end
   local k=key(seed);local lo,hi=u32(position+5),u32(position+9)
   if hi>=2147483648 then hi=hi-4294967296 end
   local encoded=lo+hi*4294967296
   if u32(position+13)~=(encoded%M+k*257)%M then fail() end
   value=encoded+k
--<<string>>
  elseif tag==__TSTRING__ then
   local length=u32(position+1);local base=position+5
   if length<8 or base+length-1>size then fail() end
   local seed,tag=u32(base),u32(base+4)
   if seed<=0 or seed>=M then fail() end
   local state=key(seed);local h=(state+length-8)%M
   for i=base+8,base+length-1 do h=(xor(h,byte(i))*65599)%M end
   if h~=tag then fail() end
   local out,chunks={},{}
   for i=base+8,base+length-1 do
    state=state*48271%M;out[#out+1]=A.char((byte(i)-state%251-1)%256)
    if #out==4096 then chunks[#chunks+1]=A.concat(out);out={} end
   end
   if #out>0 then chunks[#chunks+1]=A.concat(out) end
   value=A.concat(chunks)
--<<ENDstring>>
  else fail() end
  cache[index]={value};expected[index]=value
  return value
 end
--<<script_hash>>
 function S.script_hash() return script end
--<<ENDscript_hash>>
 for name,value in next0,S do if kind(value)=='function' then trusted[#trusted+1]={S,name,value} end end
 for name,value in next0,A do trusted[#trusted+1]={A,name,value} end
 for name,value in next0,P do trusted[#trusted+1]={P,name,value} end
 for name,value in next0,_BCore do trusted[#trusted+1]={_BCore,name,value} end
 if S.constant(__SENTINEL_SLOT__)~=__SENTINEL__ then fail() end
 S.guard(true)
 return S,function(g)
  S.guard=g
  for i=1,#trusted do local b=trusted[i];if b[1]==S and b[2]==__GUARD_SLOT__ then b[3]=g end end
 end
end
