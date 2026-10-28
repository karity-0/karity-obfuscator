do
 local native=__PROBE_NATIVE__
 local D,C=native.debug,native.coroutine
 if kind(D)~='table' or kind(C)~='table' then fail() end
 local Q={info=A.info,hook=A.hook,pcall=pcall,sethook=D.sethook,
  create=C.create,resume=C.resume,yield=C.yield,status=C.status,running=C.running}
 local functions={Q.info,Q.hook,Q.pcall,Q.sethook,Q.create,Q.resume,Q.yield,Q.status,Q.running}
 if kind(Q.pcall)~='function' or kind(Q.info)~='function' then fail() end
 local anchor_ok,anchor=Q.pcall(Q.info,Q.pcall,'Sf')
 if not anchor_ok or kind(anchor)~='table' then fail() end
 local c_fields={'source','short_src','linedefined','lastlinedefined'}
 for i=1,9 do
  local fn=functions[i]
  if kind(fn)~='function' then fail() end
  local ok,info=Q.pcall(Q.info,fn,'Sf')
  if not ok or kind(info)~='table' or raw(info,'what')~='C' or not same(raw(info,'func'),fn) then fail() end
  for j=1,4 do local key=c_fields[j];local x,y=raw(info,key),raw(anchor,key)
   local expected=j<=2 and 'string' or 'number'
   if kind(x)~=expected or kind(y)~=expected or x~=y then fail() end
  end
 end
 local function clean(h,m,c)
  return h==nil and (m==nil or (kind(m)=='string' and #m==0))
   and (c==nil or (kind(c)=='number' and c==0))
 end
 local ok0,h0,m0,c0=Q.pcall(Q.hook)
 if not ok0 or not clean(h0,m0,c0) then fail() end
 local thread,touched
 local function check_info(a,b,fn,upvalues)
  if kind(a)~='table' or kind(b)~='table' then fail() end
  if not same(raw(a,'func'),fn) or not same(raw(b,'func'),fn) then fail() end
  local fields={'what','source','short_src','linedefined','lastlinedefined'}
  for i=1,5 do
   local key=fields[i];local x,y=raw(a,key),raw(b,key)
   local expected=i<=3 and 'string' or 'number'
   if kind(x)~=expected or kind(y)~=expected or x~=y then fail() end
  end
  if raw(a,'what')~='Lua' then fail() end
  if upvalues then
   local x,y=raw(a,'nups'),raw(b,'nups')
   if kind(x)~='number' or kind(y)~='number' or x~=y then fail() end
   x,y=raw(a,'nparams'),raw(b,'nparams')
   if x~=nil or y~=nil then
    if kind(x)~='number' or kind(y)~='number' or x~=y then fail() end
   end
   x,y=raw(a,'isvararg'),raw(b,'isvararg')
   if x~=nil or y~=nil then
    if kind(x)~='boolean' or kind(y)~='boolean' or x~=y then fail() end
   end
  end
 end
 -- Native stack collector; validation decisions are kept separate for IR reuse.
 local function sample_info()
  local info=Q.info(1,'Suf')
  return sample_info,info
 end
 local ok=Q.pcall(function()
  local fn,stack=sample_info()
  local direct=Q.info(fn,'Suf')
  check_info(stack,direct,fn,true)
  check_info(direct,Q.info(fn,'Sf'),fn,false)
  local identity=Q.info(fn,'f')
  if kind(identity)~='table' or not same(raw(identity,'func'),fn) then fail() end
  -- Only this private native worker executes while a probe hook is installed.
  local function worker()
   local n=0
   for i=1,12 do n=n+i end
   Q.yield(31)
   for i=1,12 do n=n+i end
   Q.yield(37)
   for i=1,12 do n=n+i end
   return n
  end
  thread=Q.create(worker)
  if kind(thread)~='thread' or same(thread,Q.running()) or Q.status(thread)~='suspended' then fail() end
  if not clean(Q.hook(thread)) then fail() end
  local object_info=Q.info(worker,'Suf')
  check_info(object_info,Q.info(thread,worker,'Suf'),worker,true)
  local mode,lines,counts,bad=0,0,0,false
  local function hook(event)
   if mode~=0 then
    if not same(Q.running(),thread) then bad=true
    elseif mode==1 and event=='line' then lines=lines+1
    elseif mode==2 and event=='count' then counts=counts+1
    else bad=true end
   end
  end
  touched=true;Q.sethook(thread,hook,'l',0)
  local h,m,c=Q.hook(thread)
  if not same(h,hook) or m~='l' or c~=0 then fail() end
  mode=1;local resumed,value=Q.resume(thread);mode=0
  if not resumed or value~=31 or lines==0 or bad or Q.status(thread)~='suspended' then fail() end
  local found=false
  for level=0,3 do
   local info=Q.info(thread,level,'Suf')
   if kind(info)=='table' and same(raw(info,'func'),worker) then
    check_info(object_info,info,worker,true);found=true
   end
  end
  if not found then fail() end
  Q.sethook(thread)
  if not clean(Q.hook(thread)) then fail() end
  mode=3;resumed,value=Q.resume(thread);mode=0
  if not resumed or value~=37 or bad or Q.status(thread)~='suspended' then fail() end
  Q.sethook(thread,hook,'',1)
  h,m,c=Q.hook(thread)
  if not same(h,hook) or m~='' or c~=1 then fail() end
  mode=2;resumed,value=Q.resume(thread);mode=0
  if not resumed or value~=234 or counts==0 or bad or Q.status(thread)~='dead' then fail() end
 end)
 local cleared,read,h,m,c=true,true
 if touched then
  cleared=Q.pcall(Q.sethook,thread)
  read,h,m,c=Q.pcall(Q.hook,thread)
 end
 if not ok or not cleared or not read or not clean(h,m,c) then fail() end
 local current,a,b=Q.hook()
 if not clean(current,a,b) then fail() end
 -- New initialization-only dependencies use the existing periodic record lane.
 local records={{D,'sethook',Q.sethook},{C,'create',Q.create},{C,'resume',Q.resume},
  {C,'yield',Q.yield},{C,'status',Q.status},{C,'running',Q.running},{native,'coroutine',C}}
 for i=1,#records do local r=records[i]
  if not same(r[1][r[2]],r[3]) then fail() end
  periodic[#periodic+1]=r
  binding_owners[r[1]]=true
 end
end
