do
 local native=__PROBE_NATIVE__
 local D,C=native.debug,native.coroutine
 if kind(D)~='table' or kind(C)~='table' then fail() end
 local Q={info=A.info,hook=A.hook,pcall=pcall,sethook=D.sethook,
  create=C.create,resume=C.resume,yield=C.yield,status=C.status,running=C.running}
 local functions={__PROBE_API_ORDER__}
 if kind(Q.pcall)~='function' or kind(Q.info)~='function' then fail() end
 local anchor_ok,anchor=Q.pcall(Q.info,Q.pcall,__PROBE_SHORT_OPTIONS__)
 if not anchor_ok or kind(anchor)~='table' then fail() end
 local c_fields={__PROBE_C_FIELDS__}
 for i=1,9 do
  local fn=functions[i]
  if kind(fn)~='function' then fail() end
  local ok,info=Q.pcall(Q.info,fn,__PROBE_SHORT_OPTIONS__)
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
  local fields={__PROBE_LUA_FIELDS__}
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
   if __PROBE_REQUIRE_PARAMS__ or x~=nil or y~=nil then
    if kind(x)~='number' or kind(y)~='number' or x~=y then fail() end
   end
   x,y=raw(a,'isvararg'),raw(b,'isvararg')
   if __PROBE_REQUIRE_PARAMS__ or x~=nil or y~=nil then
    if kind(x)~='boolean' or kind(y)~='boolean' or x~=y then fail() end
   end
  end
 end
 -- Native stack collector; validation decisions are kept separate for IR reuse.
 local function sample_info()
  local info=Q.info(1,__PROBE_FULL_OPTIONS__)
  return sample_info,info
 end
 local ok=Q.pcall(function()
  local fn,stack=sample_info()
  local direct=Q.info(fn,__PROBE_FULL_OPTIONS__)
  check_info(stack,direct,fn,true)
  check_info(direct,Q.info(fn,__PROBE_SHORT_OPTIONS__),fn,false)
  local identity=Q.info(fn,'f')
  if kind(identity)~='table' or not same(raw(identity,'func'),fn) then fail() end
  -- Only this private native worker executes while a probe hook is installed.
  local function worker()
   __PROBE_WORKER__
  end
  thread=Q.create(worker)
  if kind(thread)~='thread' or same(thread,Q.running()) or Q.status(thread)~='suspended' then fail() end
  if not clean(Q.hook(thread)) then fail() end
  local object_info=Q.info(worker,__PROBE_FULL_OPTIONS__)
  check_info(object_info,Q.info(thread,worker,__PROBE_FULL_OPTIONS__),worker,true)
  local mode,lines,counts,bad=__PROBE_IDLE__,0,0,false
  local function hook(event)
   if mode~=__PROBE_IDLE__ then
    if not same(Q.running(),thread) then bad=true
    elseif mode==__PROBE_LINE__ and event=='line' then lines=lines+1
    elseif mode==__PROBE_COUNT__ and event=='count' then counts=counts+1
    else bad=true end
   end
  end
  touched=true;Q.sethook(thread,hook,__PROBE_MASK_FIRST__,__PROBE_INTERVAL_FIRST__)
  local h,m,c=Q.hook(thread)
  if not same(h,hook) or m~=__PROBE_MASK_FIRST__ or c~=__PROBE_INTERVAL_FIRST__ then fail() end
  mode=__PROBE_MODE_FIRST__;local resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  if not resumed or value~=__PROBE_RESULT_FIRST__ or __PROBE_MISSING_FIRST__ or bad or Q.status(thread)~='suspended' then fail() end
  local found,level=false,0
  while level<64 do
   local info=Q.info(thread,level,__PROBE_FULL_OPTIONS__)
   if info==nil then break end
   if kind(info)~='table' then fail() end
   if same(raw(info,'func'),worker) then
    check_info(object_info,info,worker,true);found=true;break
   end
   level=level+1
  end
  if not found then fail() end
  Q.sethook(thread)
  if not clean(Q.hook(thread)) then fail() end
  mode=__PROBE_QUIET__;resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  if not resumed or value~=__PROBE_RESULT_QUIET__ or bad or Q.status(thread)~='suspended' then fail() end
  Q.sethook(thread,hook,__PROBE_MASK_LAST__,__PROBE_INTERVAL_LAST__)
  h,m,c=Q.hook(thread)
  if not same(h,hook) or m~=__PROBE_MASK_LAST__ or c~=__PROBE_INTERVAL_LAST__ then fail() end
  mode=__PROBE_MODE_LAST__;resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  if not resumed or value~=__PROBE_RESULT_LAST__ or __PROBE_MISSING_LAST__ or bad or Q.status(thread)~='dead' then fail() end
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
