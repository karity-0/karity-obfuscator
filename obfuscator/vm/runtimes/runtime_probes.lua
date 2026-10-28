do
 local native=__PROBE_NATIVE__
 local D,C=native.debug,native.coroutine
 if kind(D)~='table' or kind(C)~='table' then fail() end
 local Q={info=A.info,hook=A.hook,pcall=pcall,sethook=D.sethook,
  create=C.create,resume=C.resume,yield=C.yield,status=C.status,running=C.running}
 local functions={__PROBE_API_ORDER__}
 if kind(Q.pcall)~='function' or kind(Q.info)~='function' then fail() end
 local fields={__PROBE_INFO_FIELDS__}
 -- Source text can be the entire loaded VM. Canonical IDs preserve exact
 -- string equality without encrypting/comparing that public text inside the VM.
 -- Lua table keys resolve collisions by equality; these are not lossy hashes.
 local sources,source_count={},0
 local function describe(info)
  local record={kind(info)}
  if kind(info)=='table' then
   for i=1,#fields do
    local field=fields[i];local value=raw(info,field);local tag=kind(value)
    if tag=='string' and (field=='source' or field=='short_src') then
     local id=sources[value]
     if id==nil then source_count=source_count+1;id=source_count;sources[value]=id end
     value=id
    end
    record[2*i]=tag;record[2*i+1]=value
   end
  end
  return record
 end
 local function hook_record(h,m,c)return {kind(h),h,kind(m),m,kind(c),c} end
 local observations={}
 local anchor_ok,anchor=Q.pcall(Q.info,Q.pcall,__PROBE_SHORT_OPTIONS__)
 if not anchor_ok or kind(anchor)~='table' then fail() end
 observations[1]=describe(anchor);observations[2]={}
 -- Basic C/API prerequisites remain native before using the bootstrap APIs.
 -- Function identity and cross-query metadata decisions belong to the IR verifier.
 for i=1,9 do local fn=functions[i]
  if kind(fn)~='function' then fail() end
  local ok,info=Q.pcall(Q.info,fn,__PROBE_SHORT_OPTIONS__)
  if not ok or kind(info)~='table' or raw(info,'what')~='C' then fail() end
  observations[2][i]={kind(fn),fn,describe(info)}
 end
 local function clean(h,m,c)
  return h==nil and (m==nil or (kind(m)=='string' and #m==0))
   and (c==nil or (kind(c)=='number' and c==0))
 end
 local ok0,h0,m0,c0=Q.pcall(Q.hook)
 -- Never touch an existing caller hook or an already hooked foreign thread.
 if not ok0 or not clean(h0,m0,c0) then fail() end
 observations[14]=hook_record(h0,m0,c0)
 local thread,touched
 local function sample_info()
  local info=Q.info(1,__PROBE_FULL_OPTIONS__)
  return sample_info,info
 end
 local ok=Q.pcall(function()
  local fn,stack=sample_info()
  observations[3]=fn;observations[4]=describe(stack)
  observations[5]=describe(Q.info(fn,__PROBE_FULL_OPTIONS__))
  observations[6]=describe(Q.info(fn,__PROBE_SHORT_OPTIONS__))
  observations[7]=describe(Q.info(fn,'f'))
  local function worker()
   __PROBE_WORKER__
  end
  thread=Q.create(worker)
  if kind(thread)~='thread' or same(thread,Q.running()) or Q.status(thread)~='suspended' then fail() end
  local h,m,c=Q.hook(thread)
  if not clean(h,m,c) then fail() end
  observations[8]=worker;observations[9]=describe(Q.info(worker,__PROBE_FULL_OPTIONS__))
  observations[10]=describe(Q.info(thread,worker,__PROBE_FULL_OPTIONS__))
  observations[12]=thread;observations[15]=hook_record(h,m,c)
  local mode=__PROBE_IDLE__
  local events,index,nil_key={},{},{}
  local function hook(event)
   local running=Q.running()
   -- Aggregate observations by phase/event/thread, without a native verdict.
   local group=index[mode];if not group then group={};index[mode]=group end
   local event_key=event or nil_key
   local threads=group[event_key];if not threads then threads={};group[event_key]=threads end
   local thread_key=running or nil_key
   local bucket=threads[thread_key]
   if not bucket then
    bucket={mode,kind(event),event,kind(running),running,0}
    threads[thread_key]=bucket;events[#events+1]=bucket
   end
   bucket[6]=bucket[6]+1
  end
  observations[13]=hook;observations[24]=events
  touched=true;Q.sethook(thread,hook,__PROBE_MASK_FIRST__,__PROBE_INTERVAL_FIRST__)
  observations[16]=hook_record(Q.hook(thread))
  mode=__PROBE_MODE_FIRST__;local resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  local status=Q.status(thread)
  observations[17]={kind(resumed),resumed,kind(value),value,kind(status),status}
  local level=0;observations[11]=describe(nil)
  while level<64 do
   local info=Q.info(thread,level,__PROBE_FULL_OPTIONS__)
   if info==nil then break end
   if kind(info)~='table' then break end
   if same(raw(info,'func'),worker) then observations[11]=describe(info);break end
   level=level+1
  end
  Q.sethook(thread);observations[18]=hook_record(Q.hook(thread))
  mode=__PROBE_QUIET__;resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  status=Q.status(thread)
  observations[19]={kind(resumed),resumed,kind(value),value,kind(status),status}
  Q.sethook(thread,hook,__PROBE_MASK_LAST__,__PROBE_INTERVAL_LAST__)
  observations[20]=hook_record(Q.hook(thread))
  mode=__PROBE_MODE_LAST__;resumed,value=Q.resume(thread);mode=__PROBE_IDLE__
  status=Q.status(thread)
  observations[21]={kind(resumed),resumed,kind(value),value,kind(status),status}
 end)
 local cleared,read,h,m,c=true,true
 if touched then
  cleared=Q.pcall(Q.sethook,thread)
  read,h,m,c=Q.pcall(Q.hook,thread)
 end
 -- Cleanup failure is an operational bootstrap failure, not an IR success flag.
 if not ok or not cleared or not read or not clean(h,m,c) then fail() end
 observations[22]=hook_record(h,m,c);observations[23]=hook_record(Q.hook())
 local records={{D,'sethook',Q.sethook},{C,'create',Q.create},{C,'resume',Q.resume},
  {C,'yield',Q.yield},{C,'status',Q.status},{C,'running',Q.running},{native,'coroutine',C}}
 for i=1,#records do local r=records[i]
  if not same(r[1][r[2]],r[3]) then fail() end
  periodic[#periodic+1]=r;binding_owners[r[1]]=true
 end
 __PROBE_PUBLISH__
end
