function(o,kind)
 if kind(o)~='table' or kind(o[1])~='table' or kind(o[2])~='table' or #o[2]~=9
  or kind(o[24])~='table' or kind(o[3])~='function' or kind(o[8])~='function'
  or kind(o[12])~='thread' or kind(o[13])~='function' then return false end
 local rules={__PROBE_MATCH_RULES__}
 local anchor=o[1]
 if anchor[1]~='table' or anchor[__PROBE_FUNC_TYPE__]~='function'
  or anchor[__PROBE_FUNC_VALUE__]~=o[2][__PROBE_PCALL_INDEX__][2] then return false end
 for i=1,9 do
  local record=o[2][i];local a=record[3]
  if record[1]~='function' or kind(record[2])~='function' or a[1]~='table'
   or a[__PROBE_FUNC_TYPE__]~='function' or a[__PROBE_FUNC_VALUE__]~=record[2]
   or a[__PROBE_WHAT_VALUE__]~='C' then return false end
  for j=1,5 do local rule=rules[j];local t,v=rule[1],rule[2]
   if a[t]~=rule[3] or anchor[t]~=rule[3] or a[v]~=anchor[v] then return false end
  end
 end
 local pairs={{o[4],o[5],o[3],true},{o[5],o[6],o[3],false},
  {o[9],o[10],o[8],true},{o[9],o[11],o[8],true}}
 for i=1,4 do local pair=pairs[i];local a,b,fn=pair[1],pair[2],pair[3]
  if a[1]~='table' or b[1]~='table' or a[__PROBE_FUNC_TYPE__]~='function'
   or b[__PROBE_FUNC_TYPE__]~='function' or a[__PROBE_FUNC_VALUE__]~=fn
   or b[__PROBE_FUNC_VALUE__]~=fn or a[__PROBE_WHAT_VALUE__]~='Lua' then return false end
  for j=1,5 do local rule=rules[j];local t,v=rule[1],rule[2]
   if a[t]~=rule[3] or b[t]~=rule[3] or a[v]~=b[v] then return false end
  end
  if pair[4] then
   local x,y=a[__PROBE_NUPS_VALUE__],b[__PROBE_NUPS_VALUE__]
   if a[__PROBE_NUPS_TYPE__]~='number' or b[__PROBE_NUPS_TYPE__]~='number'
    or x~=y or x<0 or (x/1)%1~=0 then return false end
   if __PROBE_REQUIRE_PARAMS__ or a[__PROBE_NPARAMS_TYPE__]~='nil' or b[__PROBE_NPARAMS_TYPE__]~='nil' then
    x,y=a[__PROBE_NPARAMS_VALUE__],b[__PROBE_NPARAMS_VALUE__]
    if a[__PROBE_NPARAMS_TYPE__]~='number' or b[__PROBE_NPARAMS_TYPE__]~='number'
     or x~=y or x<0 or (x/1)%1~=0 then return false end
   end
   if __PROBE_REQUIRE_PARAMS__ or a[__PROBE_ISVARARG_TYPE__]~='nil' or b[__PROBE_ISVARARG_TYPE__]~='nil' then
    if a[__PROBE_ISVARARG_TYPE__]~='boolean' or b[__PROBE_ISVARARG_TYPE__]~='boolean'
     or a[__PROBE_ISVARARG_VALUE__]~=b[__PROBE_ISVARARG_VALUE__] then return false end
   end
  end
 end
 local identity=o[7]
 if identity[1]~='table' or identity[__PROBE_FUNC_TYPE__]~='function'
  or identity[__PROBE_FUNC_VALUE__]~=o[3] then return false end
 local clean={__PROBE_CLEAN_SLOTS__}
 for i=1,5 do local h=o[clean[i]]
  if h[1]~='nil' or not (h[3]=='nil' or (h[3]=='string' and h[4]==''))
   or not (h[5]=='nil' or (h[5]=='number' and h[6]==0)) then return false end
 end
 local installed={__PROBE_INSTALLED_SLOTS__};local masks={__PROBE_MASK_FIRST__,__PROBE_MASK_LAST__}
 local intervals={__PROBE_INTERVAL_FIRST__,__PROBE_INTERVAL_LAST__}
 for i=1,2 do local h=o[installed[i]]
  if h[1]~='function' or h[2]~=o[13] or h[3]~='string' or h[4]~=masks[i]
   or h[5]~='number' or h[6]~=intervals[i] then return false end
 end
 local resumed={__PROBE_RESUMED_SLOTS__};local values={__PROBE_RESULT_FIRST__,__PROBE_RESULT_QUIET__,__PROBE_RESULT_LAST__}
 local statuses={'suspended','suspended','dead'}
 for i=1,3 do local r=o[resumed[i]]
  if r[1]~='boolean' or r[2]~=true or r[3]~='number' or r[4]~=values[i]
   or r[5]~='string' or r[6]~=statuses[i] then return false end
 end
 local first,last=0,0
 for i=1,#o[24] do local event=o[24][i]
  if event[2]~='string' or event[4]~='thread' or event[5]~=o[12]
   or kind(event[6])~='number' or event[6]<1 or (event[6]/1)%1~=0 then return false end
  if event[1]==__PROBE_MODE_FIRST__ and event[3]==__PROBE_EVENT_FIRST__ then first=first+event[6]
  elseif event[1]==__PROBE_MODE_LAST__ and event[3]==__PROBE_EVENT_LAST__ then last=last+event[6]
  else return false end
 end
 return first>0 and last>0
end
