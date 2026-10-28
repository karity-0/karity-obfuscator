_PG=(function()
 local specs=__PROGRAM_MANIFEST__
 local header=__PROGRAM_HEADER__
 local kind,raw,meta,call,next0,floor=type,rawget,getmetatable,pcall,next,math.floor
 local decoder,mask=decode,_ksm
 local reject=_PS.program_error
 local mask_seed
 local seals={}
 local ids=setmetatable({},{__mode='k'})
 local constant_ids=setmetatable({},{__mode='k'})
 local objects=setmetatable({},{__mode='v'})
 local cursor,ready,initializing=0,false,false
 local string_spec={CK_STR}
 local function table0(t)
  if kind(t)~='table' or meta(t)~=nil then error(nil,0) end
  return t
 end
 local function add(h,v)
  if kind(v)~='number' or v<0 or v>4294967295 or v%1~=0 then error(nil,0) end
  return (h*65599+v)%2147483647
 end
 --<<PROGRAM_NUMBER_WORDS>>
 local function valid_value(spec,value)
  if spec[1]==CK_STR then return true end
  local h=spec[2]
  if spec[1]==CK_NIL then if value~=nil then return false end
  elseif spec[1]==CK_BOOL then
   if kind(value)~='boolean' then return false end
   h=(h*65599+(value and 1 or 0))%2147483647
  else
   if kind(value)~='number' then return false end
   --<<PROGRAM_NUMBER_TYPE>>
   local lo,hi=words(value,spec[5]==1)
   return (lo+spec[2])%4294967296==spec[3]
    and (hi+spec[2]*65599%4294967296)%4294967296==spec[4]
  end
  return h==spec[3]
 end
 local function constant(p,k)
  local id=ids[p];local record=constant_ids[k]
  if not id or not record or record[1]~=id then return nil end
  local spec=specs[id][__PROGRAM_SPEC_CONSTANTS__][record[2]];table0(k)
  if spec==0 then spec=string_spec end
  if raw(table0(raw(p,'constants')),record[2])~=k or raw(k,1)~=spec[1] then return nil end
  return spec
 end
 local function valid_encoded(p,k,spec)
  local mix=_ieval(table0(raw(k,3)),p)
  -- Derive the expected encoded word from independently masked build shares.
  -- The original integer is never combined for this integrity-only path.
  local lo=_ixor(_ixor(spec[4],mix),spec[2])
  local hi=_ixor(spec[5],spec[3])
  --<<PROGRAM_ENCODED_WORD>>
 end
 local function digest(p,id,all_constants)
  if _IT.seed~=header[1] or _IT.layout~=header[2] or _IT.vmc~=header[3] then return false end
  if decode~=decoder or _ksm~=mask or _ksd~=mask_seed then return false end
  local spec=specs[id];table0(p)
  local words=table0(raw(p,'code'));local constants=table0(raw(p,'constants'))
  local captures=table0(raw(p,'upvalues'));local children=table0(raw(p,'protos'))
  if #words~=spec[__PROGRAM_SPEC_CODE_COUNT__] or #constants~=spec[__PROGRAM_SPEC_CONSTANT_COUNT__]
   or #captures~=spec[__PROGRAM_SPEC_CAPTURE_COUNT__] or #children~=#spec[__PROGRAM_SPEC_CHILDREN__] then return false end
  local shape=spec[__PROGRAM_SPEC_HEADER__]
  if raw(p,'num_params')~=shape[1] or raw(p,'is_vararg')~=shape[2]
   or raw(p,'max_stack_size')~=shape[3] or raw(p,'vm_id')~=shape[4] then return false end
  if all_constants then
   for i=1,#constants do local k=raw(constants,i);local cs=constant(p,k)
    if not cs then return false end
    if cs[1]==CK_IEXPR then
     if not valid_encoded(p,k,cs) then return false end
    elseif cs[1]~=CK_STR and not valid_value(cs,_program_kval(k,p)) then return false end
   end
  end
  local h=spec[__PROGRAM_SPEC_CODE_SEED__];local sealed=h
  local av=table0(raw(p,'avalanche'));local graph=table0(raw(p,'graph_sites'))
  local g=spec[__PROGRAM_SPEC_LAYOUT_SEED__]
  local empty=spec[__PROGRAM_SPEC_EMPTY_METADATA__]>=0 and next0(av)==nil and next0(graph)==nil
  if empty then g=spec[__PROGRAM_SPEC_EMPTY_METADATA__] end
  for i=1,#words do
   local word=raw(words,i)
   if kind(word)~='number' or word<0 or word>=281474976710656 or word%1~=0 then return false end
   sealed=((sealed*65599+word%16777216)%2147483647*65599+floor(word/16777216))%2147483647
   if initializing then
    local op,a,b,c=decoder(word,mask(i))
    h=((((h*65599+op)%2147483647*65599+a)%2147483647*65599+b)%2147483647*65599+c)%2147483647
   end
   if not empty then
   local list=raw(av,i)
   if list then table0(list);g=add(g,#list);for j=1,#list do g=add(g,raw(list,j)) end
   else g=g*65599%2147483647 end
   list=raw(graph,i)
   if list then
    table0(list);g=add(g,#list)
    for j=1,#list do local record=table0(raw(list,j))
     if #record~=5 then return false end
     for k=1,5 do g=add(g,raw(record,k)) end
    end
   else g=g*65599%2147483647 end
   end
  end
  if (initializing and h~=spec[__PROGRAM_SPEC_CODE_TAG__]) or (not initializing and sealed~=seals[id]) then return false end
  local routes=table0(raw(p,'block_routes'));g=add(g,#routes)
  for i=1,#routes do local route=table0(raw(routes,i));g=add(g,#route)
   for j=1,#route do g=add(g,raw(route,j)) end
  end
  for i=1,#captures do local capture=table0(raw(captures,i))
   g=add(g,raw(capture,'instack'));g=add(g,raw(capture,'idx'))
  end
  for i=1,#children do
   local child=raw(children,i)
   if ids[child]~=spec[__PROGRAM_SPEC_CHILDREN__][i] then return false end
   g=add(g,ids[child])
  end
  g=add(g,spec[__PROGRAM_SPEC_MOV_ENTRIES__])
  if spec[__PROGRAM_SPEC_MOV_ENTRIES__]>0 then local entries=table0(raw(p,'mov_entries'))
   if #entries~=spec[__PROGRAM_SPEC_MOV_ENTRIES__] then return false end
   for i=1,#entries do g=add(g,raw(entries,i)) end
  end
  return g==spec[__PROGRAM_SPEC_LAYOUT_TAG__],sealed
 end
 local function checked(p,all_constants)
  local id=ids[p]
  if not id then return false end
  local ok,result,sealed=call(digest,p,id,all_constants)
  if initializing and ok and result==true then seals[id]=sealed end
  return ok and result==true
 end
 local out={}
 --<<PROGRAM_MOV_DECL>>
 function out.initialize(root,kits)
  if ready then reject() end
  local n=0
  local function attach(p)
   table0(p);n=n+1
   if n>#specs or ids[p] then error(nil,0) end
   ids[p]=n;objects[n]=p
   local constants=table0(raw(p,'constants'))
   if #constants~=specs[n][__PROGRAM_SPEC_CONSTANT_COUNT__] then error(nil,0) end
   for i=1,#constants do local k=table0(raw(constants,i))
    if constant_ids[k] then error(nil,0) end
    constant_ids[k]={n,i}
   end
   local children=table0(raw(p,'protos'))
   if #children~=#specs[n][__PROGRAM_SPEC_CHILDREN__] then error(nil,0) end
   for i=1,#children do attach(raw(children,i)) end
  end
  local ok=call(attach,root)
  if not ok or n~=#specs then reject() end
  ready=true;initializing=true;mask_seed=_ksd
  --<<PROGRAM_MOV_INIT>>
  -- Use the existing latched guard to reject; do not add a second error latch.
  for i=1,n do _PS_GUARD(false,objects[i]) end
  initializing=false
 end
 function out.check(p)return ready and checked(p,initializing) --<<PROGRAM_MOV_ENTRY>>
 end
 local function restore(p,k,resolver)
  local spec=constant(p,k)
  if not spec then return false end
  if spec[1]==CK_IEXPR then
   local valid,mix=valid_encoded(p,k,spec)
   if not valid then return false end
   return true,resolver(k,p,mix)
  end
  local value=resolver(k,p)
  return valid_value(spec,value),value
 end
 function out.value(p,k,resolver)
  local success,result,value=call(restore,p,k,resolver)
  if not success or result~=true then reject() end
  return value
 end
 local function encoded(p,k)
  local spec=constant(p,k)
  return spec and spec[1]==CK_IEXPR and valid_encoded(p,k,spec)
 end
 function out.encoded(p,k)
  local ok,valid=call(encoded,p,k)
  if not ok or valid~=true then reject() end
  return raw(k,2)
 end
 function out.poll()
  if not ready then return true end
  cursor=cursor%(#specs+__PROGRAM_EXTRA_COUNT__)+1
  --<<PROGRAM_MOV_POLL>>
  local p=objects[cursor]
  return p==nil or checked(p,true)
 end
 out.words=words
 return out
end)()
