local mov_specs=__PROGRAM_MOV_MANIFEST__
local mov_objects=setmetatable({},{__mode='v'})
local alphas={}
for i=1,#mov_specs do local r=mov_specs[i];if r[1]==0 then alphas[r[2]]=i end end
local function mov_digest(index)
 local spec=mov_specs[index];local owner=table0(mov_objects[0])
 if not policy(#specs+index,0,spec) then return false end
 local kit=table0(raw(owner,spec[2]))
 if kit~=mov_objects[spec[2]] then return false end
 local h=spec[6]
 if spec[1]==0 then
  local encode=table0(raw(kit,'encode'));local decode=table0(raw(kit,'decode'))
  local nonzero=table0(raw(kit,'nonzero'));local sign=table0(raw(kit,'sign'))
  if #table0(raw(kit,'banks'))~=10 or #table0(raw(kit,'tape'))~=spec[8] then return false end
  for i=0,15 do local digit=raw(encode,i);h=add(h,digit);h=add(h,raw(decode,digit))
   local nz,sg=raw(nonzero,digit),raw(sign,digit)
   if kind(nz)~='boolean' or kind(sg)~='boolean' then return false end
   h=add(h,nz and 1 or 0);h=add(h,sg and 1 or 0)
  end
 elseif spec[1]==1 then
  local bank=table0(raw(table0(raw(kit,'banks')),spec[3]))
  local row=table0(raw(bank,spec[4]))
  for y=0,15 do local states=table0(raw(row,y))
   for carry=0,spec[5]-1 do local pair=table0(raw(states,carry))
    if #pair~=2 then return false end
    h=add(h,raw(pair,1));h=add(h,raw(pair,2))
   end
  end
 else
  local tape=table0(raw(kit,'tape'))
  if #tape~=spec[8] then return false end
  for i=spec[4],spec[4]+spec[5]-1 do local instruction=table0(raw(tape,i))
   if #instruction~=6 then return false end
   for j=1,6 do h=add(h,raw(instruction,j)) end
  end
 end
 return h==spec[7]
end
local function mov_check_region(index)
 local ok,result=call(mov_digest,index)
 return ok and result==true
end
local function mov_check_vm(p)
 local vm=raw(p,'vm_id')
 return kind(vm)=='number' and mov_check_region(alphas[vm+1])
end
local function mov_initialize(kits)
 table0(kits);mov_objects[0]=kits
 if #kits~=#alphas then reject() end
 for i=1,#kits do mov_objects[i]=raw(kits,i) end
 for i=1,#mov_specs do if not mov_check_region(i) then reject() end end
end
