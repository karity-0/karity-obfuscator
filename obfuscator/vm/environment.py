"""Bind guest/native environments before target prelude and runtime captures."""
import re
import hashlib
import random


TOKENS = {'_ENV_GUEST', '_ENV_NATIVE', '_ENV_CHECK', '_ENV_REFRESH'}


def bind_environment(source: str, *, lua_version: str, policy: str, compact: bool,
                     qualify_globals: bool = False) -> tuple[str, str]:
    if policy not in {'compatible', 'strict'}:
        raise ValueError('environment_policy must be compatible or strict')
    from ..names import NameAllocator
    allocator = NameAllocator.for_source(source)
    kit = allocator.allocate('environment')
    rng = random.Random(hashlib.sha256(repr(random.getstate()).encode()).digest())
    guest_slot,native_slot,check_slot,refresh_slot = rng.sample(range(31,4096),4)
    original = '_ENV' if lua_version == '5.3' else 'getfenv(1)'
    fragment = '''local __KIT=(function(E,R,T,D,F)
 local M=R(D,"getmetatable")
 local failed=false
 local function fail() failed=true;F(nil,0) end
 if T(M)~="function" then fail() end
 local function direct(e)
  if T(e)~="table" then return false end
  for _,k in ipairs({"type","rawget","error","pcall","tonumber","tostring","select"}) do
   if T(R(e,k))~="function" then return false end
  end
  for _,k in ipairs({"string","table","math","debug"}) do
   if T(R(e,k))~="table" then return false end
  end
  return true
 end
 local strict=__STRICT
 if strict and not direct(E) then fail() end
 local N=E
 if not direct(E) then
  local candidate=R(E,"_G")
  if candidate==nil then candidate=E._G end
  if direct(candidate) then N=candidate end
 end
 local watched={}
 local function snapshot(b)
  local mt=M(b[1]);b[2]=mt
  b[3]=T(mt)=="table" and R(mt,"__index") or nil
  b[4]=T(mt)=="table" and R(mt,"__newindex") or nil
 end
 local function watch(t)
  if T(t)~="table" then fail() end
  for i=1,#watched do if watched[i][1]==t then return end end
  local b={t};snapshot(b)
  if strict and (T(b[3])=="function" or T(b[4])=="function") then fail() end
  watched[#watched+1]=b
 end
 watch(E);watch(N)
 for _,k in ipairs({"string","table","math","debug"}) do watch(N[k]) end
 local function check()
  if failed then fail() end
  for i=1,#watched do local b=watched[i];local mt=M(b[1])
   if mt~=b[2] then fail() end
   if T(mt)=="table" and (R(mt,"__index")~=b[3] or R(mt,"__newindex")~=b[4]) then fail() end
  end
 end
 local function refresh(t,commit)
  if failed then fail() end
  local affected=false
  for i=1,#watched do local b=watched[i]
   if t==b[1] or t==b[2] then
    affected=true
    if commit then snapshot(b) end
   end
  end
  if affected then check() end
 end
 return {E,N,check,refresh}
end)(__ORIGINAL,rawget,type,debug,error)
'''.replace('__KIT', kit).replace('__ORIGINAL', original).replace('__STRICT', 'true' if policy=='strict' else 'false')
    # ipairs itself may be provided through a proxy. Traverse with captured next
    # so the bootstrap only needs its explicit initial capability reads.
    fragment = fragment.replace('for _,k in ipairs({', 'for _,k in next,{')
    fragment = fragment.replace('}) do', '} do')
    # Capture next explicitly too, rather than resolving it inside the factory.
    fragment = fragment.replace('(E,R,T,D,F)', '(E,R,T,D,F,next)')
    fragment = fragment.replace('rawget,type,debug,error)', 'rawget,type,debug,error,next)')
    fragment = fragment.replace('return {E,N,check,refresh}',
        f'return {{[{guest_slot}]=E,[{native_slot}]=N,[{check_slot}]=check,[{refresh_slot}]=refresh}}')
    substitutions = {'_ENV_GUEST': f'{kit}[{guest_slot}]', '_ENV_NATIVE': f'{kit}[{native_slot}]',
                     '_ENV_CHECK': f'{kit}[{check_slot}]', '_ENV_REFRESH': f'{kit}[{refresh_slot}]'}
    for token, expression in substitutions.items():
        source = re.sub(r'\b'+token+r'\b', expression, source)
    if lua_version == '5.3':
        fragment += f'local _ENV={kit}[{native_slot}]\n'
        if qualify_globals:
            # Selective capsules may later pass through generic packing. Keep
            # initial capability lookups in the capsule's environment so proxy
            # extraction cannot rewrite its finalized bytecode/dump identity.
            from ..passes.rename_ts import qualify_runtime_globals
            fragment = qualify_runtime_globals(fragment)
    # Keep all helper locals lexical and opaque, without string reconstruction
    # which would perform extra environment reads before validation is complete.
    from ..passes.ts_utils import parse
    from ..passes.rename_ts import rename_replacements_with_ctx, _apply_replacements_once
    ctx = parse(fragment)
    replacements = rename_replacements_with_ctx(ctx, reserved=allocator.used,
                                                keep=lambda binding: binding.original==kit)
    fragment = _apply_replacements_once(fragment, [(r.start,r.end,r.new_text) for r in replacements])
    if compact:
        from ..passes.minify import MinifyPass
        fragment = ' '+MinifyPass().run(fragment)+' '
    anchor = re.match(r'return\s+function\s*\([^)]*\)', source)
    if anchor is None:
        raise ValueError('environment binding requires a VM factory')
    gap = ' ' if compact else '\n'
    marker = '--[[ENVIRONMENT_READY]]' if lua_version=='5.3' else ''
    result = source[:anchor.end()]+gap+fragment+marker+source[anchor.end():]
    return result, f'{kit}[{native_slot}]'
