"""Bind environments early and distribute their guards through initialization."""
import re
import hashlib
import random


TOKENS = {'_ENV_GUEST', '_ENV_NATIVE', '_ENV_CHECK', '_ENV_REFRESH'}


def _helper_sites(source: str, start: int) -> list[int]:
    """Install helpers before any statement that could capture/use a guard.

    Snapshot creation stays at entry. Only helper definitions move, at outer
    statement boundaries; no executor, loop or conditional body is entered.
    """
    from ..passes.ts_utils import parse
    ctx = parse(source)
    if ctx.root.has_error:
        raise ValueError('cannot distribute environment guards in invalid VM source')
    returned = next((n for n in ctx.root.named_children if n.type == 'return_statement'), None)
    expressions = returned.named_children if returned is not None else ()
    function = next((n for expression in expressions for n in expression.named_children
                     if n.type == 'function_definition'), None)
    body = function.child_by_field_name('body') if function is not None else None
    if body is None:
        raise ValueError('environment binding requires a VM factory')
    sites = []
    for statement in body.named_children:
        if ctx.cs(statement) < start or statement.type == 'comment':
            continue
        sites.append(ctx.cs(statement))
        # Include nested functions: install before their definition so callers
        # later in initialization can never observe an absent guard.
        if (statement.type == 'return_statement' or
                re.search(r'\b(?:_ENV_CHECK|_ENV_REFRESH)\b', ctx.plain_text(statement))):
            break
    return sites or [start]


def bind_environment(source: str, *, lua_version: str, policy: str, compact: bool,
                     qualify_globals: bool = False, ready_marker: str | None = None) -> tuple[str, str]:
    if policy not in {'compatible', 'strict'}:
        raise ValueError('environment_policy must be compatible or strict')
    from ..names import NameAllocator
    allocator = NameAllocator.for_source(source)
    kit = allocator.allocate('environment')
    rng = random.Random(hashlib.sha256(repr(random.getstate()).encode()).digest())
    keys = ('guest', 'native', 'check', 'refresh', 'state', 'raw', 'kind', 'meta',
            'fail', 'snapshot', 'watched', 'same')
    slots = dict(zip(keys, rng.sample(range(31, 4096), len(keys))))
    original = '_ENV' if lua_version == '5.3' else 'getfenv(1)'
    selection = ('if not direct(E) then fail() end' if policy == 'strict' else '''
 if not direct(E) then
  local candidate=R(E,"_G")
  if candidate==nil then candidate=E._G end
  if direct(candidate) then N=candidate end
 end''')
    strict_watch = ('''if T(b[3])=="function" or T(b[4])=="function" then fail() end'''
                    if policy == 'strict' else '')
    early = '''local __KIT=(function(E,R,T,D,F,next,same)
 local S={}
 local failed=false
 local M=R(D,"getmetatable")
 local function fail(check_only)
  if not check_only or failed then failed=true;F(nil,0) end
 end
 if T(M)~="function" then fail() end
 local function direct(e)
  if T(e)~="table" then return false end
  for _,k in next,{"type","rawget","rawequal","error","pcall","tonumber","tostring","select"} do
   if T(R(e,k))~="function" then return false end
  end
  for _,k in next,{"string","table","math","debug"} do
   if T(R(e,k))~="table" then return false end
  end
  return true
 end
 local N=E
 __SELECTION
 local watched={}
 local function snapshot(b)
  local mt=M(b[1]);b[2]=mt
  b[3]=T(mt)=="table" and R(mt,"__index") or nil
  b[4]=T(mt)=="table" and R(mt,"__newindex") or nil
 end
 local function watch(t)
  if T(t)~="table" then fail() end
  for i=1,#watched do if same(watched[i][1],t) then return end end
  local b={t};snapshot(b)
  __STRICT_WATCH
  watched[#watched+1]=b
 end
 watch(E);watch(N)
 for _,k in next,{"string","table","math","debug"} do watch(N[k]) end
 S[__raw]=R;S[__kind]=T;S[__meta]=M;S[__fail]=fail
 S[__snapshot]=snapshot;S[__watched]=watched;S[__same]=same
 return {[__guest]=E,[__native]=N,[__state]=S}
end)(__ORIGINAL,rawget,type,debug,error,next,rawequal)
'''.replace('__SELECTION', selection).replace('__STRICT_WATCH', strict_watch)
    check = '''do
 local S=__KIT[__state]
 local R,T,M,fail,watched,same=S[__raw],S[__kind],S[__meta],S[__fail],S[__watched],S[__same]
 __KIT[__check]=function()
  fail(true)
  for i=1,#watched do local b=watched[i];local mt=M(b[1])
   if not same(mt,b[2]) then fail() end
   if T(mt)=="table" and (not same(R(mt,"__index"),b[3]) or not same(R(mt,"__newindex"),b[4])) then fail() end
  end
 end
end
'''
    refresh = '''do
 local S=__KIT[__state]
 local fail,watched,snapshot,same=S[__fail],S[__watched],S[__snapshot],S[__same]
 __KIT[__refresh]=function(t,commit)
  fail(true)
  local affected=false
  for i=1,#watched do local b=watched[i]
   if same(t,b[1]) or same(t,b[2]) then
    affected=true
    if commit then snapshot(b) end
   end
  end
  if affected then __KIT[__check]() end
 end
end
'''
    if lua_version == '5.3':
        early += 'local _ENV=__KIT[__native]\n'
    # Rename together so every fragment shares the same lexical kit binding.
    separator = '--[[ENVIRONMENT_FRAGMENT]]'
    fragments = separator.join((early, check, refresh))
    fragments = fragments.replace('__KIT', kit).replace('__ORIGINAL', original)
    for key, slot in slots.items():
        fragments = re.sub(r'\b__'+key+r'\b', str(slot), fragments)
    if lua_version == '5.3' and qualify_globals:
        from ..passes.rename_ts import qualify_runtime_globals
        fragments = qualify_runtime_globals(fragments)
    from ..passes.ts_utils import parse
    from ..passes.rename_ts import rename_replacements_with_ctx, _apply_replacements_once
    ctx = parse(fragments)
    replacements = rename_replacements_with_ctx(ctx, reserved=allocator.used,
                                                keep=lambda binding: binding.original == kit)
    fragments = _apply_replacements_once(fragments, [(r.start, r.end, r.new_text) for r in replacements])
    pieces = fragments.split(separator)
    if compact:
        from ..passes.minify import MinifyPass
        pieces = [MinifyPass().run(piece) for piece in pieces]
    anchor = re.match(r'return\s+function\s*\([^)]*\)', source)
    if anchor is None:
        raise ValueError('environment binding requires a VM factory')
    sites = _helper_sites(source, anchor.end())
    # Keep both jobs ordered even if a minimal factory has only one safe site.
    if len(sites) >= 3:
        positions = sorted(rng.sample(sites[1:], 2))
    else:
        positions = [sites[0], sites[-1]]
    gap = ' ' if compact else '\n'
    insertions: dict[int, str] = {}
    for position, piece in zip(positions, pieces[1:]):
        insertions[position] = insertions.get(position, '') + gap + piece + gap
    marker = ready_marker if ready_marker is not None else ('--[[ENVIRONMENT_READY]]' if lua_version == '5.3' else '')
    insertions[anchor.end()] = gap + pieces[0] + gap + marker + insertions.get(anchor.end(), '')
    for position, fragment in sorted(insertions.items(), reverse=True):
        source = source[:position] + fragment + source[position:]
    substitutions = {'_ENV_GUEST': f'{kit}[{slots["guest"]}]', '_ENV_NATIVE': f'{kit}[{slots["native"]}]',
                     '_ENV_CHECK': f'{kit}[{slots["check"]}]', '_ENV_REFRESH': f'{kit}[{slots["refresh"]}]'}
    for token, expression in substitutions.items():
        source = re.sub(r'\b'+token+r'\b', expression, source)
    return source, f'{kit}[{slots["native"]}]'
