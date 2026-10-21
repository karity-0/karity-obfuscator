"""Shared repeated host checks independent of opcode/blob representation."""

GUARD_SOURCE = '''function S.guard(force)
 if failed then fail() end
 ticks=(ticks+1)%127
 if not force and ticks~=0 then return end
 if _ENV_CHECK then _ENV_CHECK() end
 for i=1,#trusted do local b=trusted[i]
  if not same(raw(b[1],b[2]),b[3]) then fail() end
 end
 for i=1,#bindings do local b=bindings[i]
  if not same(b[1][b[2]],b[3]) then fail() end
 end
 local hook,mask,count=hook0()
 if hook~=nil or (mask and #mask>0) or (count and count~=0) then fail() end
end'''


def inspector_source():
    """Same checks, with the fail/continue decision made by a small IR guard."""
    source=GUARD_SOURCE.replace('function S.guard(force)','function S.inspect(force)')
    source=source.replace('fail()', 'return false').replace('then return end','then return true end')
    return source.rsplit('end',1)[0]+'return true\nend'
