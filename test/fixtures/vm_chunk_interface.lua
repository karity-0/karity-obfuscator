local module_name,path,initial,trailing=...
local count=select('#',...)
local state=initial or 0
local module={name=module_name,path=path,argc=count,trailing=trailing,magic=__vm_audit_magic}
function module.next(delta)
    state=state+delta
    return state,nil,false,__vm_audit_magic,nil
end
return module,nil,false,'tail',nil
