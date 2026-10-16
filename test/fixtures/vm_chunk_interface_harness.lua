local function pack(...) return {n=select('#',...),...} end
local environment=setmetatable({__vm_audit_magic=93},{__index=_G})
local chunk
if _VERSION=='Lua 5.1' then
    chunk=assert(loadfile(arg[1]));setfenv(chunk,environment)
else chunk=assert(loadfile(arg[1],'t',environment)) end
local values=pack(chunk('demo.module',nil,41,nil))
print('chunk-returns',values.n,type(values[1]),values[2],values[3],values[4],values[5])
assert(values.n==5 and type(values[1])=='table' and values[2]==nil and values[3]==false)
assert(values[4]=='tail' and values[5]==nil)
local module=values[1]
print('module-input',type(module.name),module.argc,module.magic)
assert(module.name=='demo.module' and module.path==nil and module.argc==4 and module.trailing==nil)
assert(module.magic==93)
collectgarbage('collect');collectgarbage('collect')
local results=pack(module.next(1))
assert(results.n==5 and results[1]==42 and results[2]==nil and results[3]==false and results[4]==93 and results[5]==nil)
print('module-callback',module.name,module.argc,results.n,results[1],results[3])
package.loaded.__vm_audit_module=nil
package.preload.__vm_audit_module=chunk
local required=require('__vm_audit_module')
assert(type(required)=='table' and required.name=='__vm_audit_module' and required.magic==93)
print('require-module',required.name,required.argc,required.next(2))
assert(module.next(1)==43)
package.preload.__vm_audit_module=nil;package.loaded.__vm_audit_module=nil
