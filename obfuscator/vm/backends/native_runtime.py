"""Emit explicit-lifetime CE native modules from validated native IR."""
from .native import encode_x64
from ..targets.materialization import _lua_string


def emit_ce_module(program):
    entries = []
    for function in program.functions:
        code = encode_x64(function)
        entries.append('{' + ','.join((
            _lua_string(function.id), str(function.params),
            _lua_string(','.join(f'{value:02X}' for value in code)),
            _lua_string(f'{max(64, len(code)):X}'),
        )) + '}')
    return '''return function(fallbacks)
    if getOperatingSystem()~=0 or not cheatEngineIs64Bit() or getABI()~=0 then
        error("native module requires Windows x64")
    end
    local specs={''' + ','.join(entries) + '''}
    local owner={}
    local prefix="karity_native_"..tostring(owner):gsub("[^%w]","").."_"
    local allocations=owner
    local functions={}
    local closed=false
    for index,spec in ipairs(specs) do
        local fallback=assert(fallbacks[spec[1]],"native module requires a Lua fallback")
        if type(fallback)~="function" then error("native fallback must be a function") end
        functions[spec[1]]=function(...)
            if closed then error("native module is closed") end
            local args=table.pack(...)
            for i=1,spec[2] do
                if math.type(args[i])~="integer" then return fallback(...) end
            end
            local allocation=allocations[index]
            if not allocation then
                local name=prefix..index
                local script="[ENABLE]\\nalloc("..name..","..spec[4]..")\\nregistersymbol("..name..")\\n"..
                             name..":\\ndb "..spec[3].."\\n[DISABLE]\\nunregistersymbol("..name..")\\ndealloc("..name..")"
                local ok,disable=autoAssemble(script,true)
                if not ok then error("native allocation failed") end
                allocation={script=script,disable=disable}
                allocations[index]=allocation
                local success,address=pcall(getAddress,name,true)
                if not success or type(address)~="number" or address<=0 then
                    local released=autoAssemble(script,true,disable)
                    if released then allocations[index]=nil end
                    error("native symbol lookup failed")
                end
                allocation.address=address
            end
            if not allocation.address then error("native allocation is incomplete") end
            return executeCodeLocalEx(allocation.address,table.unpack(args,1,spec[2]))
        end
    end
    local function close()
        closed=true
        local failed=false
        for index,allocation in pairs(allocations) do
            local ok,result=pcall(autoAssemble,allocation.script,true,allocation.disable)
            if ok and result then allocations[index]=nil else failed=true end
        end
        if failed then error("native module cleanup failed; close may be retried") end
    end
    return {functions=functions,close=close}
end
'''
