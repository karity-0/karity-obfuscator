-- Output-only observer: no imports from the obfuscator, no layout/seed/source.
local artifact, mode, capture_path, forbidden = arg[1], arg[2] or "baseline", arg[3], arg[4]
local real_info, real_hook, real_sethook = debug.getinfo, debug.gethook, debug.sethook
local real_char, real_concat, real_sub, real_dump = string.char, table.concat, string.sub, string.dump
local real_load, real_loadfile, real_pack = load, loadfile, string.pack
local real_type, real_tostring, real_pcall = type, tostring, pcall
local real_next, real_getupvalue, real_getlocal = next, debug.getupvalue, debug.getlocal
local captures = capture_path and assert(io.open(capture_path,"wb"))
local seen, seen_by_kind, total, count, hook_events = {}, {}, 0, 0, 0
local original = {}
local function record(kind, value)
    if real_type(value) ~= "string" then return end
    -- Inspect every observed value even after the bounded capture file fills.
    if forbidden and value:find(forbidden,1,true) then error("AUDIT_CANARY_FOUND",0) end
    if not captures or #value < 6 then return end
    seen_by_kind[kind]=seen_by_kind[kind] or {}
    if seen_by_kind[kind][value] or total + #value > 64*1024*1024 or count >= 100000 then return end
    seen_by_kind[kind][value]=true
    seen[value] = true; total = total + #value; count = count + 1
    captures:write(kind," ",#value,"\n",value,"\n")
end
local function wrap_concat(t,...)
    local s=real_concat(t,...); record("concat",s); return s
end
local function wrap_char(...)
    local s=real_char(...); record("char",s); return s
end
local function wrap_sub(...)
    local s=real_sub(...); record("sub",s); return s
end
local function wrap_load(chunk,...)
    if real_type(chunk)=="string" then record("load",chunk) end
    return real_load(chunk,...)
end
local function wrap_dump(fn,...)
    return real_dump(original[fn] or fn,...)
end
local function walk(root)
    local visited,budget,locations={},150000,{}
    local function visit(v,depth)
        if budget<=0 then return end
        budget=budget-1
        local kind=real_type(v)
        if kind=="string" then record("upvalue",v); return end
        if depth<=0 or (kind~="table" and kind~="function") or visited[v] then return end
        if v==_G or v==package or v==debug or v==string or v==table or v==io or v==os or v==math or v==coroutine then return end
        visited[v]=true
        if kind=="table" then
            local k,val=real_next(v)
            while k~=nil and budget>0 do
                if real_type(val)=="string" then locations[#locations+1]={container=v,key=k,value=val} end
                visit(k,depth-1);visit(val,depth-1);k,val=real_next(v,k)
            end
        else
            if real_info(v,"S").what=="C" then return end
            for i=1,255 do
                local name,value=real_getupvalue(v,i)
                if not name then break end
                visit(value,depth-1)
            end
        end
    end
    visit(root,32)
    return locations
end
local function sample_hook()
    hook_events=hook_events+1
    if hook_events>100 then return end
    for level=2,4 do
        if not real_info(level,"f") then break end
        for i=1,32 do
            local name,value=real_getlocal(level,i)
            if not name then break end
            if real_type(value)=="string" then record("local",value) end
        end
    end
end
local function hide_hook() return nil,"",0 end
local function wrap_info(subject,what)
    if real_type(subject)=="function" then
        local result=real_info(original[subject] or subject,what)
        return result
    end
    if real_type(subject)=="number" then
        local result=real_info(subject+1,what)
        return result
    end
    return real_info(subject,what)
end
original[wrap_info]=real_info; original[hide_hook]=real_hook
original[wrap_concat]=real_concat; original[wrap_char]=real_char
original[wrap_sub]=real_sub; original[wrap_load]=real_load
original[wrap_dump]=real_dump
if mode=="concat" then table.concat=wrap_concat end
if mode=="char" then string.char=wrap_char end
if mode=="load" then load=wrap_load end
if mode=="native" or mode=="native-masked" then
    table.concat=wrap_concat; string.char=wrap_char; string.sub=wrap_sub; load=wrap_load
end
if mode=="native-masked" or mode=="hook-masked" then
    debug.getinfo=wrap_info; debug.gethook=hide_hook
end
if mode=="native-masked" then string.dump=wrap_dump end
if mode=="hook" or mode=="hook-masked" then
    real_sethook(function() hook_events=hook_events+1 end,"cr",10000)
end
local function execute()
    local chunk=assert(real_loadfile(artifact))
    if mode=="stripped" then
        chunk=assert(real_load(real_dump(chunk,true),"@stripped","b"))
    elseif mode=="unstripped" then
        chunk=assert(real_load(real_dump(chunk,false),"@unstripped","b"))
    end
    local api=chunk()
    assert(real_type(api)=="table", "fixture did not return API")
    if mode=="upvalues" then walk(api) end
    if mode=="upvalues-rewrite" then
        local locations=walk(api)
        local accepted
        for candidate in real_next,seen do
            local worked,value=real_pcall(api.check,candidate)
            if worked and value==true then accepted=candidate;break end
        end
        assert(accepted,"no accepted value among recovered strings")
        record("accepted",accepted)
        local replacement="AUDIT_ATTACKER_CHOSEN_VALUE"
        assert(api.check(replacement)==false,"replacement was already accepted")
        local changed=0
        for _,location in ipairs(locations) do
            if location.value==accepted then
                rawset(location.container,location.key,replacement)
                changed=changed+1
            end
        end
        assert(changed>0,"no writable reference")
        assert(api.check(replacement)==true,"replacement not accepted after rewrite")
        print("AUDIT_REWRITE",changed,"false->true")
    end
    if mode=="hook-late" then real_sethook(sample_hook,"",1000) end
    local accepted=api.check("wrong")
    local value,flag=api.compute(7,4)
    print("AUDIT_RESULT",real_tostring(accepted),value,real_tostring(flag))
end
local ok,err=real_pcall(execute)
real_sethook()
if captures then captures:close() end
print("AUDIT_OBSERVER",mode,ok,count,total,hook_events)
if not ok then io.stderr:write(real_tostring(err),"\n"); os.exit(2) end
