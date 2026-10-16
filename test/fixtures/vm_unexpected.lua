-- Differential scenarios: each case has its own scope and stable observable output.
local function case(name, fn)
    local ok, value = pcall(fn)
    if not ok then io.stderr:write(name..': '..tostring(value)..'\n') end
    print(name, ok, ok and tostring(value) or type(value))
end
local function pack(...) return {n=select('#', ...), ...} end

case('gc-overwrite', function()
    local weak=setmetatable({}, {__mode='v'})
    local obj={}; weak[1]=obj; obj=nil
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-call-temporary', function()
    local weak=setmetatable({}, {__mode='v'})
    local function make() local obj={}; weak[1]=obj; return obj end
    local function discard(value) end
    discard(make())
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-parameter-overwrite', function()
    local weak=setmetatable({}, {__mode='v'})
    local function use(obj)
        weak[1]=obj; obj=nil
        collectgarbage('collect'); collectgarbage('collect')
        return weak[1]==nil
    end
    return use({})
end)
case('gc-coroutine', function()
    local weak=setmetatable({}, {__mode='v'})
    local co=coroutine.create(function()
        local obj={}; weak[1]=obj; coroutine.yield(); return obj
    end)
    assert(coroutine.resume(co)); co=nil
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-live-shared-cell', function()
    local weak=setmetatable({}, {__mode='v'})
    local obj={answer=42}; weak[1]=obj
    local function read() return obj end
    collectgarbage('collect'); collectgarbage('collect')
    assert(read()==weak[1] and read().answer==42)
    obj=nil; collectgarbage('collect'); collectgarbage('collect')
    return read()==nil and weak[1]==nil
end)
case('gc-table-cycle', function()
    local weak=setmetatable({}, {__mode='v'})
    local obj={}; obj.self=obj; weak[1]=obj; obj=nil
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('metatable-after-create', function()
    local value={10,20}
    local mt={__index=function(_,k) return 'missing:'..k end,
              __newindex=function(t,k,v) rawset(t,k,v*2) end}
    setmetatable(value, mt); value.x=7
    assert(value.x==14 and value.no=='missing:no')
    assert(rawget(value,1)==10 and next(value)~=nil)
    return table.concat(value,',')
end)
case('weak-values', function()
    local weak=setmetatable({}, {__mode='v'})
    do local obj={}; weak.x=obj end
    collectgarbage('collect'); collectgarbage('collect')
    return weak.x==nil
end)
case('metamethod-reentry', function()
    local log={}; local value=3
    local function bump() value=value+1; return value end
    local mt={__add=function(a,b) log[#log+1]='add'; return bump()+b end,
              __index=function(a,b) log[#log+1]=b; return bump() end}
    local t=setmetatable({},mt)
    local answer=(t+5)+t.x
    assert(answer==14 and value==5)
    return table.concat(log,',')
end)
case('comparison-fallback', function()
    local calls={}
    local mt={__lt=function(a,b) calls[#calls+1]=a.n..':'..b.n; return a.n<b.n end}
    local a,b=setmetatable({n=1},mt),setmetatable({n=2},mt)
    assert(a<=b and not (b<=a) and a<b)
    return table.concat(calls,',')
end)
case('concat-order', function()
    local trace={}; local mt={}
    mt.__concat=function(a,b)
        local x=type(a)=='table' and a.s or a
        local y=type(b)=='table' and b.s or b
        trace[#trace+1]=x..':'..y; return setmetatable({s=x..y},mt)
    end
    local a,b,c=setmetatable({s='a'},mt),setmetatable({s='b'},mt),setmetatable({s='c'},mt)
    assert((a..b..c).s=='abc')
    return table.concat(trace,',')
end)
case('callable-vararg', function()
    local t=setmetatable({}, {__call=function(self,...) return self,select('#',...),... end})
    local p=pack(t(nil,false,9,nil)); assert(p.n==6 and p[1]==t and p[2]==4)
    assert(p[3]==nil and p[4]==false and p[5]==9 and p[6]==nil)
    return p.n
end)
case('gc-deleted-table-key', function()
    local weak=setmetatable({}, {__mode='v'})
    local value={}; local key={}; weak[1]=key
    value[key]=1; value[key]=nil; key=nil
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('nil-value-invalid-keys', function()
    local function invalid(key)
        local value={}
        local ok,err=pcall(function() value[key]=nil end)
        assert(not ok and type(err)=='string')
    end
    invalid(nil); invalid(0/0)
    return true
end)
case('gc-callable-overwrite', function()
    local weak=setmetatable({}, {__mode='v'})
    local callable=setmetatable({}, {__call=function(self,object)
        weak[1]=object; object=nil
        collectgarbage('collect'); collectgarbage('collect')
        return weak[1]==nil
    end})
    return callable({})
end)
case('iterator-mutable-capture', function()
    local readers={}; local n=0
    local function iter(_,last) if last==nil then return false,7 elseif last==false then return 0,8 end end
    for k,v in iter,nil,nil do n=n+v; readers[#readers+1]=function() return k,v end end
    local a,b=readers[1](); local c,d=readers[2]()
    assert(a==false and b==7 and c==0 and d==8)
    return n
end)
case('repeat-close', function()
    local funcs={}; local count=0
    repeat
        count=count+1; local x=count
        funcs[count]=function(v) if v then x=v end; return x end
    until count==4
    funcs[2](99)
    return funcs[1]()+funcs[2]()+funcs[3]()+funcs[4]()
end)
case('error-cell-identity', function()
    local marker={}; local escaped
    local ok,err=pcall(function()
        local x=marker; escaped=function(v) if v then x=v end; return x end
        error(marker,0)
    end)
    assert(not ok and err==marker and escaped()==marker)
    escaped(false); assert(escaped()==marker)
    return err==marker
end)
case('coroutine-open-results', function()
    local co=coroutine.create(function(...)
        local p=pack(...); assert(p.n==4)
        local q=pack(coroutine.yield(nil,false,nil))
        assert(q.n==3 and q[1]==8 and q[2]==nil and q[3]==false)
        return nil,p.n,false,nil
    end)
    local a=pack(coroutine.resume(co,1,nil,3,nil))
    local b=pack(coroutine.resume(co,8,nil,false))
    assert(a.n==4 and a[1] and a[2]==nil and a[3]==false and a[4]==nil)
    assert(b.n==5 and b[1] and b[2]==nil and b[3]==4 and b[4]==false)
    return coroutine.status(co)
end)
case('nan-zero-identity', function()
    local nan=0/0; local negative=-1/math.huge; local positive=1/math.huge
    local values={nan,negative,positive,nan}
    assert(values[1]~=values[1] and values[4]~=values[4])
    assert(1/values[2]==-math.huge and 1/values[3]==math.huge)
    return true
end)
case('table-resize-alias', function()
    local t={}; local alias=t
    for i=1,130 do t[i]=i end
    for i=1,130,2 do alias[i]=nil end
    local sum=0; for k,v in pairs(t) do sum=sum+v end
    assert(sum==4290 and t[130]==130)
    return sum
end)
case('tail-open-call', function()
    local function pass(...) return ... end
    local function recur(n,...) if n==0 then return pass(...) end; return recur(n-1,...) end
    local p=pack(recur(200,1,nil,false,nil))
    assert(p.n==4 and p[1]==1 and p[2]==nil and p[3]==false and p[4]==nil)
    return p.n
end)
case('self-evaluation-order', function()
    local trace={}
    local t=setmetatable({}, {__index=function(self,k)
        trace[#trace+1]=k
        return function(receiver,a,b) assert(receiver==self);return a+b end
    end})
    local function arg(v) trace[#trace+1]=v; return v end
    assert(t:method(arg(2),arg(3))==5)
    return table.concat(trace,',')
end)

case('gc-live-alias', function()
    local weak=setmetatable({}, {__mode='v'})
    local object={answer=73}; weak[1]=object
    local alias=object; object=nil
    collectgarbage('collect'); collectgarbage('collect')
    assert(weak[1]==alias and alias.answer==73)
    alias=nil; collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-exposed-table-overwrite', function()
    local weak=setmetatable({}, {__mode='v'})
    local holder={}; do local value={}; holder.value=value; weak[1]=value end
    rawset(holder,'value',nil)
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-native-nested-table', function()
    local weak=setmetatable({}, {__mode='v'})
    local outer=setmetatable({}, {})
    local inner={answer=81}; outer.inner=inner; weak[1]=inner; inner=nil
    local function native_check(t)
        -- string.format is native; raw iteration must never see private metadata.
        local count=0; for k,v in next,t.inner do assert(k=='answer'); count=count+v end
        return string.format('%d',count)
    end
    assert(native_check(outer)=='81'); outer.inner=nil
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-closure-cycle-active', function()
    local weak=setmetatable({}, {__mode='v'})
    do
        local fn; fn=function() return fn end; weak[1]=fn
    end
    collectgarbage('collect'); collectgarbage('collect')
    return weak[1]==nil
end)
case('gc-loop-overwrites', function()
    local weak=setmetatable({}, {__mode='v'})
    local keep={answer=41}; weak.keep=keep
    for i=1,80 do
        local object={i}; weak[i]=object; object=nil
        if i%7==0 then collectgarbage('collect') end
    end
    collectgarbage('collect'); collectgarbage('collect')
    local count=0; for _ in pairs(weak) do count=count+1 end
    assert(weak.keep==keep and keep.answer==41)
    return count
end)
case('capture-child-overwrite', function()
    local weak=setmetatable({}, {__mode='v'})
    local object={answer=22}; weak[1]=object
    local function replace(value) object=value end
    local function read() return object end
    replace(nil)
    collectgarbage('collect'); collectgarbage('collect')
    assert(read()==nil)
    return weak[1]==nil
end)
case('metamethod-mutate-register', function()
    local x=10
    local obj=setmetatable({}, {__add=function(a,b) x=31; return b+4 end})
    local function read() return x end
    local answer=(obj+read())+read()
    assert(answer==45 and x==31)
    return answer
end)
case('metamethod-error-identity', function()
    local marker={}
    local obj=setmetatable({}, {__add=function() error(marker,0) end})
    local ok,err=pcall(function() return obj+1 end)
    return not ok and err==marker
end)
case('register-many-open-results', function()
    local unpack_values=table.unpack or unpack
    local source={}; for i=1,180 do source[i]=i end
    source[2]=nil; source[179]=nil
    local function relay(...) return ... end
    local p=pack(relay(unpack_values(source,1,180)))
    assert(p.n==180 and p[2]==nil and p[179]==nil and p[180]==180)
    return p.n
end)
case('open-result-constant-boundary', function()
    local unpack_values=table.unpack or unpack
    local function relay(...) return ... end
    local sum=0
    for _,count in ipairs({250,255,256,257,300,512,1100}) do
        local values={}
        for i=1,count do
            if i%67==0 then values[i]=false else values[i]=i end
        end
        values[count]=nil
        if count>256 then values[256]={marker=count} end
        local result=pack(relay(unpack_values(values,1,count)))
        assert(result.n==count)
        for i=1,count do assert(result[i]==values[i]) end
        sum=sum+result.n
    end
    return sum
end)
case('yield-through-protected-call', function()
    local co=coroutine.create(function()
        return pcall(function() coroutine.yield('yielded'); return 'returned' end)
    end)
    local a=pack(coroutine.resume(co))
    if coroutine.status(co)=='suspended' then
        local b=pack(coroutine.resume(co))
        assert(b[1] and b[2] and b[3]=='returned')
        return a[2]..':'..b[3]
    end
    assert(a[1] and not a[2]); return 'non-yieldable-pcall'
end)
