local function check(name, fn)
    local ok, value = pcall(fn)
    print(name, ok, ok and tostring(value) or 'ERROR')
end

local function loop(a,b,c)
    local out={}
    for i=a,b,c do
        out[#out+1]=tostring(i)..':'..(math.type and math.type(i) or 'number')
        if #out==4 then break end
    end
    return table.concat(out,',')
end
check('string-limit',function() return loop(1,'3',1) end)
check('string-step',function() return loop(1,3,'1') end)
check('string-initial',function() return loop('1',3,1) end)
check('for-independent-of-tonumber-global',function()
    local old=tonumber;tonumber=function() error('overridden tonumber') end
    local ok,result=pcall(loop,'1','3','1');tonumber=old
    assert(ok);return result
end)
check('fractional-limit',function() return loop(3,0.5,-1) end)
check('float-step',function() return loop(1,3,1.0) end)
check('zero-step',function() return loop(1,0,0) end)
check('nan-step',function() return loop(1,3,0/0) end)
check('nan-limit',function() return loop(1,0/0,1) end)
check('positive-infinity',function() return loop(1,math.huge,1) end)
check('negative-infinity',function() return loop(-1,-math.huge,-1) end)
check('extreme-empty',function()
    if not math.mininteger then return 'skip' end
    return loop(math.mininteger,-math.huge,1)..loop(math.maxinteger,math.huge,-1)
end)
check('integer-overflow',function()
    if not math.maxinteger then return 'skip' end
    return loop(math.maxinteger-1,math.maxinteger,1)
end)
check('for-metamethod-rejected',function()
    return loop(setmetatable({},{__sub=function() return 0 end}),3,1)
end)
check('concat-nil',function() local a,b,c='a',nil,'c';return a..b..c end)
check('concat-trailing-nil',function() local a,b,c='a','b',nil;return a..b..c end)
check('concat-metamethod-nil',function()
    local a,b,c='a',nil,setmetatable({},{__concat=function(x,y)
        return x==nil and 'NIL' or 'OTHER'
    end})
    return a..b..c
end)
check('concat-order',function()
    local log={};local mt={__concat=function(a,b)
        log[#log+1]=tostring(a)..':'..tostring(b);return 'joined'
    end,__tostring=function() return 'object' end}
    local a,b,c='a',setmetatable({},mt),'c'
    local value=a..b..c
    return value..'/'..table.concat(log,',')
end)
check('concat-metamethod-returns-nil',function()
    local a,b,c='a',setmetatable({},{__concat=function() return nil end}),'c'
    return a..b..c
end)
check('metamethod-mutates-open-cell',function()
    local x=3;local function get() return x end
    local t=setmetatable({},{__add=function(a,b) x=99;return 7 end})
    x=x+t;assert(get()==7)
    return get()
end)
check('close-scope',function()
    local t={};for i=1,3 do local v=i;t[i]=function() return v end end
    return t[1]()*100+t[2]()*10+t[3]()
end)
check('close-break',function()
    local f;repeat local x=17;f=function() return x end;break until true
    local x=99;return f()
end)
check('shared-open-cell',function()
    local x=1
    local function set(v) x=v end
    local function get() return x end
    for i=1,30 do set(i); x=x+2;assert(get()==i+2) end
    set(false);assert(x==false);set(nil);assert(x==nil);set('end')
    x=x..'!';return get()
end)
check('captured-arithmetic',function()
    local x=3;local function get() return x end
    local function set(v) x=v end
    for i=1,40 do
        set(i);x=-x;assert(get()==-i)
        x=x*3+7;assert(get()==-i*3+7)
        local y=x+x;assert(y==get()*2)
    end
    set('a');x=x..'b'..'c';assert(get()=='abc')
    local y=x;set('z');assert(y=='abc' and x=='z')
    return get()
end)
check('return-mutated-cell',function()
    local x=1;local function set() x=42 end;set();return x
end)
check('tailcall-shared-cell',function()
    local function factory()
        local x=1
        local function next_frame(get,set)
            set(42);return get,set
        end
        return next_frame(function() return x end,function(v) x=v end)
    end
    local get,set=factory();assert(get()==42);set(nil);assert(get()==nil)
    set(false);return get()
end)
check('error-cell-gc',function()
    local weak=setmetatable({},{__mode='v'});local get,set
    local sentinel={}
    local ok,e=pcall(function()
        local x=42;local unrelated={};weak[1]=unrelated
        get=function() return x end;set=function(v) x=v end
        x=x+1;error(sentinel)
    end)
    assert(not ok and e==sentinel)
    collectgarbage('collect');collectgarbage('collect')
    assert(get()==43);set(false);assert(get()==false);set(nil);assert(get()==nil)
    return weak[1]==nil
end)
check('coroutine-open-cell',function()
    local get,set
    local co=coroutine.create(function()
        local x=2;get=function() return x end;set=function(v) x=v end
        coroutine.yield();assert(x==9);x=x+3;return x
    end)
    assert(coroutine.resume(co));assert(get()==2);set(9)
    local ok,v=coroutine.resume(co);assert(ok and v==12);return get()
end)
check('nested-error-cells',function()
    local weak=setmetatable({},{__mode='v'});local getters={}
    local function recurse(n)
        local value=n;local unrelated={};weak[n]=unrelated
        getters[n]=function() return value end
        if n==1 then error('stop',0) end
        recurse(n-1)
    end
    assert(not pcall(recurse,4))
    collectgarbage('collect');collectgarbage('collect')
    for i=1,4 do assert(getters[i]()==i and weak[i]==nil) end
    return 'ok'
end)
check('xpcall-handler-cells',function()
    local get,set;local token={}
    local ok,e=xpcall(function()
        local x=1;get=function() return x end;set=function(v) x=v end
        error(token)
    end,function(e) assert(e==token and get()==1);set(11);return e end)
    assert(not ok and e==token);return get()
end)
check('multireturn-nils',function()
    local function pack(...) return {n=select('#',...),...} end
    local function f(...) return ... end
    local function tail(...) return f(...) end
    local p=pack(tail(nil,false,3,nil));assert(p.n==4 and p[2]==false and p[3]==3)
    local t={99,tail(1,nil,3,nil)};assert(t[1]==99 and t[2]==1 and t[3]==nil and t[4]==3)
    return p.n
end)
check('iterator-false',function()
    local function iterator(_,last) if last==nil then return false,7 end end
    local n=0;for key,value in iterator do assert(key==false and value==7);n=n+1 end
    return n
end)
check('callable-multireturn',function()
    local t=setmetatable({},{__call=function(self,...) return nil,... end})
    local function pack(...) return {n=select('#',...),...} end
    local p=pack(t(false,7,nil));assert(p.n==4 and p[2]==false and p[3]==7)
    return p.n
end)
check('comparison-fallback',function()
    local calls=0
    local mt={__lt=function(a,b) calls=calls+1;return a.v<b.v end}
    local a,b=setmetatable({v=2},mt),setmetatable({v=3},mt)
    assert(a<=b and not (b<=a));return calls
end)
