-- Callback queue, coroutine suspension, trailing nil and recoverable errors.
local function pack(...) return {n=select('#',...),...} end
local unpack_values=table.unpack or unpack
local listeners={}
for i=1,8 do
    local count=i
    listeners[i]=function(event,...)
        count=count+1
        return event..':'..count,select('#',...),...
    end
end
local checksum=0
for round=1,12 do
    for _,callback in ipairs(listeners) do
        local values=pack(callback('event',round,nil,false,nil))
        assert(values.n==6 and values[2]==4 and values[4]==nil and values[5]==false)
        checksum=checksum+#values[1]+values[3]
    end
end
local function task(id)
    return coroutine.create(function(value)
        for step=1,3 do value=coroutine.yield(id,step,value+step) end
        return id,value,nil
    end)
end
for id=1,5 do
    local co=task(id)
    for step=1,4 do
        local result=pack(coroutine.resume(co,id*step))
        assert(result[1]);checksum=checksum+result[2]
    end
    assert(coroutine.status(co)=='dead')
end
local marker={tag='expected'}
local ok,err=pcall(function() error(marker,0) end)
assert(not ok and err==marker)
print('callbacks',checksum,unpack_values({true,false},1,2))
