-- Canonical executable checksum representation; this is not loadable bytecode.
return function(data)
    assert(#data>=12 and data:sub(1,6)=="\27Lua\81\0","expected standard Lua 5.1 dump")
    local endian,int_size,size_t,instruction_size,number_size,integral=string.byte(data,7,12)
    assert((endian==0 or endian==1) and (int_size==4 or int_size==8) and
           (size_t==4 or size_t==8) and instruction_size==4 and number_size==8 and integral==0,
           "unsupported Lua 5.1 dump ABI")
    local position=13
    local output={"KarityDump51\0"}
    local function take(size)
        assert(size>=0 and position+size<=#data+1,"truncated Lua 5.1 dump")
        local value=data:sub(position,position+size-1)
        position=position+size
        return value
    end
    local function uint(size)
        local raw=take(size)
        local value=0
        for index=1,size do
            local byte=string.byte(raw,endian==1 and size-index+1 or index)
            value=value*256+byte
            assert(value<=4294967295,"Lua 5.1 dump field exceeds canonical width")
        end
        return value
    end
    local function put_uint(value)
        local bytes={}
        for index=1,4 do bytes[index]=string.char(value%256);value=math.floor(value/256) end
        output[#output+1]=table.concat(bytes)
    end
    local function count()
        local value=uint(int_size)
        assert(value<=2147483647,"negative Lua 5.1 dump count")
        return value
    end
    local function str(keep)
        local size=uint(size_t)
        local raw=take(size)
        assert(size==0 or raw:sub(-1)=="\0","unterminated Lua 5.1 dump string")
        if keep then put_uint(size);output[#output+1]=raw end
    end
    local function proto()
        str(false)
        put_uint(uint(int_size));put_uint(uint(int_size))
        output[#output+1]=take(4)
        local total=count();put_uint(total)
        for index=1,total do put_uint(uint(4)) end
        total=count();put_uint(total)
        for index=1,total do
            local tag=take(1);output[#output+1]=tag
            if tag=="\1" then output[#output+1]=take(1)
            elseif tag=="\3" then
                local raw=take(8);output[#output+1]=endian==1 and raw or raw:reverse()
            elseif tag=="\4" then str(true)
            else assert(tag=="\0","unknown Lua 5.1 dump constant tag") end
        end
        total=count();put_uint(total)
        for index=1,total do proto() end
        take(count()*int_size)
        for index=1,count() do str(false);take(int_size*2) end
        for index=1,count() do str(false) end
    end
    proto()
    assert(position==#data+1,"unexpected Lua 5.1 dump tail")
    return table.concat(output)
end
