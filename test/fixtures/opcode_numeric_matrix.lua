-- Bound every loop, including zero-step, infinity and integer wraparound cases.
local values={0,-0.0,1,-1,1.5,'2','-1.5',math.huge,-math.huge,0/0,false,{}}
local function loop(a,b,c)
    local out={}
    for i=a,b,c do
        out[#out+1]=tostring(i)..':'..(math.type and math.type(i) or 'n')
        if #out==4 then break end
    end
    return table.concat(out,',')
end
for a=1,#values do
    for b=1,#values do
        for c=1,#values do
            local ok,v=pcall(loop,values[a],values[b],values[c])
            print(a,b,c,ok and v or 'ERROR')
        end
    end
end
