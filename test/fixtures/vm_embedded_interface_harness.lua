local function pack(...) return {n=select('#',...),...} end
local file=assert(io.open(arg[1],'rb'))
local source=file:read('*a');file:close()
local compile=loadstring or load
local factory=assert(compile('return function() '..source..'\nend'))
local fn=factory()
local values=pack(fn())
assert(values.n==4 and values[1]==7 and values[2]==nil and values[3]==false and values[4]==nil)
print('embedded',values.n,values[1],values[3])
