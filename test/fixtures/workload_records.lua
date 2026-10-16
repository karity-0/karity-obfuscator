-- A small application workload: parse, group, aggregate and sort records.
local lines={}
for i=1,120 do
    lines[i]=string.format('user%d,group%d,%d,%d',i,i%7,(i*17)%101,i%5+1)
end
local totals={}
for _,line in ipairs(lines) do
    local user,group,price,quantity=line:match('([^,]+),([^,]+),(%d+),(%d+)')
    assert(user and group and price and quantity)
    totals[group]=(totals[group] or 0)+tonumber(price)*tonumber(quantity)
end
local rows={}
for group,total in pairs(totals) do rows[#rows+1]={group=group,total=total} end
table.sort(rows,function(a,b)
    if a.total==b.total then return a.group<b.group end
    return a.total>b.total
end)
assert(#rows==7)
for i,row in ipairs(rows) do print(i,row.group,row.total) end
