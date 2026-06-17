-- load 기반 패커 스텁: base64 디코드 -> raw DEFLATE inflate -> load 실행.
-- 아래 _D 의 값은 base64(raw-deflate(원본 출력))로, 맨 끝 라인은 실행 라인
-- (테스트 모드면 덤프 라인)으로 빌드 시 치환된다.
local _D="__DATA__"

local _byte=string.byte
local _char=string.char
local _concat=table.concat

local function _b64(s)
    local map={}
    local al="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for i=1,#al do map[_byte(al,i)]=i-1 end
    local out={}; local on=0
    local acc=0; local nb=0
    for i=1,#s do
        local v=map[_byte(s,i)]
        if v then
            acc=(acc<<6)|v; nb=nb+6
            if nb>=8 then nb=nb-8; on=on+1; out[on]=_char((acc>>nb)&0xFF) end
        end
    end
    return _concat(out)
end

local function _inf(data)
    local pos=1
    local buf=0
    local cnt=0
    local function bits(n)
        while cnt<n do buf=buf|(_byte(data,pos)<<cnt); pos=pos+1; cnt=cnt+8 end
        local v=buf&((1<<n)-1); buf=buf>>n; cnt=cnt-n; return v
    end

    local out={}; local on=0

    local function build(lens)
        local count={}; for i=0,15 do count[i]=0 end
        local n=#lens
        for i=1,n do count[lens[i]]=count[lens[i]]+1 end
        count[0]=0
        local offs={}; offs[1]=0
        for i=1,15 do offs[i+1]=offs[i]+count[i] end
        local symbol={}
        for i=1,n do
            local L=lens[i]
            if L~=0 then symbol[offs[L]+1]=i-1; offs[L]=offs[L]+1 end
        end
        return {count=count, symbol=symbol}
    end

    local function decode(h)
        local code=0; local first=0; local idx=0
        local count=h.count
        for len=1,15 do
            code=code|bits(1)
            local c=count[len]
            if code-first<c then return h.symbol[idx+(code-first)+1] end
            idx=idx+c; first=(first+c)<<1; code=code<<1
        end
        return -1
    end

    local lbase={3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258}
    local lext ={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0}
    local dbase={1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577}
    local dext ={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}

    local function inflate_block(lh,dh)
        while true do
            local sym=decode(lh)
            if sym==256 then break
            elseif sym<256 then on=on+1; out[on]=_char(sym)
            else
                sym=sym-256
                local length=lbase[sym]+bits(lext[sym])
                local ds=decode(dh)+1
                local dist=dbase[ds]+bits(dext[ds])
                local start=on-dist
                for i=1,length do on=on+1; out[on]=out[start+i] end
            end
        end
    end

    local order={16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15}

    repeat
        local final=bits(1)
        local btype=bits(2)
        if btype==0 then
            cnt=0; buf=0
            local len=_byte(data,pos)|(_byte(data,pos+1)<<8); pos=pos+4
            for _=1,len do on=on+1; out[on]=_char(_byte(data,pos)); pos=pos+1 end
        elseif btype==1 then
            local ll={}; for i=1,144 do ll[i]=8 end; for i=145,256 do ll[i]=9 end
            for i=257,280 do ll[i]=7 end; for i=281,288 do ll[i]=8 end
            local dl={}; for i=1,30 do dl[i]=5 end
            inflate_block(build(ll), build(dl))
        else
            local hlit=bits(5)+257
            local hdist=bits(5)+1
            local hclen=bits(4)+4
            local cll={}; for i=1,19 do cll[i]=0 end
            for i=1,hclen do cll[order[i]+1]=bits(3) end
            local clh=build(cll)
            local lens={}
            local i=1
            while i<=hlit+hdist do
                local s=decode(clh)
                if s<16 then lens[i]=s; i=i+1
                elseif s==16 then local r=bits(2)+3; local p=lens[i-1]; for _=1,r do lens[i]=p; i=i+1 end
                elseif s==17 then local r=bits(3)+3; for _=1,r do lens[i]=0; i=i+1 end
                else local r=bits(7)+11; for _=1,r do lens[i]=0; i=i+1 end
                end
            end
            local litlens={}; for k=1,hlit do litlens[k]=lens[k] end
            local distlens={}; for k=1,hdist do distlens[k]=lens[hlit+k] end
            inflate_block(build(litlens), build(distlens))
        end
    until final==1

    return _concat(out)
end

__ACTION__
