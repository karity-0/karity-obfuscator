    -- Integer circuits operate on XOR shares. Only observable predicates and
    -- explicit native/affine boundaries combine a finished pair of shares.
    local function _emask()
        _RX[5]=(_RX[5] or _RZ)-7046029254386353131
        return _rmix(_RX[5])
    end

    local function _eand(a,b,c,d)
        local mask=_emask()
        return (a&c)~mask,(b&d)~(a&d)~(b&c)~mask
    end

    local function _eor(a,b,c,d)
        local x,y=_eand(a,b,c,d)
        return a~c~x,b~d~y
    end

    local function _eadd(a,b,c,d)
        local p,q=a~c,b~d
        local sum,share=p,q
        local g,h=_eand(a,b,c,d)
        for shift=0,5 do
            local distance=1<<shift
            local x,y=_eand(p,q,g<<distance,h<<distance)
            g,h=g~x,h~y
            if shift<5 then p,q=_eand(p,q,p<<distance,q<<distance) end
        end
        return sum~(g<<1),share~(h<<1)
    end

    local function _eneg(a,b)
        return _eadd(~a,b,1,0)
    end

    local function _esub(a,b,c,d)
        local x,y=_eneg(c,d)
        return _eadd(a,b,x,y)
    end

    local function _emul_public(a,b,factor)
        -- The factor is representation metadata, never a guest operand.
        local x,y=0,0
        for bit=0,63 do
            if ((factor>>bit)&1)~=0 then x,y=_eadd(x,y,a<<bit,b<<bit) end
        end
        return x,y
    end

    local function _emul(a,b,c,d)
        local x,y=0,0
        for bit=0,63 do
            local u,v=_eand(a<<bit,b<<bit,-((c>>bit)&1),-((d>>bit)&1))
            x,y=_eadd(x,y,u,v)
        end
        return x,y
    end

    local function _eselect(a,b,c,d,s,t)
        -- Select a/b when the shared predicate is one, c/d otherwise.
        local x,y=_eand(a~c,b~d,-(s&1),-(t&1))
        return c~x,d~y
    end

    local function _enonzero(a,b)
        for shift=5,0,-1 do
            local distance=1<<shift
            a,b=_eor(a,b,a>>distance,b>>distance)
        end
        return a&1,b&1
    end

    local function _eult(a,b,c,d)
        local x,y=_esub(a,b,c,d)
        local u,v=_eand(~a,b,c,d)
        local p,q=_eor(~a,b,c,d)
        p,q=_eand(p,q,x,y)
        u,v=_eor(u,v,p,q)
        return u>>63,v>>63
    end

    local function _eshift(a,b,c,d,right)
        local sign,signshare=c>>63,d>>63
        local x,y=_eneg(c,d)
        x,y=_eselect(x,y,c,d,sign,signshare)
        local left,leftshare,reverse,reverseshare=a,b,a,b
        for bit=0,5 do
            local distance=1<<bit
            local s,t=(x>>bit)&1,(y>>bit)&1
            left,leftshare=_eselect(left<<distance,leftshare<<distance,left,leftshare,s,t)
            reverse,reverseshare=_eselect(reverse>>distance,reverseshare>>distance,reverse,reverseshare,s,t)
        end
        local out,outshare=_eselect(reverse,reverseshare,left,leftshare,sign~(right and 1 or 0),signshare)
        local large,largeshare=_enonzero(x>>6,y>>6)
        return _eselect(0,0,out,outshare,large,largeshare)
    end

    local function _edivmod(a,b,c,d,modulo)
        local zero,zeroshare=_enonzero(c,d)
        if (zero~zeroshare)==0 then
            error(modulo and "attempt to perform 'n%0'" or 'attempt to divide by zero',0)
        end
        local sa,sb,sc,sd=a>>63,b>>63,c>>63,d>>63
        local x,y=_eneg(a,b)
        x,y=_eselect(x,y,a,b,sa,sb)
        local v,w=_eneg(c,d)
        v,w=_eselect(v,w,c,d,sc,sd)
        local q,qs,r,rs=0,0,0,0
        for bit=63,0,-1 do
            local high,highshare=r>>63,rs>>63
            r,rs=(r<<1)|((x>>bit)&1),(rs<<1)|((y>>bit)&1)
            local less,lessshare=_eult(r,rs,v,w)
            local take,takeshare=_eor(high,highshare,less~1,lessshare)
            take,takeshare=take&1,takeshare&1
            local diff,diffshare=_esub(r,rs,v,w)
            r,rs=_eselect(diff,diffshare,r,rs,take,takeshare)
            q,qs=q|(take<<bit),qs|(takeshare<<bit)
        end
        local negative,negativeshare=sa~sc,sb~sd
        local nq,nqs=_eneg(q,qs)
        q,qs=_eselect(nq,nqs,q,qs,negative,negativeshare)
        local nr,nrs=_eneg(r,rs)
        r,rs=_eselect(nr,nrs,r,rs,sa,sb)
        local nonzero,nonzeroshare=_enonzero(r,rs)
        local correct,correctshare=_eand(negative,negativeshare,nonzero,nonzeroshare)
        if modulo then
            nr,nrs=_eadd(r,rs,c,d)
            return _eselect(nr,nrs,r,rs,correct,correctshare)
        end
        nq,nqs=_eadd(q,qs,-1,0)
        return _eselect(nq,nqs,q,qs,correct,correctshare)
    end

    local function _eaffine(a,b,scale,bias)
        local x,y=_emul_public(a,b,scale)
        x,y=_eadd(x,y,bias,0)
        return x~y
    end

    local function _ebit_store(dst,a,b,salt)
        if boxes[dst] then
            local box=boxes[dst]
            if _UY and not box.get and not box.set then
                -- Use the existing cross-frame cell format and epoch policy.
                -- Protected string owners must be cleared on integer overwrite.
                _PS.cell_set(box,0)
                _UC=_UC+1
                local epoch=_rmix(_RZ~_UC~(_SS[1] or 0)~(_XF[2] or 0)~__VM_UV_SEED__)
                local pair=_RP[(epoch&15)+1]
                local bias=_rmix(epoch~__VM_UV_BIAS__)
                local encoded=_eaffine(a,b,pair[1],bias)
                local share=_rmix(epoch~__VM_UV_SHARE__)
                _UV[box]={[__VM_UV_LEFT__]=encoded-share,[__VM_UV_RIGHT__]=share,
                          [__VM_UV_EPOCH__]=epoch,[__VM_UV_KIND__]=1}
                box.v=nil;box.refs=nil
                _RC={};_RX[3][dst]=nil
                _ss_value(-31,encoded,epoch,1)
                return
            end
            -- Shared cells are observable by closures/callbacks. Commit through
            -- their existing coherent API at this explicit native boundary.
            rset(dst,a~b)
            return
        end
        local epoch=_rnext(dst,salt)
        local mask=_emask()
        _PD[_rpos(5,dst)]={false,a~mask,b~mask,nil,nil,epoch}
        _RC[dst]=nil;_RX[3][dst]=nil;_RL[dst]=true
    end

    local function _ebit_snapshot(slot)
        if boxes[slot] then
            local box=boxes[slot]
            -- External cell accessors may call or yield. Type probing must not
            -- invoke one before the ordinary read and repeat its side effects.
            if box.get or box.set then return nil end
            local q=_UY and not box.get and _UV[box]
            if q and q[__VM_UV_KIND__]==1 then
                local epoch=q[__VM_UV_EPOCH__]
                local pair=_RP[(epoch&15)+1]
                local bias=_rmix(epoch~__VM_UV_BIAS__)
                local a,b=_eadd(q[__VM_UV_LEFT__],0,q[__VM_UV_RIGHT__]-bias,0)
                return _emul_public(a,b,pair[2])
            end
            local value=get_upvalue(box)
            if math.type(value)~='integer' then return nil end
            local mask=_emask()
            return value~mask,mask
        end
        local packet=_PD[_rpos(5,slot)]
        if packet and packet[1]==false then return packet[2],packet[3] end
        if packet then _pending_finish(slot) end
        local p1,p2,p3,p4=_rpositions(slot)
        local epoch=_RE[p3]
        if epoch==nil or _RT[p4]~=1 then return nil end
        local cache=_RX[6]
        if not cache then cache={};_RX[6]=cache end
        local saved=cache[slot]
        if saved and saved[1]==epoch and saved[2]==_MG[1] then return saved[3],saved[4] end
        local _,bias,inverse=_rparams(slot,epoch)
        -- Convert additive affine shares through masked addition and public
        -- multiplication. The original integer is never combined here.
        local a,b=_eadd(regs[p1],0,_RS[p2]-bias,0)
        a,b=_emul_public(a,b,inverse)
        cache[slot]={epoch,_MG[1],a,b}
        return a,b
    end

    local function _ebit2(dst,lhs,rhs,selector)
        local a,b=_ebit_snapshot(lhs)
        if a==nil then return false end
        local c,d
        if lhs==rhs then c,d=a,b else c,d=_ebit_snapshot(rhs) end
        if c==nil then return false end
        local x,y
        if selector==4 then x,y=a~c,b~d
        elseif selector==2 then x,y=_eand(a,b,c,d)
        elseif selector==3 then x,y=_eor(a,b,c,d)
        elseif selector==5 or selector==6 then x,y=_eshift(a,b,c,d,selector==6)
        elseif selector==7 or selector==8 then x,y=_edivmod(a,b,c,d,selector==7)
        elseif selector==1 then x,y=_eadd(a,b,c,d)
        elseif selector==-1 then x,y=_esub(a,b,c,d)
        else x,y=_emul(a,b,c,d) end
        _ebit_store(dst,x,y,selector~lhs~(rhs<<8))
        return true
    end

    local function _ebit1(dst,src,negate)
        local a,b=_ebit_snapshot(src)
        if a==nil then return false end
        if negate then a,b=_eneg(a,b) else a=~a end
        _ebit_store(dst,a,b,src~0x424E4F54)
        return true
    end

    local function _eint_copy(dst,src)
        local packet=_PD[_rpos(5,src)]
        if (not packet or packet[1]~=false) and _elinear1(dst,src,1) then return end
        local a,b=_ebit_snapshot(src)
        assert(a~=nil,'invalid integer copy proof')
        if boxes[dst] then _ebit_store(dst,a,b,src~0x434F5059); return end
        local epoch=_rnext(dst,src~0x434F5059)
        local scale,bias=_rparams(dst,epoch)
        _rstore(dst,_eaffine(a,b,scale,bias),epoch,1)
    end

    local function _esplit_copy(dst,src)
        local packet=_PD[_rpos(5,src)]
        local _,_,_,kind=_rpositions(src)
        if (packet and packet[1]==false) or _RT[kind]==1 then
            _eint_copy(dst,src)
        else rset(dst,rget(src)) end
    end

    local function _ecmp2(lhs,rhs,selector)
        local a,b=_ebit_snapshot(lhs)
        if a==nil then return nil end
        local c,d
        if lhs==rhs then c,d=a,b else c,d=_ebit_snapshot(rhs) end
        if c==nil then return nil end
        local x,y
        if selector==0 then
            x,y=_enonzero(a~c,b~d)
            return (x~y)==0
        end
        if selector==2 then a,b,c,d=c,d,a,b end
        local diff,diffshare=_esub(a,b,c,d)
        local overflow,overflowshare=_eand(a~c,b~d,a~diff,b~diffshare)
        x,y=(diff~overflow)>>63,(diffshare~overflowshare)>>63
        return (x~y)==(selector==2 and 0 or 1)
    end
