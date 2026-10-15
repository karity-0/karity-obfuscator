"""Guarded raw temporaries with the original encoded commits still mandatory.

Specialize the existing helpers rather than copy their graph/linear algorithms.
Ordinary handlers and pending producer paths continue using the old ABI.
"""
from .strategies import SCALAR


def active_values(entry,defers):
    from ..backends.handler_ir import OPERATION_IDS
    deferred={n for n,step in enumerate(entry.recipe.steps)
              if defers.get(OPERATION_IDS[step.operation])==entry.original_vops[n]}
    eligible=set(entry.occurrence.local_values)-deferred
    return eligible & {
        a for a,b in entry.recipe.edges if b not in deferred}


def helper_arities(entry,defers):
    from ..backends.handler_ir import OPERATION_IDS
    if not active_values(entry,defers):return set()
    return {len(step.inputs) for n,step in enumerate(entry.recipe.steps) if step.operation in SCALAR
            and defers.get(OPERATION_IDS[step.operation])!=entry.original_vops[n]}


def guarded_read(value,epoch,generation,position,field,target):
    return (f'local {target}; if {value}~=nil and {generation}==_MG[1] and '
            f'{epoch}==_RE[{position}] and _PD[_rpos(5,{field})]==nil then {target}={value} end')


def helper_source(template, arities):
    pieces=[]
    for arity,following in ((2,'_arith1r'),(1,'_arith2s')):
        if arity not in arities:continue
        name=f'_arith{arity}r'
        a=template.index(f'local function {name}(')
        b=template.index(f'local function {following}(',a)
        body=template[a:b].rstrip()
        if arity==2:
            old='(dst,lhs,rhs,av,slot,linear)'
            body=body.replace(old,'(dst,lhs,rhs,av,slot,linear,left,right)',1)
            body=body.replace('local left=rget(lhs)','if left==nil then left=rget(lhs) end',1)
            body=body.replace('local right\n','',1)
            body=body.replace('else right=rget(rhs) end','elseif right==nil then right=rget(rhs) end',1)
            old_commit='rset(dst,_arith2(left,right,av,slot,desc))'
            new_commit='local result=_arith2(left,right,av,slot,desc)\n        rset(dst,result)\n        return result'
        else:
            old='(dst,src,av,slot,linear)'
            body=body.replace(old,'(dst,src,av,slot,linear,value)',1)
            old_commit='rset(dst,_arith1(rget(src),av,slot,desc))'
            new_commit=('if value==nil then value=rget(src) end\n'
                        '        local result=_arith1(value,av,slot,desc)\n'
                        '        rset(dst,result)\n        return result')
        if old_commit not in body or old in body:
            raise ValueError('Karity register-local helper contract changed: '+name)
        body=body.replace(old_commit,new_commit,1)
        pieces.append(body.replace('function '+name+'(','function _syn'+name+'(',1))
    return '\n'.join(pieces)+'\n' if pieces else ''
