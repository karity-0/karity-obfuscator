"""Specialize existing CALL handlers without extending the instruction ABI."""
from .backends.handler_layout import iter_protos


def call_signatures(lowered):
    return frozenset((i.b,i.c) for f in iter_protos(lowered.program)
                     for i in f.code if i.operation=='CALL')


def prepare_classic_calls(source,lowered,target=None):
    if getattr(lowered,'program',None) is None:return source
    native=target is None or target.security_runtime_options()['native_table_pack']
    api=target.value_packet_api() if target else ('table.pack','table.unpack')
    return classic_calls(source,call_signatures(lowered),packet_api=api,source_calls=not native)


def _optional_packet(source):
    clear='for key in pairs(packet) do packet[key]=nil end'
    if source.count(clear)!=1:raise ValueError('CALL packet ownership boundary changed')
    optional='if packet then '+clear+' end'
    return source if optional in source else source.replace(clear,optional,1)


def _result(call,count,pack):
    if count==1:return call+'\n'
    if 2<=count<=4:
        names=[f'_cr{i}' for i in range(1,count)]
        return ('local '+','.join(names)+'='+call+'\n'+
                '\n'.join(f'_open_set(A+{i},{name})' for i,name in enumerate(names))+'\n'+
                ','.join(names)+'='+','.join('nil' for _ in names)+'\n')
    return (f'local res={pack}({call})\n'
            'if C==0 then _store_values(A,res,res.n);top=A+res.n-1\n'
            'elseif C>1 then _store_values(A,res,C-1) end\nres=nil\n')


def classic_calls(source,signatures,*,packet_api=('table.pack','table.unpack'),
                  source_calls=False,specialize=True):
    """Last-position trim returns zero values: no extra argument or live packet."""
    # Large/open counts share the original packet path. Grouping them bounds
    # native dispatch to 24 shapes instead of one branch per observed count.
    shapes={(b if 1<=b<=4 else 0,c if 1<=c<=4 else 0) for b,c in signatures}
    shapes.discard((0,0))
    selected=sorted(shapes,key=lambda v:(v[0]==0,v[0],v[1]==0,v[1]))
    if not selected:return source
    start=source.index('        elseif op==36 then\n')
    end=source.index('        elseif op==37 then\n',start)
    original=source[start+len('        elseif op==36 then\n'):end]
    generic=original.replace('local fn=rget(A); local ca','local ca',1)
    generic=generic.replace('local vm=_VF[fn];local res','local res',1)
    if generic==original or 'local vm=_VF[fn]' in generic:
        raise ValueError('Classic CALL template boundary changed')
    pack,unpack=packet_api
    prefix='_source_call,fn,upvals,_source_parents' if source_calls else 'fn'
    branches=[]
    for b,c in selected:
        setup=''
        if 1<=b<=4:
            arguments=','.join(f'_open_get(A+{i})' for i in range(1,b))
            arguments=(arguments+',' if arguments else '')+'_stack_trim(A)'
            call=f'_call_packet(nil,{prefix},{arguments})'
        else:
            setup=('local ca\nif B==0 then ca=_collect_values(A+1)\n'
                   'else ca=_collect_values(A+1,B-1) end\n'
                   'local ca_n=ca.n\n_stack_trim(A)\n')
            call=f'_call_packet(ca,{prefix},{unpack}(ca,1,ca_n))'
        condition=' and '.join(([f'B=={b}'] if b else [])+([f'C=={c}'] if c else []))
        branches.append((condition,setup+_result(call,c,pack)))
    # Keep VM calls out of the entire arity chain, including broad call sites.
    # Reuse the original fallback verbatim (5.1 may still require source_call).
    body='local fn=rget(A);local vm=_VF[fn]\nif vm then\n'+generic
    if specialize and len(signatures)==1:
        body+='else\n'+branches[0][1]
    else:
        body+='\n'.join('elseif '+condition+' then\n'+code for condition,code in branches)
        body+='else\n'+generic
    body+='end\n\n'
    source=source[:start]+'        elseif op==36 then\n'+body+source[end:]
    return _optional_packet(source)
