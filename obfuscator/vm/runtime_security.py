"""Install shared host guards and Karity's protected-string value boundary."""
from pathlib import Path
import random
import re


# Compiler-owned invariant failures have no useful guest-facing diagnostic.
# Preserve semantic errors (numeric for, division, explicit guest error calls)
# and the separate integrity-failure path. Templates retain their diagnostics
# for development; only the assembled VM is made opaque before output passes.
_INTERNAL_DIAGNOSTICS = frozenset({
    'invalid blob', 'bad blob uint32', 'noncanonical blob uint32',
    'unterminated blob uint32', 'unsupported handler blob format',
    'bad metadata mode', 'bad metadata count', 'bad metadata index',
    'truncated blob string', 'bad const tag ', 'argument packet mismatch ',
    'unexpected EXTRAARG', 'unknown op ', 'unreachable',
    'unknown arithmetic slot', 'unknown unary slot',
    'register vault index mismatch', 'register vault exhausted',
    'invalid virtualized upvalue index', 'MOV field overflow',
    'invalid MOV field', 'MOV instruction pointer out of range',
    'bad MOV instruction', 'unexpected MOV host jump',
    'bad synthesis storage', 'bad synthesis dictionary', 'bad synthesis operands',
    'bad synthesis count', 'bad synthesis span', 'bad synthesis word',
    'bad MOV version', 'bad MOV alphabet', 'bad MOV VM assignment',
    'bad MOV entry count', 'bad MOV prototype count',
})


def _internal_diagnostic(ctx, arguments, index=0) -> bool:
    values = [node for node in arguments.named_children if node.type != 'comment']
    first = values[index] if index<len(values) else None
    # A diagnostic may append register/opcode values. Remove that whole error
    # object, including tostring calls, rather than retaining revealing suffixes.
    while first is not None:
        if first.type == 'parenthesized_expression':
            first = next((node for node in first.named_children if node.type != 'comment'), None)
        elif first.type == 'binary_expression':
            operator = first.child_by_field_name('operator')
            if operator is None or ctx.plain_text(operator) != '..':
                return False
            first = first.child_by_field_name('left')
        else:
            break
    if first is None or first.type != 'string':
        return False
    text = ctx.plain_text(first)
    # Authored invariant messages are ASCII short literals with no escapes.
    if text[0] not in {'"', "'"} or text[-1] != text[0]:
        return False
    message = text[1:-1]
    return (message in _INTERNAL_DIAGNOSTICS or
            message.startswith('unsupported Lua 5.1 MOV operation: '))


def prepare(source: str, *, backend: str, native_unpack: str, globals_name: str,
            native_table_pack: bool) -> str:
    expressions = ['debug.getinfo','debug.gethook','string.dump','string.byte','string.char','string.len',
                   'string.sub','string.format','string.match','string.find','table.concat',native_unpack,
                   'string','table','math','debug','type','rawget','error','pcall','tostring','tonumber','select','getmetatable','setmetatable','next','pairs','ipairs','math.floor','math.max','math.min']
    bindings=[]
    for expression in expressions:
        if '.' in expression:
            owner,key=expression.rsplit('.',1)
        else:
            owner,key=globals_name,expression
        bindings.append('{'+owner+',"'+key+'",'+expression+'}')
    runtime=(Path(__file__).parent/'runtimes/protected_strings.lua').read_text(encoding='utf8')
    from .host_guards import GUARD_SOURCE
    runtime=runtime.replace('--<<SHARED_HOST_GUARD>>',GUARD_SOURCE)
    runtime=runtime.replace('__PS_UNPACK__',native_unpack).replace('__PS_BINDINGS__','{'+','.join(bindings)+'}')
    anchor='--<<TARGET_CONSTANT_RESOLVER>>'
    if source.count(anchor)!=1:
        raise ValueError('protected string resolver boundary is missing')
    source=_capture_source(native_unpack=native_unpack,native_table_pack=native_table_pack)+'local _PS,_PS_GUARD\n'+source.replace(anchor,runtime+'\n'+anchor,1)
    source=source.replace('local env_box={v=_ENV}', 'local env_box={v=_ENV_GUEST}')
    source=source.replace('apack=_apack,env=_ENV,', 'apack=_apack,env=_ENV_GUEST,')
    source=source.replace('return fn(...)',
        'if fn==setmetatable and _ENV_REFRESH then local object=...; '
        '_ENV_REFRESH(object,false);local result=fn(...);_ENV_REFRESH(object,true);'
        'return result end;return fn(...)')
    resolver='_PS.constant(k)' if backend=='karity' else '_PS.open(_PS.constant(k))'
    source=source.replace('return _kss(k[2])','return '+resolver)
    # RK constants and LOADK must share the same checked envelope/cache.
    source=source.replace('_kss(_c[2])','kval(_c,proto)')
    source=source.replace('local dump=_function_dump(self_func)', '_PS.guard(true)\n    local dump=_function_dump(self_func)')
    source=re.sub(r'(local function _invoke_closure\([^\n]+\)\n)',r'\1    _PS.guard(true)\n',source)
    source=re.sub(r'(local function _call_packet\([^\n]+\)\n)',r'\1    _PS.guard(true)\n',source)
    source=source.replace('--[[VM_DISPATCH_ENTRY]] while true do','--[[VM_DISPATCH_ENTRY]] while true do\n        _PS.guard(false)')
    # Authorize actual VM stores while keeping the runtime's captured APIs.
    source=source.replace('get_upvalue(upvals[A+1])[rget(B)]=rget(C)',
                          '_PS.write(get_upvalue(upvals[A+1]),rget(B),rget(C))')
    source=source.replace('rget(A)[rget(B)]=rget(C)',
                          '_PS.write(rget(A),rget(B),rget(C))')
    source=source.replace('get_environment(upvals)[kval(consts[Bx+1],proto)]=rget(A)',
                          '_PS.write(get_environment(upvals),kval(consts[Bx+1],proto),rget(A))')
    source=source.replace('local function _tset(t,k,v) t[k]=v end',
                          'local function _tset(t,k,v) _PS.write(t,k,v) end')
    if backend!='karity':
        source=source.replace('x[y]=z','_PS.write(x,y,z)')
    if backend=='karity':
        source=_karity(source)
    source=re.sub(r'(local function _native_call\([^\n]+\)\n)',r'\1        _PS.guard(true)\n',source)
    return source.replace('_PS.guard(', '_PS_GUARD(')


def _karity(source: str) -> str:
    source=source.replace('local function rset(i,v)\n','local function rset(i,v)\n        v=_PS.seal(v)\n')
    source=source.replace('local function _rvalue(v,epoch)\n','local function _rvalue(v,epoch)\n        v=_PS.seal(v)\n')
    source=source.replace('if box.get then return box.get() end','if box.get then return _PS.seal(box.get()) end')
    source=source.replace('if not _UY then return box.v end','if not _UY then return _PS.cell_get(box,box.v) end')
    source=source.replace('return box.refs[payload]','return _PS.cell_get(box,box.refs[payload])')
    source=source.replace('return box.refs[index_lo]','return _PS.cell_get(box,box.refs[index_lo])')
    source=source.replace('set_upvalue=function(box,v)\n','set_upvalue=function(box,v)\n        v=_PS.cell_set(box,v)\n')
    source=source.replace('if box.set then box.set(v)','if box.set then box.set(_PS.open(v))')
    source=source.replace('_texpose=function(v,seen)\n','_texpose=function(v,seen)\n        if _PS.is(v) then return _PS.open(v) end\n')
    source=source.replace('local function _tlen(t)\n','local function _tlen(t)\n        if _PS.is(t) then return _PS.length(t) end\n')
    source=source.replace('local function _tkey(m,k,create)\n','local function _tkey(m,k,create)\n        k=_PS.open(k)\n')
    source=source.replace('local function _tget(t,k)\n','local function _tget(t,k)\n        k=_PS.open(k)\n        if _PS.is(t) then\n            local index=(getmetatable("") or {}).__index\n            if type(index)=="table" then return index[k] end\n            return _PS.open(t)[k]\n        end\n')
    source=source.replace('t[_texpose(k)]=_texpose(v); return','_PS.write(t,_texpose(k),_texpose(v)); return')
    source=source.replace('local function _tset(t,k,v)\n','local function _tset(t,k,v)\n        k=_PS.open(k)\n')
    source=source.replace('local function _arith2(a,b,av,slot,desc)\n','local function _arith2(a,b,av,slot,desc)\n        a,b=_PS.open(a),_PS.open(b)\n')
    source=source.replace('local function _arith1(a,av,slot,desc)\n','local function _arith1(a,av,slot,desc)\n        a=_PS.open(a)\n')
    source=source.replace('local function _for_values(initial,limit,step)\n','local function _for_values(initial,limit,step)\n    initial,limit,step=_PS.open(initial),_PS.open(limit),_PS.open(step)\n')
    sem='''
        if tag==__VM_DATA_VALUE__ then x=_PS.check(x) end
        if tag==__VM_CMP_TRUTH__ and _PS.is(x) then return true end
        if tag==__VM_OP_NOT__ and _PS.is(x) then return false end
        if tag==__VM_CMP_EQ__ and (_PS.is(x) or _PS.is(y)) then return _PS.equal(x,y) end
        if tag==__VM_OP_LEN__ and _PS.is(x) then return _PS.length(x) end
        if tag==__VM_OP_CONCAT__ then
            local joined=_PS.join(x,z)
            if joined then return joined end
            local values={};for i=1,z do values[i]=_PS.open(x[i]) end;x=values
        elseif tag==__VM_DATA_GET__ then
            if _PS.is(x) then
                local index=(getmetatable("") or {}).__index
                if type(index)=="table" then return index[_PS.open(y)] end
            end
            y=_PS.open(y)
        elseif tag==__VM_DATA_SET__ then
            y=_PS.open(y)
            if not _TY and _PS.watched(x,y) then _PS.write(x,y,_PS.open(z));return nil end
        elseif tag==__VM_OP_SETLIST__ and not _TY then
            local values={};for i=1,z[2] do values[i]=_PS.open(y[i]) end;y=values
        end
'''
    source=source.replace('local function _sem(tag,x,y,z)\n','local function _sem(tag,x,y,z)\n'+sem)
    # Native fallback graph families must receive ordinary Lua operands.
    source=source.replace('local site=((pc-1)<<32)~tag','if tag~=__VM_DATA_VALUE__ then x,y,z=_PS.open(x),_PS.open(y),_PS.open(z) end\n        local site=((pc-1)<<32)~tag')
    source=source.replace('local site=_pxor(_pshl(pc-1,32),tag)','if tag~=__VM_DATA_VALUE__ then x,y,z=_PS.open(x),_PS.open(y),_PS.open(z) end\n        local site=_pxor(_pshl(pc-1,32),tag)')
    # Lua 5.1 has a target-native semantic route with an equivalent boundary.
    source=re.sub(r'for i=1,count do args\[i\]=_texpose\(args\[i\]\) end\s*local result=([^\n]+)',
                  r'''local _handled,_value=_PS.native(fn,args,count,_tget,_tlen)
        local result
        if _handled then
            result={n=1,[1]=_value}
            for key in pairs(args) do args[key]=nil end
        else
            fn=_PS.open(fn)
            for i=1,count do args[i]=_texpose(args[i]) end
            result=\1
        end
        _PS.guard(true)''',source)
    return source


_CORE_GLOBALS=('type','rawget','rawset','select','tonumber','tostring','error',
               'pcall','xpcall','getmetatable','setmetatable','next','pairs','ipairs')
_CORE_MEMBERS={
    'string':('byte','char','sub','dump','format','match','find','len','rep','gmatch','gsub','pack','unpack'),
    'table':('concat','unpack','pack','insert','remove','sort'),
    'debug':('getinfo','gethook'),
    'math':('floor','ceil','max','min','abs','modf','sqrt','huge','frexp','ldexp',
            'type','tointeger','mininteger','maxinteger'),
    'os':('clock','time','setlocale'),
}
_CORE_53_ONLY={'string.pack','string.unpack','math.type','math.tointeger',
               'math.mininteger','math.maxinteger'}


def _capture_source(*, native_unpack: str, native_table_pack: bool) -> str:
    entries=[name+'='+name for name in _CORE_GLOBALS]
    for owner,names in _CORE_MEMBERS.items():
        for name in names:
            if not native_table_pack and owner+'.'+name in _CORE_53_ONLY:
                continue
            if owner=='table' and ((name=='pack' and not native_table_pack) or
                                   (name=='unpack' and native_unpack!='table.unpack')):
                continue
            entries.append(owner+'_'+name+'='+owner+'.'+name)
    if native_unpack=='unpack': entries.append('unpack=unpack')
    return ('--<<SECURITY_CAPTURE>>\nlocal _PS_CORE={'+','.join(entries)+'}\n'
            '--<<ENDSECURITY_CAPTURE>>\n')


def _private_field_edits(ctx, bindings):
    """Number only the compiler-owned value/API banks, including escaped keys."""
    start=ctx.script.find('--<<SECURITY_VALUES>>')
    end=ctx.script.find('--<<ENDSECURITY_VALUES>>')
    if start<0 or end<=start:
        return []
    groups={node.id:('api' if binding.original=='A' else 'values')
            for binding in bindings if binding.original in {'_PS','S','A'}
            and any(start<=ctx.cs(node)<end for node in binding.nodes)
            for node in binding.nodes}

    def owner_group(node):
        if node.type=='identifier':
            return groups.get(node.id)
        if node.type=='dot_index_expression':
            owner,key=node.named_children
            if ctx.plain_text(key)=='api' and owner_group(owner)=='values':
                return 'api'
        return None

    accesses=[]
    fields=[]
    records=[]
    keys={'values':set(),'api':set()}
    for node in ctx.walk():
        if node.type=='dot_index_expression':
            owner,key=node.named_children
            group=owner_group(owner)
            if group:
                name=ctx.plain_text(key)
                keys[group].add(name)
                accesses.append((node,owner,key,group,name))
        elif node.type=='assignment_statement':
            name=node.child_by_field_name('name')
            value=node.child_by_field_name('value')
            if (name is not None and name.id in groups and groups[name.id]=='values'
                    and value is not None and value.type=='table_constructor'):
                for field in value.named_children:
                    key=field.child_by_field_name('name')
                    if key is None:continue
                    name=ctx.plain_text(key);keys['values'].add(name)
                    fields.append((key,'values',name))
                    api=field.child_by_field_name('value')
                    if name=='api' and api is not None and api.type=='table_constructor':
                        for member in api.named_children:
                            key=member.child_by_field_name('name')
                            name=ctx.plain_text(key);keys['api'].add(name)
                            fields.append((key,'api',name))
        elif node.type=='table_constructor' and start<=ctx.cs(node)<end:
            # Integrity records contain {S,'api',A}; generic iterations already
            # carry their numeric key through unchanged.
            items=node.named_children
            if len(items)==3 and all(len(item.named_children)==1 for item in items):
                owner,key,value=(item.named_children[0] for item in items)
                if (owner_group(owner)=='values' and key.type=='string'
                        and ctx.plain_text(key) in {"'api'",'"api"'} and owner_group(value)=='api'):
                    keys['values'].add('api');records.append(key)
    ordered=[(group,name) for group,names in keys.items() for name in sorted(names)]
    slots=dict(zip(ordered,random.sample(range(31,4096),len(ordered))))
    edits=[(ctx.cs(key),ctx.ce(key)+1,f'[{slots[group,name]}]') for key,group,name in fields]
    edits.extend((ctx.cs(key),ctx.ce(key)+1,str(slots['values','api'])) for key in records)
    for node,owner,key,group,name in accesses:
        slot=slots[group,name]
        parent=node.parent
        if parent.type=='function_declaration' and parent.child_by_field_name('name')==node:
            edits.append((ctx.cs(parent),ctx.ce(node)+1,f'{ctx.plain_text(owner)}[{slot}]=function'))
        else:
            # Replace only the dot/key suffix so nested _PS.api.byte accesses
            # can independently rewrite both owned table levels.
            edits.append((ctx.ce(owner)+1,ctx.ce(key)+1,f'[{slot}]'))
    return edits


def _freeze_calls(source: str) -> str:
    """Freeze native references into numeric slots and hide internal diagnostics."""
    from ..passes.ts_utils import parse
    from ..passes.rename_ts import resolve_bindings
    ctx=parse(source)
    free: dict[int, object]={}
    names=set(_CORE_GLOBALS)|set(_CORE_MEMBERS)|{'unpack','_PS_CORE','_PS','S','A','assert'}
    bindings, *_ = resolve_bindings(ctx,free_environments=free,collect_literals=False,
                                   identifier_filter=lambda node:ctx.plain_text(node) in names)
    start=source.find('--<<SECURITY_CAPTURE>>')
    end=source.find('--<<ENDSECURITY_CAPTURE>>')
    if start < 0 or end <= start:
        raise ValueError('native capture boundary is missing')
    # This generator-owned bank escapes into generic integrity records, so the
    # general StripInfo pass cannot safely rename its keys. Bind its declaration
    # and every static use here, before output passes and runtime identity binding.
    core_nodes={node.id for binding in bindings if binding.original=='_PS_CORE'
                and any(start<=ctx.cs(node)<end for node in binding.nodes)
                for node in binding.nodes}
    capture=next(node for node in ctx.walk() if node.type=='table_constructor'
                 and start<=ctx.cs(node)<ctx.ce(node)<end)
    keys=[*_CORE_GLOBALS,'unpack',
          *(owner+'_'+name for owner,members in _CORE_MEMBERS.items() for name in members)]
    slots=dict(zip(keys,random.sample(range(31,4096),len(keys))))
    entries=[]
    available=set()
    for field in capture.named_children:
        key,value=field.named_children
        available.add(ctx.plain_text(key))
        entries.append(f'[{slots[ctx.plain_text(key)]}]={ctx.plain_text(value)}')
    random.shuffle(entries)
    edits=[(ctx.cs(capture),ctx.ce(capture)+1,'{'+','.join(entries)+'}')]
    edits.extend(_private_field_edits(ctx,bindings))
    aliases={owner+'.'+name:f'_PS_CORE[{slots[owner+"_"+name]}]'
             for owner,members in _CORE_MEMBERS.items() for name in members}
    globals_alias={name:f'_PS_CORE[{slots[name]}]' for name in (*_CORE_GLOBALS,'unpack')}
    stack=[ctx.root]
    while stack:
        node=stack.pop()
        if start>=0 and start<=ctx.cs(node) and ctx.ce(node)<end+len('--<<ENDSECURITY_CAPTURE>>'):
            continue
        if node.type == 'function_call':
            function = node.child_by_field_name('name')
            arguments = node.child_by_field_name('arguments')
            if (function is not None and function.type=='identifier' and function.id in free
                    and ctx.plain_text(function)=='assert' and node.parent is not None and node.parent.type=='block'
                    and arguments is not None and _internal_diagnostic(ctx,arguments,1)):
                # These compiler-owned assertions are statement guards. Keep
                # their short-circuit condition, but omit the diagnostic object.
                condition=next(n for n in arguments.named_children if n.type!='comment')
                edits.append((ctx.cs(node),ctx.ce(node)+1,
                              'if not ('+ctx.plain_text(condition)+') then '+globals_alias['error']+'(nil,0) end'))
                continue
            if (function is not None and function.type == 'identifier' and
                    function.id in free and ctx.plain_text(function) == 'error' and
                    arguments is not None and _internal_diagnostic(ctx, arguments)):
                edits.append((ctx.cs(arguments), ctx.ce(arguments)+1, '(nil,0)'))
                # Still capture the native error function, without overlapping
                # edits inside the discarded diagnostic expression.
                stack.append(function)
                continue
        replacement=None
        if node.type=='dot_index_expression':
            owner=node.named_children[0]
            if owner.id in core_nodes:
                slot=slots.get(ctx.plain_text(node.named_children[-1]))
                if slot is not None: replacement=f'_PS_CORE[{slot}]'
            elif owner.id in free:
                replacement=aliases.get(ctx.plain_text(node))
                if replacement and ctx.plain_text(node).replace('.','_') not in available:
                    raise ValueError('native API is unavailable for the selected target: '+ctx.plain_text(node))
        elif node.type=='identifier' and node.id in free:
            replacement=globals_alias.get(ctx.plain_text(node))
        if replacement:
            edits.append((ctx.cs(node),ctx.ce(node)+1,replacement))
        else:
            stack.extend(node.named_children)
    for start,end,replacement in sorted(edits,reverse=True):
        source=source[:start]+replacement+source[end:]
    return source.replace('--<<SECURITY_VALUES>>','').replace('--<<ENDSECURITY_VALUES>>','')
