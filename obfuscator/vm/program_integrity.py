"""Build-bound semantic instruction/layout domains; no serialized format change."""
from pathlib import Path
import math
import random
import re
import struct

MODULUS = 2147483647
SPEC_FIELDS=('header','code_seed','layout_seed','code_tag','layout_tag','code_count',
             'constant_count','capture_count','children','mov_entries','constants','empty_metadata')


def fingerprint(seed, values):
    result=seed
    for value in values:
        if type(value) is not int or not 0<=value<=0xffffffff:
            raise ValueError('program fingerprint requires uint32 canonical fields')
        result=(result*65599+value)%MODULUS
    return result


def manifest(root, entries=None, *, kinds, version):
    functions=[]
    def visit(function):
        index=len(functions)+1
        functions.append((function,[]))
        functions[index-1][1].extend(visit(child) for child in function.children)
        return index
    visit(root)
    if entries is not None and len(entries)!=len(functions):
        raise ValueError('MOV entries differ from program manifest functions')
    records=[]
    for index,(function,children) in enumerate(functions,1):
        proto=function.source
        seeds=random.sample(range(1,MODULUS),3)
        header=[proto.num_params,proto.is_vararg,proto.max_stack_size,function.vm_id]
        code=[];layout=[]
        for item in function.code:
            instruction=item.instruction
            code.extend((item.vop,instruction.a,instruction.b,instruction.c))
            layout.append(len(item.avalanche));layout.extend(item.avalanche)
            layout.append(len(item.graph_sites))
            for site in item.graph_sites:layout.extend(site)
        layout.append(len(function.routes))
        for route in function.routes:
            layout.append(len(route));layout.extend(route)
        for upvalue in proto.upvalues:layout.extend((upvalue.instack,upvalue.idx))
        layout.extend(children)
        linked_entries=[] if entries is None else entries[index-1]
        layout.append(len(linked_entries));layout.extend(linked_entries)
        tags=[fingerprint(seed,values) for seed,values in zip(seeds,(code,layout))]
        constants=[]
        for ordinal,value in enumerate(proto.constants):
            name=('nil' if value is None else 'bool' if isinstance(value,bool) else
                  'int' if isinstance(value,int) else 'float' if isinstance(value,float) else 'str')
            if name=='str':
                constants.append(0)  # Existing envelope/cell checks own content.
                continue
            storage='iexpr' if name=='int' and ordinal in function.integrity_indices else name
            if storage=='iexpr':
                bits=int(value)&((1<<64)-1)
                low,high=bits&0xffffffff,bits>>32
                a,b=random.randrange(1,1<<32),random.randrange(1,1<<32)
                constants.append([kinds[storage],a,b,low^a,high^b])
                continue
            seed=(seeds[2]+ordinal*65537)%(MODULUS-1)+1
            fields=[];number_class=0
            if name=='bool':fields=[int(value)]
            elif name in ('int','float'):
                number_class=1 if name=='int' else 2
                if name=='int' and version=='5.3':
                    bits=int(value)&((1<<64)-1);fields=[bits&0xffffffff,bits>>32]
                else:
                    number=float(value)
                    bits=(0x7ff8000000000000 if version=='5.1' and math.isnan(number)
                          else struct.unpack('<Q',struct.pack('<d',number))[0])
                    fields=[bits&0xffffffff,bits>>32]
                mask_hi=seed*65599%(1<<32)
                constants.append([kinds[storage],seed,(fields[0]+seed)%(1<<32),
                                  (fields[1]+mask_hi)%(1<<32),number_class])
                continue
            constants.append([kinds[storage],seed,fingerprint(seed,fields),number_class])
        empty_metadata=(fingerprint(seeds[1],[0,0]*len(function.code))
            if all(not item.avalanche and not item.graph_sites for item in function.code) else -1)
        records.append(dict(header=header,code_seed=seeds[0],layout_seed=seeds[1],
            code_tag=tags[0],layout_tag=tags[1],code_count=len(function.code),
            constant_count=len(proto.constants),capture_count=len(proto.upvalues),
            children=children,mov_entries=len(linked_entries),constants=constants,empty_metadata=empty_metadata))
    return records


def _literal(value, fields=SPEC_FIELDS):
    if isinstance(value,dict):
        if set(value)!=set(fields):raise ValueError('program manifest schema differs from runtime')
        value=[value[key] for key in fields]
    if isinstance(value,list):return '{'+','.join(_literal(item,fields) for item in value)+'}'
    return str(value)


def initialization_source(version, backend):
    line='ctx.line_state or 0' if version=='5.1' else '_LS or 0'
    kits='_mov_kits' if backend=='mov' else 'nil'
    return f'_PG_INIT(proto,{kits},crc,{line})'


def _decision(name, entries):
    if not entries:return 'return nil'
    if len(entries)==1:
        key,body=entries[0]
        return f'if {name}=={key} then {body} end'
    mid=len(entries)//2
    return (f'if {name}<={entries[mid-1][0]} then '+_decision(name,entries[:mid])+
            ' else '+_decision(name,entries[mid:])+' end')


def _vector(value, numbers):
    if len(numbers)<=8:
        return 'vector('+value+','+str(len(numbers))+('' if not numbers else ','+','.join(map(str,numbers)))+')'
    return ('(#table0('+value+')=='+str(len(numbers))+' and '+
            ' and '.join(f'{value}[{i}]=={number}' for i,number in enumerate(numbers,1))+')')


def policy_source(records, mov_records, fields):
    """Exact literal field comparisons, without a mutable expected policy bank."""
    rows=[]
    for domain,record in enumerate(records,1):
        checks=['#value=='+str(len(fields))]
        for i,key in enumerate(fields,1):
            value=f'value[{i}]'
            if key=='constants':checks.append('#table0('+value+')=='+str(len(record[key])))
            elif isinstance(record[key],list):checks.append(_vector(value,record[key]))
            else:checks.append(value+'=='+str(record[key]))
        tags=[(0,'return '+' and '.join(checks))]
        tags.extend((i,'return '+('value==0' if leaf==0 else _vector('value',leaf)))
                    for i,leaf in enumerate(record['constants'],1))
        rows.append((domain,_decision('ordinal',tags)))
    for i,value in enumerate(mov_records,len(records)+1):
        rows.append((i,'if ordinal==0 then return '+_vector('value',value)+' end'))
    return ('local function policy(domain,ordinal,value) '
            'if value~=0 then table0(value) end '+_decision('domain',rows)+' end')


def mov_manifest(kits, linked):
    from .mov.tables import banks, STATE_COUNTS
    records=[]
    for vm,(kit,tape) in enumerate(zip(kits,linked[0]),1):
        values=[]
        for i,digit in enumerate(kit.encode):values.extend((digit,i,int(i!=0),int(i>=8)))
        seed=random.randrange(1,MODULUS)
        records.append([0,vm,0,0,16,seed,fingerprint(seed,values),len(tape)])
        for bank_id,(bank,count) in enumerate(zip(banks(kit.encode),STATE_COUNTS),1):
            for x in range(16):
                values=[value for states in bank[x] for pair in states for value in pair]
                seed=random.randrange(1,MODULUS)
                records.append([1,vm,bank_id,x,count,seed,fingerprint(seed,values),len(tape)])
        for start in range(0,len(tape),64):
            values=[]
            for instruction in tape[start:start+64]:
                values.extend(map(int,(kit.opcodes[instruction.op],instruction.a,instruction.b,
                               instruction.c,instruction.d,instruction.mode)))
            seed=random.randrange(1,MODULUS)
            records.append([2,vm,0,start+1,min(64,len(tape)-start),seed,fingerprint(seed,values),len(tape)])
    random.shuffle(records)
    return records


def prepare(source, layout, context, blob, mov=None, validation_id=None):
    from .backends.handler_codec import BinReader
    reader=BinReader(blob);reader.header()
    header=[reader.u16(),reader.u32(),reader.u16()]
    records=manifest(layout.functions,None if mov is None else mov['linked'][1],
                     kinds=layout.constant_kinds,version=context.target.lua_version)
    mov_records=[] if mov is None else mov_manifest(mov['kits'],mov['linked'])
    native=(Path(__file__).parent/'runtimes/program_integrity.lua').read_text(encoding='utf8')
    fields=random.sample(SPEC_FIELDS,len(SPEC_FIELDS))
    from .backends.handler_layout import iter_protos
    validators=[i for i,p in enumerate(iter_protos(layout.functions.source),1) if p.id==validation_id]
    if len(validators)!=1:raise ValueError('program admission requires exactly one private validator')
    native=native.replace('--<<PROGRAM_POLICY>>',policy_source(records,mov_records,fields))
    native=native.replace('__PROGRAM_VALIDATOR__',str(validators[0]))
    for slot,field in enumerate(fields,1):
        native=native.replace('__PROGRAM_SPEC_'+field.upper()+'__',str(slot))
    native=native.replace('__PROGRAM_MANIFEST__',_literal(records,fields))
    native=native.replace('__PROGRAM_HEADER_CHECK__',
        ' or '.join('_IT.'+key+'~='+str(value) for key,value in zip(('seed','layout','vmc'),header)))
    if context.target.lua_version=='5.1':
        template=context.target.runtime_template('mov_exec.lua')
        start=template.index('local function _mov_f64_words(value)')
        end=template.index('local function _mov_f64_value(',start)
        original_words=template[start:end]
        words=original_words.replace('_mov_f64_words','words',1)
        if mov is not None:
            if source.count(original_words)!=1:raise ValueError('shared MOV numeric normalization boundary is missing')
            source=source.replace(original_words,'local _mov_f64_words=_PG_WORDS\n')
        numeric_type=''
        encoded_word="local word=raw(k,2);table0(word);return raw(word,1)==lo and raw(word,2)==hi,mix"
    else:
        words='''local function words(value,integer)
 if integer then return value&4294967295,(value>>32)&4294967295 end
 return string.unpack('<I4I4',string.pack('<d',value))
end'''
        numeric_type="if (spec[5]==1 and math.type(value)~='integer') or (spec[5]==2 and math.type(value)~='float') then return false end"
        encoded_word="local word=raw(k,2);return math.type(word)=='integer' and word&4294967295==lo and (word>>32)&4294967295==hi,mix"
    native=native.replace('--<<PROGRAM_NUMBER_WORDS>>',words)
    native=native.replace('--<<PROGRAM_NUMBER_TYPE>>',numeric_type)
    native=native.replace('--<<PROGRAM_ENCODED_WORD>>',encoded_word)
    native=native.replace('__PROGRAM_EXTRA_COUNT__',str(len(mov_records)))
    declarations=''
    if mov_records:
        declarations=(Path(__file__).parent/'runtimes/program_mov_integrity.lua').read_text(encoding='utf8')
        declarations=declarations.replace('__PROGRAM_MOV_MANIFEST__',_literal(mov_records))
    replacements={
        '--<<PROGRAM_MOV_DECL>>':declarations,
        '--<<PROGRAM_MOV_INIT>>':'if not call(mov_initialize,kits) then reject() end' if mov_records else '',
        '--<<PROGRAM_MOV_ENTRY>>':'and mov_check_vm(p)' if mov_records else '',
        '--<<PROGRAM_MOV_POLL>>':'if cursor>#specs then return mov_check_region(cursor-#specs) end' if mov_records else '',
    }
    for marker,replacement in replacements.items():
        if native.count(marker)!=1:raise ValueError('MOV program integrity boundary is missing')
        native=native.replace(marker,replacement)
    if '__PROGRAM_' in native:raise ValueError('unresolved program integrity boundary')
    anchor='local function get_environment('
    if source.count(anchor)!=1:raise ValueError('program integrity native boundary is missing')
    source=source.replace(anchor,native+'\n'+anchor)
    resolver='local function kval(k,proto)'
    if source.count(resolver)!=1:raise ValueError('program constant resolver boundary is missing')
    marker='--<<ENDTARGET_CONSTANT_RESOLVER>>'
    if source.count(marker)!=1:raise ValueError('program constant consumer boundary is missing')
    start=source.index(resolver);end=source.index(marker,start)
    body=source[start:end]
    if body.count('_ieval(k[3],proto)')!=1:raise ValueError('integrity expression reuse boundary is missing')
    body=body.replace(resolver,'local function _program_kval(k,proto,_program_mix)').replace(
        '_ieval(k[3],proto)','(_program_mix or _ieval(k[3],proto))')
    source=source[:start]+body+source[end:]
    source=source.replace(marker,'local function kval(k,proto)return _PG_VALUE(proto,k,_program_kval) end\n'+marker)
    # Stream arithmetic consumes the encoded operand. Validate its build shares
    # with the existing expression mix, without using the native-value resolver.
    source=source.replace('rset(A,consts[Bx+1][2])','rset(A,_PG_ENCODED(proto,consts[Bx+1]))')
    # This is after all backend-specific parsing, including MOV extension loading.
    anchor='local env_box={v='
    if source.count(anchor)!=1:raise ValueError('program integrity initialization boundary is missing')
    source=source.replace(anchor,initialization_source(context.target.lua_version,'mov' if mov_records else 'classic')+'\n    '+anchor)
    pattern=r'((?:exec|_mov_dispatch\[[0-9]+\]) = function\(proto,[^\n]+\)\n)'
    source,count=re.subn(pattern,lambda match:match[1]+(
        '    if not _fr then _PS_GUARD(false,proto) end\n' if re.search(r'\b_fr\b',match[1])
        else '    _PS_GUARD(false,proto)\n'),source)
    expected=layout.vm_count if '_mov_dispatch[' in source else 1
    if count!=expected:raise ValueError('program integrity function-entry boundary is missing')
    source=source.replace('local _PS,_PS_GUARD\n','local _PS,_PS_GUARD,_PG,_PG_INIT,_PG_VALUE,_PG_ENCODED,_PG_WORDS\n')
    replacements={
        'function S.guard(force)':'function S.guard(force,program)',
        'if failed then fail() end\n ticks=':
            'if failed then fail() end\n if program and (not program_check or not program_check(program)) then fail() end\n ticks=',
        'if ticks==0 then\n  for i=1,#periodic':
            'if ticks==0 then\n  if program_poll and not program_poll() then fail() end\n  for i=1,#periodic',
    }
    for anchor,replacement in replacements.items():
        if source.count(anchor)!=1:raise ValueError('program integrity guard boundary is missing')
        source=source.replace(anchor,replacement)
    context.profile.append({'phase':'program_integrity','elapsed':0.0,'functions':len(records),
                            'domains':['header','instructions','layout','scalar_constants'],
                            'initial':True,'function_entry':True,'period_guard_events':127,
                            'periodic_regions':len(records)+len(mov_records),'mov_regions':len(mov_records),
                            'manifest_fields':fields,
                            'policy_exact_literals':True,'periodic_canonical_decode':True,
                            'captured_consumers':True,'bootstrap_stage_admission':True,
                            'format_changed':False})
    return source
