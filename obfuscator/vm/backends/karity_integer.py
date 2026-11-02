"""Integer representation emission and conservative whole-program alias proofs.

Proofs cover every physical use of a handler, including original aliases retained
inside synthesized regions. A missing fact keeps the general Lua route. The
proof never infers argument types from sampled executions or call-site guesses.
"""
from pathlib import Path
import re

from .runtime_layout import iter_functions


SELECTORS = {13: 1, 14: -1, 15: 0, 20: 2, 21: 3, 22: 4, 23: 5, 24: 6}
UNARY = {25: -1, 26: 2}
SUPPORTED = frozenset((*SELECTORS, *UNARY, 16, 19, 31, 32, 33))


def proof_signature(lowered):
    layout = lowered.backend_data['layout']
    return (lowered.semantic_ir.generation, layout.encoded_bitwise,
            tuple(tuple(sorted(mapping[2].items())) for mapping in layout.vm_maps),
            tuple((f.source.id, f.vm_id, tuple(f.code),
                   tuple((entry.start,entry.opcode,entry.original_vops) for entry in f.synthesis))
                  for f in iter_functions(layout.functions)))


def validate_proofs(lowered):
    key = proof_signature(lowered)
    bound = lowered.backend_data.get('integer_proof_binding')
    expected = bound[1] if bound is not None and bound[0] == key else integer_aliases(lowered)[0]
    if lowered.backend_data.get('integer_aliases') != expected:
        raise ValueError('Karity integer aliases differ from whole-program proofs')
    lowered.backend_data['integer_proof_binding'] = (key, expected)


def integer_aliases(lowered):
    """Return aliases with a proof at every source/physical occurrence."""
    from ..ir.facts import analyze_function
    layout = lowered.backend_data['layout']
    if not layout.encoded_bitwise:
        return tuple(frozenset() for _ in layout.vm_maps), ()
    facts = {function.id: analyze_function(function, '5.3')
             for function in lowered.semantic_ir.functions()}
    uses: list[dict[int,list[bool]]] = [{} for _ in layout.vm_maps]
    operations: list[dict[int,str]] = [{} for _ in layout.vm_maps]
    for function in iter_functions(layout.functions):
        evidence = facts[function.source.id]
        # Synthetic source operations can refer to instruction IDs absent from
        # semantic IR. Missing correspondence must never become a proof.
        def proved(ins):
            source = evidence.producers.get(ins.source_id)
            if source is None or source.operation != ins.operation:
                return False
            roles = ('source',) if ins.op in UNARY else ('left', 'right')
            return (source.id in evidence.before and all(
                evidence.operand(source, role).kind == 'integer' for role in roles))

        fuses = set(layout.vm_maps[function.vm_id][2].values())
        synthesized = {pc for entry in function.synthesis
                       for pc in range(entry.start, entry.start+len(entry.original_vops))}
        for pc, item in enumerate(function.code):
            if pc in synthesized:
                continue
            ins = item.instruction
            if item.vop in fuses:
                group = [ins, function.code[pc+1].instruction]
                integer = [entry for entry in group if entry.op in SUPPORTED]
                if not integer:
                    continue
                valid = all(proved(entry) for entry in integer)
            else:
                if ins.op not in SUPPORTED:
                    continue
                valid = proved(ins)
            uses[function.vm_id].setdefault(item.vop, []).append(bool(valid))
            operations[function.vm_id][item.vop] = '/'.join(
                entry.operation for entry in group) if item.vop in fuses else ins.operation
        for entry in function.synthesis:
            for offset, alias in enumerate(entry.original_vops):
                ins = function.code[entry.start+offset].instruction
                if ins.op in SUPPORTED:
                    uses[function.vm_id].setdefault(alias, []).append(proved(ins))
                    operations[function.vm_id][alias] = ins.operation
    selected = tuple(frozenset(alias for alias, values in vm.items() if all(values))
                     for vm in uses)
    events = tuple({'vm': vm, 'vop': alias, 'kind': 'integer-general-path',
                    'operation': operations[vm][alias],
                    'outcome': 'elided' if all(values) else 'retained',
                    'uses': len(values), 'proven_uses': sum(values),
                    'reason': 'all-physical-uses-proven-integer' if all(values)
                              else 'unproven-physical-use'}
                   for vm, entries in enumerate(uses)
                   for alias, values in sorted(entries.items()))
    return selected, events


def _replace_function(source, name, following, replacement):
    start = source.index('    local function ' + name + '(')
    stop = source.index('    local function ' + following + '(', start)
    return source[:start] + replacement + '\n\n' + source[stop:]


def prepare_runtime(source, lowered):
    """Expand only the Karity Lua 5.3 asset before helper cloning/renaming."""
    integer = (Path(__file__).parents[1] / 'runtimes' / 'karity_integer.lua').read_text(encoding='utf-8')
    from ..vm_obfuscation import _iter_protos
    selectors = {SELECTORS[ins.op] for fn in _iter_protos(lowered.program)
                 for ins in fn.code if ins.op in SELECTORS}
    for fn in _iter_protos(lowered.program):
        selectors.update(7 if ins.op == 16 else 8 for ins in fn.code if ins.op in (16,19))
    expressions = {
        -1: '_esub(a,b,c,d)', 0: '_emul(a,b,c,d)', 1: '_eadd(a,b,c,d)',
        2: '_eand(a,b,c,d)', 3: '_eor(a,b,c,d)', 4: 'a~c,b~d',
        5: '_eshift(a,b,c,d,false)', 6: '_eshift(a,b,c,d,true)',
        7: '_edivmod(a,b,c,d,true)', 8: '_edivmod(a,b,c,d,false)',
    }
    start = integer.index('        if selector==4 then')
    stop = integer.index('        _ebit_store(dst,x,y,', start)
    cases = [f"        {'if' if n == 0 else 'elseif'} selector=={value} then x,y={expressions[value]}\n"
             for n,value in enumerate(sorted(selectors))]
    replacement = ''.join(cases) + '        else return false end\n' if cases else '        return false\n'
    if not cases:
        # Lua return must be the last statement in its lexical block.
        replacement = '        do return false end\n'
    integer = integer[:start] + replacement + integer[stop:]
    # Final runtime schema names were allocated before backend emission. Cost
    # probes use the same fragment with its original field spellings.
    names = lowered.backend_data.get('vm_key_renames', {})
    for field in ('get','set','refs'):
        integer = integer.replace('.' + field, '.' + names.get(field, field))
    if not lowered.policy.get('semantic_state_threading', False):
        integer = integer.replace('                _ss_value(-31,encoded,epoch,1)\n', '')
    source = _replace_function(source, '_ebit_snapshot', '_pending_snapshot', integer)
    graphs = []
    for arity, following in ((2, '_arith1'), (1, '_elinear2')):
        name = f'_arith{arity}'
        a = source.index('    local function ' + name + '(')
        b = source.index('    local function ' + following + '(', a)
        body = source[a:b].rstrip()
        body = body.replace(f'function {name}(', f'function _egraph{arity}(', 1)
        body = body.replace('_int2(a,b)' if arity == 2 else '_int1(a)', '2')
        graphs.append(body)
    source = source.replace('    local function _elinear2(', '\n'.join(graphs) + '\n\n    local function _elinear2(', 1)
    old = '''            local value=q[2]~q[3]
            _rstore(dst,scale*value+bias,q[6],1)
            return value'''
    if source.count(old) != 1:
        raise ValueError('Karity Boolean completion contract changed')
    source = source.replace(old, '''            _rstore(dst,_eaffine(q[2],q[3],scale,bias),q[6],1)
            return''')
    # Preserve the cheap affine route. Shared packets can instead continue
    # directly in Boolean arithmetic, including captured-cell boundaries.
    anchor = '        local left=rget(lhs)\n'
    start = source.index('    local function _arith2r(')
    end = source.index('    local function _arith2s(', start)
    body = source[start:end]
    binary_marker = '        if linear and linear<2 and (not desc or desc[1]==0) and\n'
    body = body.replace(binary_marker,
        '        local lp,rp=_PD[_rpos(5,lhs)],_PD[_rpos(5,rhs)]\n'
        '        if linear and linear<2 and (not desc or desc[1]==0) and\n'
        '           ((lp and lp[1]==false) or (rp and rp[1]==false)) and\n'
        '           _ebit2(dst,lhs,rhs,linear) then return end\n' + binary_marker, 1)
    body = body.replace(anchor,
        '        if linear and linear<2 and (not desc or desc[1]==0) and\n'
        '           _ebit2(dst,lhs,rhs,linear) then return end\n' + anchor, 1)
    unary = '        rset(dst,_arith1(rget(src),av,slot,desc))'
    body = body.replace(unary,
        '        if linear and linear<2 and (not desc or desc[1]==0) and\n'
        '           _ebit1(dst,src,true) then return end\n' + unary, 1)
    marker = '        if linear and linear<2 and (not desc or desc[1]==0) and\n           _elinear1'
    body = body.replace(marker,
        '        local packet=_PD[_rpos(5,src)]\n'
        '        if linear and linear<2 and (not desc or desc[1]==0) and\n'
        '           packet and packet[1]==false and _ebit1(dst,src,true) then return end\n' + marker, 1)
    source = source[:start] + body + source[end:]
    # General-path-free aliases use separate helpers, so lexical dead-helper
    # pruning can actually remove the general handlers, not just guard them.
    only = '''    local function _eonly2r(dst,lhs,rhs,av,slot,linear,desc,bound)
        if not bound then _gq=(_gq or 0)+1; desc=_gsl and _gsl[_gq] end
        if not desc or desc[1]==0 then
            local lp,rp=_PD[_rpos(5,lhs)],_PD[_rpos(5,rhs)]
            if ((lp and lp[1]==false) or (rp and rp[1]==false)) and
               _ebit2(dst,lhs,rhs,linear) then return end
            if linear<2 and _elinear2(dst,lhs,rhs,linear) then return end
            assert(_ebit2(dst,lhs,rhs,linear),'invalid integer proof')
            return
        end
        -- Active graphs retain their complete original execution/state effects.
        local left=rget(lhs)
        local right
        if lhs==rhs then right=left else right=rget(rhs) end
        rset(dst,_egraph2(left,right,av,slot,desc))
    end

    local function _eonly1r(dst,src,av,slot,linear,desc,bound)
        if not bound then _gq=(_gq or 0)+1; desc=_gsl and _gsl[_gq] end
        if not desc or desc[1]==0 then
            local packet=_PD[_rpos(5,src)]
            if packet and packet[1]==false and _ebit1(dst,src,linear<2) then return end
            if linear<2 and _elinear1(dst,src,linear) then return end
            assert(_ebit1(dst,src,linear<2),'invalid integer proof')
            return
        end
        rset(dst,_egraph1(rget(src),av,slot,desc))
    end

    local function _ediv2r(dst,lhs,rhs,modulo)
        return _ebit2(dst,lhs,rhs,modulo and 7 or 8)
    end

'''
    state = lowered.backend_data.get('karity_state')
    if state is not None and not (state.occurrence_inventory()[1] - {0}):
        # No active graph exists anywhere in this closed program. Proven-only
        # helpers must not keep the native arithmetic bank alive just in case.
        graph_prefix = '        if not bound then _gq=(_gq or 0)+1; desc=_gsl and _gsl[_gq] end\n        if not desc or desc[1]==0 then\n'
        only = only.replace(graph_prefix, '')
        for _ in range(2):
            a = only.index('            return\n        end\n')
            b = only.index('    end', a + len('            return\n        end\n'))
            only = only[:a] + only[b:]
    source = source.replace('    local function _arith2s(', only + '    local function _arith2s(', 1)
    deferred = []
    for arity, following in ((2, '_defer1r'), (1, '_arith2r')):
        name = f'_defer{arity}r'
        a = source.index('    local function ' + name + '(')
        b = source.index('    local function ' + following + '(', a)
        body = source[a:b].rstrip()
        if arity == 2:
            a = body.index('        local left=rget(lhs)')
            body = body[:a] + '''        _eonly2r(dst,lhs,rhs,av,slot,token==__VM_PENDING_ADD__ and 1 or -1,desc,true)
    end'''
        else:
            body = body.replace('rset(dst,_arith1(rget(src),av,slot,desc))',
                                '_eonly1r(dst,src,av,slot,-1,desc,true)')
        deferred.append(body.replace('function ' + name + '(', 'function _e' + name[1:] + '(', 1))
    # The proved deferred helpers must see the earlier local eonly bindings.
    source = source.replace('    local function _arith2s(', '\n'.join(deferred) + '\n\n    local function _arith2s(', 1)
    # Split scratch is not a logical guest-register commit.
    if lowered.policy.get('semantic_state_threading', False):
        source = source.replace('\n        _ss_value(slot,encoded,epoch,kind)',
                                '\n        if slot~=-7 then _ss_value(slot,encoded,epoch,kind) end', 1)
    # All ordinary aliases try integer representations. Lua's general route
    # remains for floats/coercions/metamethods unless a whole-alias proof elides it.
    for op, selector in SELECTORS.items():
        if op >= 20:
            source = re.sub(r'(elseif op==' + str(op) + r' then _arith2r\([^\n]+),nil\)',
                            lambda m: m[1] + ',' + str(selector) + ')', source)
    source = source.replace('_arith1r(A,B,_av,__VM_SLOT_BNOT__,nil)',
                            '_arith1r(A,B,_av,__VM_SLOT_BNOT__,2)')
    for op, modulo, token in ((16, 'true', 'MOD'), (19, 'false', 'IDIV')):
        old = f'rset(A,_carry(_sem(__VM_OP_{token}__,rget(B),rget(C),nil),_av,{op}))'
        source = source.replace(old, f'if not _ediv2r(A,B,C,{modulo}) then {old} end', 1)
    for op, selector, token in ((31, 0, 'EQ'), (32, 1, 'LT'), (33, 2, 'LE')):
        start = source.index(f'        elseif op=={op} then')
        end = source.index(f'        elseif op=={op+1} then', start)
        source = source[:start] + f'''        elseif op=={op} then
            local result=_ecmp2(B,C,{selector})
            if result==nil then
                local left=rget(B); local right
                if B==C then right=left else right=rget(C) end
                result=_sem(__VM_CMP_{token}__,left,right,nil)
            end
            if not _branch(_carry(result,_av,{op}),A~=0,_av,{op}) then pc=pc+1 end
''' + source[end:]
    return source


def split_integer_bodies(op, parts, *, proven=True):
    """Keep the same physical part count and graph occurrence placement."""
    from ..vm_obfuscation import _GRAPH_BINARY_SLOTS, _GRAPH_UNARY_SLOTS
    copy = '_eint_copy' if proven else '_esplit_copy'
    if op in SELECTORS:
        slot, selector = _GRAPH_BINARY_SLOTS[op], SELECTORS[op]
        helper = '_eonly2r' if proven else '_arith2r'
        binary = lambda left: f'{helper}(-7,{left},C,_av,{slot},{selector})'
    elif op in (16,19):
        def binary(left):
            attempt = f"_ediv2r(-7,{left},C,{'true' if op == 16 else 'false'})"
            if proven:
                return f"assert({attempt},'invalid integer proof')"
            token = '__VM_OP_MOD__' if op == 16 else '__VM_OP_IDIV__'
            return f'if not {attempt} then rset(-7,_carry(_sem({token},rget({left}),rget(C),nil),_av,{op})) end'
    else:
        binary = None
    if binary is not None:
        if parts == 2:
            return [binary('B'), f'{copy}(A,-7)']
        return ['rset(-7,_sem(__VM_DATA_VALUE__,rget(B),nil,nil))',
                binary('-7'), f'{copy}(A,-7)']
    if op in UNARY:
        slot, selector = _GRAPH_UNARY_SLOTS[op], UNARY[op]
        helper = '_eonly1r' if proven else '_arith1r'
        if parts == 2:
            return [f'{copy}(-7,B)', f'{helper}(A,-7,_av,{slot},{selector})']
        return ['rset(-7,_sem(__VM_DATA_VALUE__,rget(B),nil,nil))',
                f'{helper}(-7,-7,_av,{slot},{selector})', f'{copy}(A,-7)']
    raise ValueError('unsupported integer split proof')


def proven_body(op, body):
    """Preserve alias transitions; replace only the guest operation body."""
    if op in SELECTORS:
        return body.replace('_arith2r(', '_eonly2r(')
    if op in UNARY:
        return body.replace('_arith1r(', '_eonly1r(')
    if op in (16, 19):
        return f"assert(_ediv2r(A,B,C,{'true' if op == 16 else 'false'}),'invalid integer proof')"
    if op in (31, 32, 33):
        return (f'local result=_ecmp2(B,C,{op-31}); assert(result~=nil,"invalid integer proof"); '
                f'if not _branch(_carry(result,_av,{op}),A~=0,_av,{op}) then pc=pc+1 end')
    raise ValueError('unsupported integer alias proof')
