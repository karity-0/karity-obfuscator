"""Keep active source-local references resident across their lexical scope.

Last guest use is not the lifetime of a native Lua stack slot. Weak tables and
callbacks can observe a still-resident source local. Primitive values need no
additional roots; anonymous temporaries retain the existing call/top policy.
"""
from dataclasses import replace


PRIMITIVES=frozenset(('nil','boolean','integer','float','number'))


def preserve_locals(function, live, facts, hints, releases, edge_releases):
    locals_=function.debug_metadata.get('locals',())
    if not locals_ or function.debug_metadata.get('security_owned'):return live
    source_limit=function.debug_metadata.get('security_scratch_base',function.max_stack_size)
    prefix=function.id+':r'
    named_cache={}
    def named(point):
        if not isinstance(point,int):
            # An internal bridge has no source PC. Keep source slots stable
            # through it; the next source instruction restores exact scope.
            return set(range(min(len(locals_),source_limit)))
        if point not in named_cache:
            active=[v for v in locals_ if v[1]<=point<v[2]]
            named_cache[point]=set(range(min(len(active),source_limit)))
        return named_cache[point]
    def outputs(instruction):
        return {int(name[len(prefix):]) for name in instruction.outputs
                if name.startswith(prefix) and name[len(prefix):].isdigit() and int(name[len(prefix):])<source_limit}
    def primitive_after(instruction,r):
        op=instruction.operation
        if r not in outputs(instruction):
            fact=facts.before[instruction.id].get(r)
            return fact is not None and fact.kind in PRIMITIVES
        if instruction.id in hints:return hints[instruction.id].kind in PRIMITIVES
        if op in ('LOAD_NIL','LOAD_BOOL','LOGICAL_NOT'):return True
        fields={o.role:o for o in instruction.operands}
        if op=='MOVE':
            fact=facts.before[instruction.id].get(fields['source'].value)
            return fact is not None and fact.kind in PRIMITIVES
        if op=='LOAD_CONST':return facts.constants[fields['value'].value].kind in PRIMITIVES
        return op in ('ADD','SUB','MUL','NEGATE','BIT_AND','BIT_OR','BIT_XOR','BIT_NOT','SHIFT_LEFT','SHIFT_RIGHT') and facts.effects[instruction.id].pure
    before={};after={}
    by_block={b.id:b for b in function.blocks}
    for block in function.blocks:
        for index,instruction in enumerate(block.instructions):
            pc=instruction.metadata.get('source_pc')
            # Locals can become active after the final table-field initializer,
            # which does not itself define the table's register. Scope roots
            # therefore cannot be inferred only from register definitions.
            extra_before={prefix+str(r) for r in named(pc)
                if facts.before[instruction.id].get(r) is None or facts.before[instruction.id][r].kind not in PRIMITIVES}
            # Protection expansion can contain several instructions for one
            # native PC. A local's initializer/scope changes only when that
            # source operation finishes, not after each synthetic guard call.
            if index+1<len(block.instructions):
                next_pc=block.instructions[index+1].metadata.get('source_pc')
                next_scope=named(next_pc)
            else:
                next_scope=set().union(*(named(by_block[target].instructions[0].metadata.get('source_pc'))
                                         for target in block.successors))
            if isinstance(pc,int):
                # A CALL can initialize a new source local before its trailing
                # protection guard. Keep its produced value through that guard
                # even though the local's debug scope starts at the next PC.
                next_scope=next_scope|(outputs(instruction)&named(pc+1))
            extra_after={prefix+str(r) for r in next_scope if not primitive_after(instruction,r)}
            before[instruction.id]=live.before[instruction.id]|extra_before
            after[instruction.id]=live.after[instruction.id]|extra_after
            releases[instruction.id]=tuple(sorted(int(key[len(prefix):]) for key in extra_before-after[instruction.id]))
    for block in function.blocks:
        last=block.instructions[-1]
        for target in set(block.successors):
            remaining=before[by_block[target].instructions[0].id]
            expired=after[last.id]-remaining
            edge_releases[block.id,target]=tuple(sorted(int(key[len(prefix):]) for key in expired
                if key.startswith(prefix) and key[len(prefix):].isdigit() and int(key[len(prefix):])<source_limit))
    return replace(live,before=before,after=after,
        live_in={b.id:before[b.instructions[0].id] for b in function.blocks},
        live_out={b.id:after[b.instructions[-1].id] for b in function.blocks})
