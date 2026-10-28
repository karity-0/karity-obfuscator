"""Build-time proofs for redundant caller-side full host scans.

Every generated callee still has full entry/return checks. Only closed ordinary
CALLs whose complete reaching-definition chain produces generated closures may
use caller-side periodic polls. Host entry, native/unknown calls, captures,
tailcalls and open argument/result paths retain the conservative policy.
"""
from .ir.facts import analyze_function
from .backends.bare_registers import native_prefix


def internal_calls(function, version):
    if not any(i.operation=='CALL' for b in function.blocks for i in b.instructions):return frozenset()
    facts=analyze_function(function,version)
    captured={o.value for b in function.blocks for i in b.instructions
              if i.operation=='CLOSURE' for o in i.operands
              if o.role=='capture' and o.kind=='register'}
    prefix=native_prefix(function)
    memo: dict[tuple[str,int],bool]={}
    def generated(point,register,visiting):
        key=(point,register)
        if key in memo:return memo[key]
        if key in visiting or register in captured:return False
        definitions=facts.definitions[point][register]
        result=bool(definitions)
        for definition in definitions:
            producer=facts.producers.get(definition)
            if producer is None:result=False;break
            if producer.operation=='CLOSURE':continue
            if producer.operation=='MOVE':
                source=next(o for o in producer.operands if o.role=='source')
                if generated(producer.id,source.value,visiting|{key}):continue
            result=False;break
        memo[key]=result
        return result
    result=set()
    for block in function.blocks:
        for instruction in block.instructions:
            if (instruction.operation!='CALL' or instruction.metadata.get('protection_origin')
                    or instruction.id not in facts.definitions):continue
            if any(o.kind=='register_range' and o.count is None for o in instruction.operands):continue
            # A spill/captured-cell result store may allocate before the caller
            # poll. Keep its immediate post-call scan; reuse the emitter's exact
            # prefix bound rather than guessing from source variable names.
            results=next(o for o in instruction.operands if o.role=='results')
            if any(r>=prefix or r in captured for r in range(results.value,results.value+(results.count or 0))):continue
            callee=next(o for o in instruction.operands if o.role=='callee')
            if callee.kind=='register' and generated(instruction.id,callee.value,set()):result.add(instruction.id)
    return frozenset(result)
