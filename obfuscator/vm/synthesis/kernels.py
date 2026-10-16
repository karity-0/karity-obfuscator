"""Build-local reuse of exact generated bodies, mutation and compiler reports."""
import re
import time
from ...passes.function_costs import measure


def generated_names(body,mapping):
    if not mapping:return body
    pattern=re.compile(r'\b(?:'+ '|'.join(re.escape(name) for name in mapping)+r')\b')
    return pattern.sub(lambda match:mapping[match.group()],body)


def ordered_bodies(lowered,variant,aliases,native):
    from ..vm_obfuscation import apply_vop_to_vm,_find_chain,_parse_handler_blocks
    source=lowered.backend_data['synthesis_template']
    key=(source,repr(aliases),repr(variant['semantic_alias_modes']),repr(variant['alias_transition_indices']),native)
    cache=lowered.backend_data.setdefault('synthesis_ordered_bodies',{})
    if key not in cache:
        script=apply_vop_to_vm(source,aliases,variant['semantic_alias_modes'],native_state=native,
            alias_transition_indices=variant['alias_transition_indices'])
        a,b=_find_chain(script);cache[key]=_parse_handler_blocks(script[a:b])
    return cache[key]


def prepare_kernel(entry,lowered,variant,fetch,aliases,defers,native):
    from .emission import render_kernel
    from ..vm_mutation import mutate_handlers,planned_mutation_seeds,_native_scratch_locals
    ordinary=ordered_bodies(lowered,variant,aliases,native) if entry.occurrence.numeric_domain=='ordered' else None
    body=render_kernel(entry,lowered,variant,fetch,aliases,defers,native,ordinary)
    names=lowered.backend_data.get('vm_key_renames',{})
    # This is the exact generator's injective key-renaming map, not inferred
    # equivalence of arbitrary Lua. Identifier spelling cannot alter compiler
    # instruction counts, stack or jumps under this known bijection.
    body=generated_names(body,{value:key for key,value in names.items()})
    seed=planned_mutation_seeds(variant['mutation_seed'],{0:'synthesis:'+entry.recipe.id})[0] if variant['mutate_handlers'] else None
    key=(body,seed,native)
    cache=lowered.backend_data.setdefault('synthesis_kernel_cache',{})
    stats=lowered.backend_data.setdefault('synthesis_kernel_reuse',{'hits':0,'misses':0})
    if key in cache:
        stats['hits']+=1
        value=cache[key]
        return generated_names(value[0],names),*value[1:]
    stats['misses']+=1
    scratch=False
    if seed is not None:
        body=mutate_handlers({0:body},native_state=native,planned_seeds={0:seed})[0]
    from .register_local import active_values
    raw=entry.execution_form!='materialized' and active_values(entry,defers)
    if (seed is not None or raw) and len(set(re.findall(r'\blocal\s+([A-Za-z_]\w*)',body)))>200//4:
        if seed is None:
            # Reserve the same enclosing-executor local budget without adding
            # mutation. Hoisting keeps initializers at their original steps,
            # including nil resets on repeated execution of the scratch bank.
            # This new path is restricted to proven scalar/raw recipes: do not
            # extend table/userdata lifetimes by banking ordered-step locals.
            from ..vm_mutation import _hoist_locals
            declarations,statements=_hoist_locals(body.splitlines())
            body='\n'+'\n'.join(declarations+statements)+'\n'
        body=_native_scratch_locals(body,0,0,scratch_name='_SYN_TEMPS',rewrite_helpers=False)
        scratch=True
    started=time.perf_counter()
    report=measure(body,version='5.1' if native else '5.3')
    value=(body,scratch,report,time.perf_counter()-started)
    cache[key]=value
    return generated_names(body,names),scratch,report,value[3]
