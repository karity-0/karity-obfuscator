"""Cost the existing physical fallback, without changing protection planning.

Bodies and mutation seeds come from the real emitters. Compiler work is a proxy,
not elapsed time: helper internals and input-dependent paths remain explicit
limits. Only fusion pairs selected by the existing plan are alternatives.
"""
from ..vm_obfuscation import (
    apply_vop_to_vm, _find_chain, _parse_handler_blocks, fused_handler_body,
    split_handler_bodies,
)
from ..vm_mutation import mutate_handlers, planned_mutation_seeds
from ..backends.handler_layout import _lower_units, _compute_protected, _block_chunks, _mark_integrity_stream_units


class Alternatives:
    def __init__(self, source, variant, vm_map, compile_body, fetch, policy):
        self.variant=variant;self.maps=vm_map;self.compile=compile_body;self.fetch=fetch
        self.policy=policy;self.plans={}
        self.native='--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source or '--<<TARGET_KARITY_EXEC_STATE>>' in source
        patched=apply_vop_to_vm(source,vm_map[0],variant['semantic_alias_modes'],
            native_state=self.native,alias_transition_indices=variant['alias_transition_indices'])
        a,b=_find_chain(patched);self.aliases=_parse_handler_blocks(patched[a:b])
        self.cache={};self.protected={};self.empty=compile_body('')['instructions']

    def body(self, kind, op, value):
        key=(kind,op,value)
        if key in self.cache:return self.cache[key]
        if kind=='alias':
            body=self.aliases[value];ordinal=self.maps[0][op].index(value)
            identity=f'alias:{op}:{ordinal}'
        elif kind=='fuse':
            body=fused_handler_body(op,value,native_state=self.native);identity=f'fuse:{op}:{value}'
        elif kind=='split':
            parts,part=value;body=split_handler_bodies(op,parts)[part];identity=f'split:{op}:{parts}:{part}'
        else:
            # Deferred arithmetic uses the same real producer token and ABI.
            slot='UNM' if op==25 else 'ADD' if op==13 else 'SUB'
            body=(f'_defer1r(A,B,_av,__VM_SLOT_{slot}__,__VM_PENDING_{slot}__)' if op==25 else
                  f'_defer2r(A,B,C,_av,__VM_SLOT_{slot}__,__VM_PENDING_{slot}__)')
            identity=f'defer:{op}'
        if self.variant['mutate_handlers']:
            seeds=planned_mutation_seeds(self.variant['mutation_seed'],{0:identity})
            body=mutate_handlers({0:body},native_state=self.native,planned_seeds=seeds)[0]
        report=self.compile('do\n'+self.fetch+'\n'+body+'\nend')
        if 'error' in report:raise ValueError(f'cannot cost planned {identity} handler: {report["error"]}')
        self.cache[key]={**report,'work':max(0,report['instructions']-self.empty)}
        return self.cache[key]

    def compare(self, fn, state, indexes, dispatch):
        aliases,splits,fuses,defers=self.maps
        def normal(index):
            op=fn.code[index].op
            vop=aliases[op][state['alias_variants'][index]%len(aliases[op])]
            return self.body('alias',op,vop)
        ordinary=[normal(i) for i in indexes]
        rows={'ordinary':{'work':sum(r['work'] for r in ordinary)+len(indexes)*dispatch,
                          'dispatches':len(indexes),'body_bytes':sum(r['bytes'] for r in ordinary)}}
        variants=[];owned=set(indexes);overlap=False
        if id(fn) not in self.protected:self.protected[id(fn)]=_compute_protected(fn.code)
        if id(fn) not in self.plans:
            chunks=_block_chunks(fn.code,int(self.policy.get('block_variant_max_instructions',6)),{})
            routes=0;selected=[]
            for start,end,eligible in chunks:
                enabled=eligible and routes<256 and self.policy.get('block_variant_rate',0)>0 and state['block_variants'].get(start,False)
                routes+=bool(enabled);selected.append((start,end,enabled))
            total=int(self.policy.get('block_variant_count',3)) if routes else 1
            integrity=set(state['integrity_constants']) if self.policy.get('integrity_constants',False) else set()
            stream=bool(integrity) and fn.max_stack_size<=253 and not state['open_register_extent']
            plans=[
                [unit for start,end,enabled in selected for unit in _mark_integrity_stream_units(
                    _lower_units(fn.code,splits,fuses,defers,0,self.protected[id(fn)],start,end,
                        state['instruction_forms'],variant if enabled else 0),fn.code,integrity,stream)]
                for variant in range(total)]
            self.plans[id(fn)]=[]
            for plan in plans:
                lookup={unit[1]:unit for unit in plan}
                lookup.update((unit[2],unit) for unit in plan if unit[0]=='fuse')
                self.plans[id(fn)].append(lookup)
        for plan in self.plans[id(fn)]:
            units=[];seen=set()
            for index in indexes:
                unit=plan[index]
                if unit[1] in seen:continue
                seen.add(unit[1])
                covered={unit[1],unit[2]} if unit[0]=='fuse' else {unit[1]}
                overlap|=not covered<=owned;units.append(unit)
            reports=[];kinds=[]
            for unit in units:
                kind,index=unit[:2];op=fn.code[index].op;kinds.append(kind)
                if kind=='normal':reports.append(normal(index))
                elif kind=='fuse':reports.append(self.body('fuse',op,fn.code[unit[2]].op))
                elif kind=='split':reports.extend(self.body('split',op,(int(unit[2]),part)) for part in range(int(unit[2])))
                else:reports.append(self.body('defer',op,0))
            variants.append({'work':sum(r['work'] for r in reports)+len(reports)*dispatch,
                'dispatches':len(reports),'body_bytes':sum(r['bytes'] for r in reports),'kinds':kinds})
        # All runtime-selectable block variants survive. Efficiency must beat
        # the cheapest legal fallback, not just an expensive representative.
        rows['planned']={'work':min(r['work'] for r in variants),'variants':variants}
        if any('fuse' in r['kinds'] for r in variants):
            rows['fusion']=min((r for r in variants if 'fuse' in r['kinds']),key=lambda r:r['work'])
        else:rows['fusion']={'unavailable':'no_planned_pair'}
        rows['baseline']='planned'
        rows['cross_region_unit']=overlap
        return rows
