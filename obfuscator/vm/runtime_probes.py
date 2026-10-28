"""Shared native observations and build-specific protected validation source."""
from dataclasses import dataclass
from pathlib import Path
import random
import re


@dataclass(frozen=True)
class ProbePlan:
    worker: str
    results: tuple[int, int, int]
    modes: tuple[int, int, int, int]  # idle, line, count, quiet
    first: str
    count: int
    full_options: str
    short_options: str
    api_order: tuple[str, ...]
    info_fields: tuple[str, ...]
    observation_slots: tuple[int, ...]
    lua_version: str | None = None


def new_plan(lua_version: str | None = None) -> ProbePlan:
    """Vary private work/observations; API meanings and detection bounds stay fixed."""
    value=random.randrange(4096,65536)
    lines=[f'local value={value}']
    results=[]
    for stage in range(3):
        n=random.randint(8,24)
        a,b,c=(random.randint(1,17),random.randint(1,17),random.randint(1,31))
        recipe=random.randrange(4)
        if recipe==0:
            lines.append(f'for i=1,{n} do value=value+(i+{b})*{a} end')
            value+=sum((i+b)*a for i in range(1,n+1))
        elif recipe==1:
            lines.append(f'for i={n},1,-1 do value=value+i*{a}+{b} end')
            value+=sum(i*a+b for i in range(1,n+1))
        elif recipe==2:
            lines.append(f'local i=0;repeat i=i+1;value=value+(i*i+{b})*{a} until i=={n}')
            value+=sum((i*i+b)*a for i in range(1,n+1))
        else:
            lines.append(f'for i=1,{n} do if i%2==0 then value=value+i*{a}+{c} '
                         f'else value=value+i*{b}+{c} end end')
            value+=sum(i*(a if i%2==0 else b)+c for i in range(1,n+1))
        results.append(value)
        lines.append('Q.yield(value)' if stage<2 else 'return value')
    def shuffled(items):return tuple(random.sample(items,len(items)))
    modes=random.sample(range(128,2**20),4)
    return ProbePlan('\n'.join(lines),(results[0],results[1],results[2]),
        (modes[0],modes[1],modes[2],modes[3]),random.choice(('line','count')),
        random.randint(1,7),''.join(random.sample('Suf',3)),random.choice(('Sf','fS')),
        shuffled(('info','hook','pcall','sethook','create','resume','yield','status','running')),
        shuffled(('func','what','source','short_src','linedefined','lastlinedefined','nups','nparams','isvararg')),
        tuple(random.sample(range(31,4096),24)),
        lua_version)


def _bindings(plan: ProbePlan, native_namespace: str = '') -> dict[str,str]:
    idle,line,count,quiet=plan.modes
    first_line=plan.first=='line'
    first_mode,last_mode=(line,count) if first_line else (count,line)
    first_mask,last_mask=('l','') if first_line else ('','l')
    first_count,last_count=(0,plan.count) if first_line else (plan.count,0)
    fields=plan.info_fields
    indices={field:(2*i,2*i+1) for i,field in enumerate(fields,1)}
    replacements={
        'NATIVE':native_namespace,'WORKER':plan.worker,
        'RESULT_FIRST':str(plan.results[0]),'RESULT_QUIET':str(plan.results[1]),
        'RESULT_LAST':str(plan.results[2]),'IDLE':str(idle),'LINE':str(line),
        'COUNT':str(count),'QUIET':str(quiet),'MODE_FIRST':str(first_mode),
        'MODE_LAST':str(last_mode),'MASK_FIRST':repr(first_mask),'MASK_LAST':repr(last_mask),
        'INTERVAL_FIRST':str(first_count),'INTERVAL_LAST':str(last_count),
        'FULL_OPTIONS':repr(plan.full_options),'SHORT_OPTIONS':repr(plan.short_options),
        'API_ORDER':','.join('Q.'+name for name in plan.api_order),
        'REQUIRE_PARAMS':'true' if plan.lua_version=='5.3' else 'false',
        'INFO_FIELDS':','.join(map(repr,fields)),
        'MATCH_RULES':','.join('{'+str(indices[f][0])+','+str(indices[f][1])+','+
            repr('string' if f in ('what','source','short_src') else 'number')+'}' for f in fields
            if f in ('what','source','short_src','linedefined','lastlinedefined')),
        'PCALL_INDEX':str(plan.api_order.index('pcall')+1),
        'EVENT_FIRST':repr('line' if first_line else 'count'),
        'EVENT_LAST':repr('count' if first_line else 'line'),
        'CLEAN_SLOTS':','.join(str(plan.observation_slots[i-1]) for i in (14,15,18,22,23)),
        'INSTALLED_SLOTS':','.join(str(plan.observation_slots[i-1]) for i in (16,20)),
        'RESUMED_SLOTS':','.join(str(plan.observation_slots[i-1]) for i in (17,19,21)),
    }
    for field,(tag,value) in indices.items():
        replacements[field.upper()+'_TYPE']=str(tag)
        replacements[field.upper()+'_VALUE']=str(value)
    return replacements


def _render(source: str, bindings: dict[str,str], plan: ProbePlan) -> str:
    def replace(match):
        name=match[1]
        if name not in bindings:raise ValueError('unresolved runtime probe boundary: '+name)
        return bindings[name]
    source=re.sub(r'__PROBE_([A-Z_]+)__',replace,source)
    # These identifiers belong solely to the generator templates. Physical
    # slots start at 31, so an already-rendered embedded oracle is not remapped.
    return re.sub(r'\b(o|observations)\[([1-9]|1[0-9]|2[0-4])\]',
        lambda m:m[1]+'['+str(plan.observation_slots[int(m[2])-1])+']',source)


def verifier_source(plan: ProbePlan) -> str:
    """One implementation, compiled into IR in production and native in unit oracles."""
    source=(Path(__file__).parent/'runtimes/runtime_verifier.lua').read_text(encoding='utf-8')
    return _render(source,_bindings(plan),plan)


EVIDENCE_SOURCE='''function S.evidence() return pending_evidence,kind,pcall end
function S.complete(ok)
 local present=pending_evidence~=nil
 pending_evidence=nil
 if ok~=true or not present then fail() end
end'''


def bootstrap_source(native_namespace: str, *, plan: ProbePlan | None = None,
                     lua_version: str | None = None, protected: bool = False) -> str:
    plan=plan or new_plan(lua_version)
    source=(Path(__file__).parent/'runtimes/runtime_probes.lua').read_text(encoding='utf-8')
    if source.count('__PROBE_NATIVE__')!=1:
        raise ValueError('runtime probe native namespace boundary is missing')
    bindings=_bindings(plan,native_namespace)
    bindings['PUBLISH']=('pending_evidence=observations' if protected else
        'local verify='+verifier_source(plan)+'\nlocal valid,result=Q.pcall(verify,observations,kind)\n'
        'if not valid or result~=true then fail() end')
    return _render(source,bindings,plan)
