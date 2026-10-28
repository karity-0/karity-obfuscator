"""One shared initialization probe; native mechanics remain bootstrap-safe.

This stage is not the auxiliary-IR integration. The template separates native
stack/worker collection from comparisons so actual validation can be protected
through the existing IR machinery without duplicating a second protocol.
"""
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
    c_fields: tuple[str, ...]
    lua_fields: tuple[str, ...]
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
        shuffled(('source','short_src'))+shuffled(('linedefined','lastlinedefined')),
        shuffled(('what','source','short_src'))+shuffled(('linedefined','lastlinedefined')),
        lua_version)


def bootstrap_source(native_namespace: str, *, plan: ProbePlan | None = None,
                     lua_version: str | None = None) -> str:
    plan=plan or new_plan(lua_version)
    source=(Path(__file__).parent/'runtimes/runtime_probes.lua').read_text(encoding='utf-8')
    if source.count('__PROBE_NATIVE__')!=1:
        raise ValueError('runtime probe native namespace boundary is missing')
    idle,line,count,quiet=plan.modes
    first_line=plan.first=='line'
    first_mode,last_mode=(line,count) if first_line else (count,line)
    first_mask,last_mask=('l','') if first_line else ('','l')
    first_count,last_count=(0,plan.count) if first_line else (plan.count,0)
    replacements={
        'NATIVE':native_namespace,'WORKER':plan.worker,
        'RESULT_FIRST':str(plan.results[0]),'RESULT_QUIET':str(plan.results[1]),
        'RESULT_LAST':str(plan.results[2]),'IDLE':str(idle),'LINE':str(line),
        'COUNT':str(count),'QUIET':str(quiet),'MODE_FIRST':str(first_mode),
        'MODE_LAST':str(last_mode),'MASK_FIRST':repr(first_mask),'MASK_LAST':repr(last_mask),
        'INTERVAL_FIRST':str(first_count),'INTERVAL_LAST':str(last_count),
        'MISSING_FIRST':'lines==0' if first_line else 'counts==0',
        'MISSING_LAST':'counts==0' if first_line else 'lines==0',
        'FULL_OPTIONS':repr(plan.full_options),'SHORT_OPTIONS':repr(plan.short_options),
        'API_ORDER':','.join('Q.'+name for name in plan.api_order),
        'C_FIELDS':','.join(map(repr,plan.c_fields)),
        'LUA_FIELDS':','.join(map(repr,plan.lua_fields)),
        'REQUIRE_PARAMS':'true' if plan.lua_version=='5.3' else 'false',
    }
    for name,value in replacements.items():
        marker='__PROBE_'+name+'__'
        if marker not in source:raise ValueError('runtime probe boundary is missing: '+name)
        source=source.replace(marker,value)
    if re.search(r'__PROBE_[A-Z_]+__',source):raise ValueError('unresolved runtime probe boundary')
    return source
