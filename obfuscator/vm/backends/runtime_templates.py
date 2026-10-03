"""Shared template assembly primitives; backend classes select executors."""
from pathlib import Path

_RUNTIMES = Path(__file__).parents[1] / 'runtimes'


def classic_executor():
    return (_RUNTIMES / 'classic_exec.lua').read_text(encoding='utf-8')


def direct_executor(source, executor, *, target=None):
    start = source.index('local exec, _EX, _NX')
    marker = '--<<ENDNEXT_ROUTER>>'
    end = source.index(marker, start) + len(marker)
    source = source[:start] + executor + source[end:]
    start = source.index('--<<RUN_ENTRY>>')
    marker = '--<<ENDRUN_ENTRY>>'
    end = source.index(marker, start) + len(marker)
    entry = (target.direct_runtime_entry() if target else
             '_EX[proto.vm_id+1](proto,{env_box,environment=env_box.v},table.pack())')
    return source[:start] + entry + source[end:]
