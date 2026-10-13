"""Physical permutation changes storage while preserving composite dispatch."""
from pathlib import Path
import sys
import random

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from profile_vm_runtime import build,execute,FIXTURES,SETTINGS
from obfuscator.vm.backends.handler_layout import PhysicalFunction,PhysicalInstruction
from obfuscator.vm.backends.handler_ir import HandlerInstruction,HandlerFunction
from obfuscator.vm.backends.block_permutation import permute_blocks


def limits():
    n=131075
    move=PhysicalInstruction(HandlerInstruction(0),0,(),())
    jump=PhysicalInstruction(HandlerInstruction(30).with_bx(131071),30,(),())
    ret=PhysicalInstruction(HandlerInstruction(38),38,(),())
    source=HandlerFunction('limit',0,0,2,[],[],[],[])
    code=[jump]+[move]*(n-2)+[ret]
    function=PhysicalFunction(source,0,code,[],set(),False,[],tuple(range(n)),((0,1),(1,2),(2,n)))
    permute_blocks(function,({59:[59]}, {},{},{}),rate=1,max_jumps=64,rng=random.Random(1))
    assert function.code is code and function.permutation['skip']=='relative_jump_range'


def main():
    limits()
    builds=0
    for version in ('5.1','5.3'):
        for backend in ('classic','karity'):
            for seed,fixture in ((712,'loops'),(921,'closures')):
                opts={'lua_version':version,'backend':backend,'vm_count':2,
                      'physical_block_permutation_rate':1.0}
                if backend=='karity':opts.update(SETTINGS['protected'])
                row=build(FIXTURES[fixture],opts,seed)
                assert execute(row['output'],version)[0]==execute(FIXTURES[fixture],version)[0]
                stats=[r for r in row['profile'] if r['phase']=='physical_block_permutation']
                assert any(r['moved_units'] for r in stats),stats
                assert all(r['bridges']<=64 for r in stats)
                builds+=1
                print('block-permutation-ok',version,backend,fixture,seed,flush=True)
    # Explicit disabling follows the existing physical emission path exactly.
    a=build(FIXTURES['loops'],{'physical_block_permutation_rate':0},712)
    b=build(FIXTURES['loops'],{},712)
    assert a['runtime']==b['runtime'] and a['blob_sha256']==b['blob_sha256']
    print('block-permutation-regression-ok',builds,'builds, address limit, disabled identity')


if __name__=='__main__':main()
