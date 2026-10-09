"""Normalize common control flow without referring to frontend opcodes."""
from dataclasses import replace
from .model import SemanticIR
from .operations import OPERATIONS
from .validate import validate_semantic_ir


def normalize_semantic_ir(ir: SemanticIR) -> SemanticIR:
    validate_semantic_ir(ir)
    def normalize(function):
        records={block.id:[list(block.instructions),block.successors] for block in function.blocks}
        predecessors={block.id:set() for block in function.blocks}
        for block in function.blocks:
            for successor in block.successors:
                predecessors[successor].add(block.id)
        entry=function.blocks[0].id if function.blocks else None
        for block in function.blocks:
            if block.id not in records:
                continue
            current=records[block.id]
            while len(current[1])==1 and OPERATIONS[current[0][-1].operation].edges is None:
                successor=current[1][0]
                if successor in (entry,block.id) or predecessors[successor]!={block.id}:
                    break
                following=records.pop(successor)
                # Keep instruction identities and preserve entry/branch targets.
                current[0][-1]=replace(current[0][-1],targets=())
                current[0].extend(following[0])
                current[1]=following[1]
                for target in following[1]:
                    predecessors[target].discard(successor)
                    predecessors[target].add(block.id)
        blocks=tuple(replace(block,instructions=tuple(records[block.id][0]),successors=records[block.id][1])
                     for block in function.blocks if block.id in records)
        return replace(function,blocks=blocks,children=tuple(normalize(child) for child in function.children))
    result=replace(ir,root=normalize(ir.root))
    validate_semantic_ir(result)
    return result
