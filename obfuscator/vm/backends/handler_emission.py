"""Shared handler ABI transforms; executor policy belongs to each backend."""
from ..vm_obfuscation import (
    apply_vop_to_vm, prune_and_inject_handlers, apply_split_to_vm,
    apply_fuse_to_vm, apply_defer_to_vm, apply_dispatch,
)


def single_handlers(source, lowered, variant, *, vm_index=0, executor_name=None,
                    handler_map=None, used_ops=None):
    layout = lowered.backend_data['layout']
    vops, splits, fuses, defers = (
        handler_map if handler_map is not None else layout.vm_maps[vm_index]
    )
    used_ops = layout.used_ops[vm_index] if used_ops is None else used_ops
    mutate = variant['mutate_handlers']
    mutation_seed = variant['mutation_seed'] if mutate else None
    mutation_identities = {
        vop: f"alias:{operation}:{ordinal}"
        for operation, aliases in vops.items()
        for ordinal, vop in enumerate(aliases)
    }
    native_state = (
        '--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source
        or '--<<TARGET_KARITY_EXEC_STATE>>' in source
    )
    source = apply_vop_to_vm(
        source, vops, 0.0, variant['semantic_alias_modes'],
        native_state=native_state,
        alias_transition_indices=variant['alias_transition_indices'],
    )
    source = prune_and_inject_handlers(
        source, used_ops, fake_handlers=bool(variant['decoy_body_variants']),
        mutate=mutate, fake_body_variants=variant['decoy_body_variants'],
        native_state=native_state, mutation_seed=mutation_seed,
        mutation_identities=mutation_identities)
    source = apply_split_to_vm(source, splits, mutate=mutate, native_state=native_state,
                               mutation_seed=mutation_seed)
    source = apply_fuse_to_vm(source, fuses, mutate=mutate, native_state=native_state,
                              mutation_seed=mutation_seed)
    source = apply_defer_to_vm(source, defers, mutate=mutate, native_state=native_state,
                               mutation_seed=mutation_seed)
    if executor_name is not None:
        source = source.replace('exec = function', f'{executor_name} = function', 1)
    return apply_dispatch(source, variant['dispatcher'])
