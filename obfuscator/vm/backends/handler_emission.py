"""Shared handler ABI transforms; executor policy belongs to each backend."""
from ..vm_obfuscation import (
    apply_vop_to_vm, prune_and_inject_handlers, apply_split_to_vm,
    apply_fuse_to_vm, apply_defer_to_vm, apply_dispatch,
)


def single_handlers(source, lowered, variant, *, vm_index=0, executor_name=None):
    layout = lowered.backend_data['layout']
    vops, splits, fuses, defers = layout.vm_maps[vm_index]
    mutate = variant['mutate_handlers']
    native_state = (
        '--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source
        or '--<<TARGET_KARITY_EXEC_STATE>>' in source
    )
    source = apply_vop_to_vm(
        source, vops, 0.0, variant['semantic_alias_modes'],
        native_state=native_state,
    )
    source = prune_and_inject_handlers(
        source, layout.used_ops[vm_index], fake_handlers=bool(variant['decoy_body_variants']),
        mutate=mutate, fake_body_variants=variant['decoy_body_variants'],
        native_state=native_state)
    source = apply_split_to_vm(source, splits, mutate=mutate, native_state=native_state)
    source = apply_fuse_to_vm(source, fuses, mutate=mutate, native_state=native_state)
    source = apply_defer_to_vm(source, defers, mutate=mutate, native_state=native_state)
    if executor_name is not None:
        source = source.replace('exec = function', f'{executor_name} = function', 1)
    return apply_dispatch(source, variant['dispatcher'])
