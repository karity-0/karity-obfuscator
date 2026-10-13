"""Versioned user presets shared by the CLI, GUI and selection resolver.

Legacy/project profiles remain owned by their JSON file. These policies never
own the backend, target, signature, toolchain or explicit selection settings.
"""
from copy import deepcopy

REVISION = 2
USER_PRESETS = ('fast', 'balanced', 'strong', 'maximum')
PREFIX = 'builtin:'
CONTEXT_KEYS = ('target', 'signature', 'lua_executable', 'luac_executable',
                'lua_library', 'selection_modes', 'selection_profiles', 'debug_dumps')
OUTPUT_PASSES = ['strip_info', 'rename_obf', 'meme_strings', 'number_obf', 'minify']


def canonical_name(name):
    short = name.removeprefix(PREFIX) if isinstance(name, str) else ''
    return PREFIX + short if short in USER_PRESETS else None


def user_preset(name):
    canonical = canonical_name(name)
    if canonical is None:
        raise ValueError(f'unknown user preset: {name}')
    index = USER_PRESETS.index(canonical.removeprefix(PREFIX))
    full = index >= 2
    passes = ['strip_info', 'anti_debug', 'anti_decompile']
    if index == 1:
        passes += ['boolean_obf', 'localize_globals']
    elif full:
        passes += ['boolean_obf', 'table_obf', 'string_obf', 'function_obf',
                   'number_obf', 'localize_globals', 'meme_strings']
    passes += ['minify', 'vm']
    if index == 3:
        passes.append('pack')
    return {
        'passes': passes,
        'vm_output_passes': OUTPUT_PASSES.copy(),
        'packer_output_passes': OUTPUT_PASSES.copy(),
        'function_obf_options': {
            'boundary_mode': 'mixed', 'nested': True, 'all_source_functions': full,
            'nested_max_depth': (1, 1, 2, 4)[index],
            'loop_split': True, 'loop_unroll': True,
            'loop_unroll_rate': (0.15, 0.25, 0.35, 0.5)[index],
            'loop_unroll_max_iterations': (2, 3, 4, 4)[index],
            'loop_max_generated_blocks': (24, 32, 48, 64)[index],
            'loop_max_expansion_ratio': (16.0, 24.0, 32.0, 48.0)[index],
            'loop_max_depth': (1, 1, 2, 3)[index],
            'reconstruction_group_size': (8, 6, 4, 3)[index],
            'max_pass_expansion_ratio': (8.0, 10.0, 12.0, 16.0)[index],
        },
        'string_obf_options': {
            'steps_min': (2, 2, 3, 3)[index],
            'steps_max': (3, 3, 4, 5)[index],
            'slots_min': (2, 2, 2, 3)[index], 'slots_max': (3, 4, 4, 4)[index],
            'unroll_bytes': (8, 12, 16, 16)[index],
        },
        'literal_mosaic': {
            'style': 'exotic', 'cost': 'high', 'max_operations': 20,
            'output_cost': {
                'hot_operations': (2, 2, 3, 3)[index],
                'cold_operations': (3, 6, 12, 20)[index],
                'hot_meme_rate': (0.08, 0.1, 0.12, 0.15)[index],
                'cold_meme_rate': (0.15, 0.2, 0.25, 0.3)[index],
            },
        },
        'vm_options': {
            'physical_block_permutation_rate': (0.15, 0.35, 0.6, 0.8)[index],
            'physical_block_permutation_max_jumps': (8, 16, 32, 64)[index],
            'ir_mba_rate': (0.06, 0.2, 0.45, 0.65)[index],
            'ir_test_set_rate': (0.15, 0.25, 0.5, 0.75)[index],
            'ir_tail_duplication_rate': (0.04, 0.08, 0.18, 0.3)[index],
            'ir_rematerialization_rate': (0.03, 0.1, 0.25, 0.4)[index],
            'ir_morph_max_growth': (1.12, 1.2, 1.3, 1.4)[index],
            'ir_morph_max_added_instructions': (16, 32, 64, 96)[index],
            'ir_morph_max_added_blocks': (2, 4, 8, 12)[index],
            'ir_morph_max_transforms': (2, 4, 8, 12)[index],
            'ir_morph_max_depth': (1, 2, 2, 3)[index],
            'ir_morph_pass_max_added_instructions': (256, 512, 2048, 4096)[index],
            'ir_morph_max_new_operations': (1, 2, 3, 4)[index],
            'dispatcher_type': 'mixed', 'blob_form': 'random',
            'vm_count': (1, 1, 2, 3)[index], 'runtime_trace': False,
            'dispatcher_target_hiding': True,
            'semantic_state_threading': True, 'argument_virtualization': True,
            'upvalue_virtualization': True, 'table_virtualization': True,
            'branch_virtualization': True, 'fake_handlers': True,
            'mutate_handlers': True, 'junk_instructions': True,
            'junk_rate': (0.03, 0.06, 0.1, 0.15)[index],
            'integrity_constants': True,
            'integrity_constant_rate': (0.1, 0.15, 0.25, 0.35)[index],
            'graph_execution_rate': (0.03, 0.06, 0.12, 0.18)[index],
            'cross_instruction_rate': (0.1, 0.2, 0.3, 0.4)[index],
            'runtime_polymorphism_rate': (0.1, 0.15, 0.25, 0.35)[index],
            'block_variant_rate': (0.03, 0.06, 0.12, 0.18)[index],
            'block_variant_count': (2, 2, 3, 4)[index],
            'block_variant_max_instructions': (4, 6, 8, 10)[index],
            'helper_variant_count': (2, 2, 3, 4)[index],
            'helper_diversity_rate': (0.2, 0.3, 0.5, 0.7)[index],
            'semantic_diversity_rate': (0.2, 0.35, 0.55, 0.75)[index],
            'state_dependency_limit': (1, 2, 2, 3)[index],
        },
    }


def resolve_user_preset(name, context=None):
    context = context or {}
    result = {key: deepcopy(context[key]) for key in CONTEXT_KEYS if key in context}
    result.update(user_preset(name))
    for key in ('backend', 'requirements'):
        if key in context.get('vm_options', {}):
            result['vm_options'][key] = deepcopy(context['vm_options'][key])
    result['_profile'] = canonical_name(name)
    return result


def selection_profiles(project_profiles=None):
    """Qualified builtins cannot collide with user's unqualified names."""
    project = deepcopy(project_profiles or {})
    aliases = {name: user_preset(name) for name in USER_PRESETS if name not in project}
    profiles = {PREFIX + name: user_preset(name) for name in USER_PRESETS}
    return {**aliases, **project, **profiles}
