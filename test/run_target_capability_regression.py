"""Target requirements must keep host access and compatibility independent."""
import sys
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.vm.targets.capabilities import (
    Capability, CompatibilityPolicy, TargetEnvironment, TargetRequirements,
    HOST_CAPABILITIES, LUA_VERSION_CAPABILITIES,
)
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.targets.pass_requirements import (
    validate_pass_target, validate_vm_output_pass_target,
)


def main():
    policies = tuple(CompatibilityPolicy)
    for selected_index, selected in enumerate(policies):
        for minimum_index, minimum in enumerate(policies):
            assert selected.allows(minimum) == (selected_index >= minimum_index)
    memory = TargetRequirements({Capability.LOCAL_MEMORY_READ}, "binary_specific")
    for version in ("5.1", "5.3"):
        lua = LUA_VERSION_CAPABILITIES[version]
        assert memory.unmet(lua, "binary_specific") == ("local_memory_read",)
        ce = lua | HOST_CAPABILITIES[TargetEnvironment.CHEAT_ENGINE]
        assert memory.unmet(ce, "portable") == ("compatibility:binary_specific",)
        assert memory.unmet(ce, "binary_specific") == ()
    assert Capability.ENV_TABLE not in LUA_VERSION_CAPABILITIES["5.1"]
    assert Capability.GETFENV not in LUA_VERSION_CAPABILITIES["5.3"]
    assert not HOST_CAPABILITIES[TargetEnvironment.STANDALONE]
    for version in ('5.1', '5.3'):
        for backend in ('classic', 'karity', 'mov'):
            profile = TargetProfile(version, backend, environment='cheatengine',
                                    compatibility='binary_specific')
            assert profile.supports(memory)
            assert profile.adapter().lua_version == version
            assert not TargetProfile(version, backend).supports(memory)
    limited = TargetProfile(disabled_capabilities={'debug_library'})
    assert not limited.supports(TargetRequirements({'debug_library'}))
    portable = TargetProfile(environment='cheatengine', compatibility='portable')
    assert not portable.supports(TargetRequirements({'local_memory_read'}))
    configured = TargetProfile.from_config({'target': {'lua_version': '5.1'}})
    assert configured.lua_version == '5.1'
    validate_pass_target('vm', configured)
    # Build-time compilation does not imply a dynamic loader in the target VM.
    no_loader = TargetProfile(lua_version='5.1', disabled_capabilities={'text_chunk_load'})
    validate_pass_target('vm', no_loader)

    validate_pass_target('string_encode', configured)
    for name, profile in (('boolean_obf', configured),
                          ('meme_strings', configured),
                          ('anti_debug', configured),
                          ('localize_globals', configured),
                          ('vm', TargetProfile(compatibility='portable')),
                          ('pack', limited)):
        try:
            validate_pass_target(name, profile)
        except ValueError as error:
            assert 'pass ' + name in str(error)
        else:
            raise AssertionError('incompatible pass was accepted')
    from obfuscator import Pipeline, build_pipeline_from_config
    from obfuscator.registry import validate_config, ConfigError
    from obfuscator.vm.vm_pass import VMBuildPipeline
    config = {'passes': ['vm'], 'target': {'lua_version': '5.1'},
              'vm_options': {'backend': 'classic'}}
    pipeline = build_pipeline_from_config(config, Pipeline, show_header=False)
    assert pipeline.target_profile.lua_version == '5.1'
    assert pipeline._post_passes[0].target_profile == pipeline.target_profile
    validate_config({**config, 'vm_output_passes': ['localize_globals', 'minify']})
    validate_pass_target('function_obf', configured)
    validate_vm_output_pass_target('function_obf', configured)
    validate_config({**config, 'vm_output_passes': ['function_obf']})
    for unsupported in ('string_obf', 'boolean_obf', 'number_obf',
                        'anti_decompile', 'meme_strings'):
        try:
            validate_vm_output_pass_target(unsupported, configured)
        except ValueError as error:
            assert 'VM output pass ' + unsupported in str(error)
        else:
            raise AssertionError('Lua 5.1 output pass accepted unsupported syntax: ' + unsupported)
        try:
            validate_config({**config, 'vm_output_passes': [unsupported]})
        except ConfigError as error:
            assert 'VM output pass ' + unsupported in str(error)
        else:
            raise AssertionError('config accepted incompatible Lua 5.1 output pass: ' + unsupported)
        try:
            from obfuscator.vm import VMPass
            VMPass(target=configured, vm_output_passes=[unsupported])
        except ValueError as error:
            assert 'VM output pass ' + unsupported in str(error)
        else:
            raise AssertionError('direct VM API accepted incompatible output pass: ' + unsupported)
    for non_output in ('anti_debug', 'vm', 'pack', 'missing_pass'):
        try:
            validate_vm_output_pass_target(non_output, TargetProfile('5.3'))
        except ValueError:
            pass
        else:
            raise AssertionError('invalid VM output pass accepted: ' + non_output)
    for invalid in ({**config, 'passes': ['boolean_obf', 'vm']},
                    {**config, 'target': {'host_images': ['host.dll']}},
                    {**config, 'target': {'host_images': 'host.dll'}},
                    {**config, 'target': {'environment': 'unknown'}},
                    {**config, 'target': {'disabled_capabilities': 'debug_library'}},
                    {**config, 'target': {'compatibility': 'portable'}},
                    {**config, 'passes': ['pack']}):
        try:
            validate_config(invalid)
        except ConfigError:
            pass
        else:
            raise AssertionError('incompatible configuration accepted')
    try:
        VMBuildPipeline(target=TargetProfile(compatibility='portable'))
    except ValueError:
        pass
    else:
        raise AssertionError('direct VM API bypassed target policy')
    result = subprocess.run([sys.executable, str(ROOT / 'main.py'), '--print-config',
                             '--lua-version', '5.1', '--passes', 'vm',
                             '--vm-output-passes', 'minify',
                             '--target-environment', 'cheatengine',
                             '--compatibility', 'binary_specific'],
                            cwd=ROOT, capture_output=True, check=True)
    assert json.loads(result.stdout)['target'] == {
        'lua_version': '5.1', 'environment': 'cheatengine', 'compatibility': 'binary_specific'}
    try:
        TargetRequirements({"unknown_capability"})
    except ValueError:
        pass
    else:
        raise AssertionError("unknown requirement silently accepted")
    print("target-capability-regression-ok policies=9 host/version separation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
