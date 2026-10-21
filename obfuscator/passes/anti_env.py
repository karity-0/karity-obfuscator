"""Opt-in denial of Roblox/executor-shaped execution environments."""
import random

from ..names import NameAllocator
from .base import PrePass


# These are shape checks only. None of the discovered APIs is invoked.
_SIGNALS = {
    'game': (('game',), 'object'),
    'workspace': (('workspace',), 'object'),
    'typeof': (('typeof',), 'function'),
    'instance': (('Instance', 'new'), 'function'),
    'enum': (('Enum',), 'object'),
    'spawn': (('task', 'spawn'), 'function'),
    'wait': (('task', 'wait'), 'function'),
    **{name: ((name,), 'function') for name in (
        'readfile', 'writefile', 'isfile', 'delfile', 'appendfile', 'listfiles',
        'getgenv', 'getrenv', 'getgc', 'getconnections', 'hookfunction',
        'hookmetamethod', 'checkcaller', 'identifyexecutor', 'getexecutorname')},
    'vector': (('Vector3', 'new'), 'function'),
    'frame': (('CFrame', 'new'), 'function'),
    'debug_constants': (('debug', 'getconstants'), 'function'),
    'debug_protos': (('debug', 'getprotos'), 'function'),
    'request': (('syn', 'request'), 'function'),
}

# Every build keeps these independent families. Randomness must not silently
# remove all coverage for a partial emulator that only exposes one family.
_CORE = {
    'roblox_core': (('game', 'workspace', 'typeof'), 3),
    'roblox_runtime': (('typeof', 'instance', 'enum', 'spawn', 'wait'), 4),
    'executor_files': (('readfile', 'writefile', 'isfile', 'delfile', 'appendfile', 'listfiles'), 4),
    'executor_introspection': (('getgenv', 'getrenv', 'getgc', 'getconnections',
        'hookfunction', 'hookmetamethod', 'checkcaller', 'identifyexecutor', 'getexecutorname'), 3),
}
_EXTRA = {
    'roblox_constructors': (('typeof', 'instance', 'vector', 'frame'), 4),
    'executor_debug': (('getgc', 'debug_constants', 'debug_protos'), 3),
    'executor_namespace': (('getgenv', 'identifyexecutor', 'request'), 3),
}


def _fault(allocator):
    name = allocator.allocate('fault')
    return random.choice((f'do local {name};{name}() end',
        f'do local {name};{name}={name}[1] end',
        f'do local {name};{name}=#{name} end'))


class AntiEnvPass(PrePass):
    """Snapshot related typed signals before guest code, then deny matching hosts.

    This deliberately blocks real matching environments too. It neither
    authenticates a host nor distinguishes an emulator from the real engine.
    """

    def run(self, script: str) -> str:
        allocator = NameAllocator.for_source(script)
        flag, kind, raw, attempt, env, lookup, environment = (
            allocator.allocate(hint) for hint in
            ('detected', 'kind', 'raw', 'attempt', 'env', 'lookup', 'environment'))
        owner, key, value, ok = (allocator.allocate() for _ in range(4))
        profiles = {**_CORE, **dict(random.sample(list(_EXTRA.items()), random.randint(1, len(_EXTRA))))}
        selected = list(profiles)
        random.shuffle(selected)
        signals = list(dict.fromkeys(signal for profile in selected for signal in profiles[profile][0]))
        random.shuffle(signals)
        names = {signal: allocator.allocate() for signal in signals}
        statements = [f'''local {flag}=(function()
local {kind},{raw},{attempt}=type,rawget,pcall
local {ok},{env}={attempt}(function() return _ENV end)
if {kind}({env})~='table' then
 local {ok},{environment}={attempt}(function() return getfenv end)
 if {kind}({environment})=='function' then
  local {ok},{value}={attempt}(function() return {environment}(1) end)
  if {ok} and {kind}({value})=='table' then {env}={value} end
 end
end
if {kind}({env})~='table' then
 local {ok},{value}={attempt}(function() return _G end);{env}={value}
end
if {kind}({env})~='table' then return false end
local function {lookup}({owner},{key})
 local {value}
 if {kind}({owner})=='table' then
  {value}={raw}({owner},{key});if {value}~=nil then return {value} end
 elseif {kind}({owner})~='userdata' then return nil end
 local {ok};{ok},{value}={attempt}(function() return {owner}[{key}] end)
 if {ok} then return {value} end
 return nil
end''']
        for signal in signals:
            path, expected = _SIGNALS[signal]
            expression = env
            for part in path:
                expression = f'{lookup}({expression},{part!r})'
            expression = f'{kind}({expression})'
            if expected == 'object':
                statements.append(f"local {names[signal]}={expression};{names[signal]}=({names[signal]}=='table' or {names[signal]}=='userdata')")
            else:
                statements.append(f"local {names[signal]}={expression}=='function'")
        conditions = []
        for profile in selected:
            members, threshold = profiles[profile]
            values = random.sample(list(members), len(members))
            if threshold == len(values):
                condition = '(' + ' and '.join(names[v] for v in values) + ')'
            else:
                count = '+'.join(f'({names[v]} and 1 or 0)' for v in values)
                condition = '(' + count + '>=' + str(threshold) + ')'
            conditions.append(condition)
        statements.append('return ' + ' or '.join(conditions) + '\nend)()\n')
        statements.append(f'if {flag} then {_fault(allocator)} end\n')

        # Later guards reuse the initial decision, so globals deliberately
        # introduced by the guest cannot create a new environment false positive.
        positions = []
        if 'function' in script:
            from .ts_utils import parse
            tree = parse(script)
            for node in tree.walk():
                if node.type in ('function_declaration', 'function_definition'):
                    body = node.child_by_field_name('body')
                    if body is not None:
                        positions.append(tree.cs(body))
        chosen = random.sample(positions, min(len(positions), random.randint(1, 3)))
        for position in sorted(chosen, reverse=True):
            script = script[:position] + f' if {flag} then {_fault(allocator)} end; ' + script[position:]
        self.last_selected_profiles = tuple(selected)
        self.last_guard_count = len(chosen) + 1
        return '\n'.join(statements) + script
