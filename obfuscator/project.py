"""Project discovery and stable module choices above the single-file pipeline."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
import fnmatch
import hashlib
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import random
from typing import cast

from .config_types import ObfuscatorConfig
from .registry import ConfigError, config_warnings, get_profile_names, resolve_config_profile, validate_config
from .presets import canonical_name
from .vm.backend import normalize_vm_backend
from .vm.targets.profile import TargetProfile
from .project_analysis import analyze_modules

REPORT_NAME = 'karity-project-report.json'


class ProjectError(ConfigError):
    pass


def digest_file(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or '\0' in value:
        raise ProjectError('Module paths must be nonempty relative paths')
    text = value.replace('\\', '/')
    if text.startswith('/') or PureWindowsPath(text).drive or any(p in ('', '.', '..') for p in text.split('/')):
        raise ProjectError(f'Unsafe project path: {value}')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}
    for part in text.split('/'):
        if part.endswith((' ', '.')) or any(ord(c)<32 or c in '<>:"|?*' for c in part) or part.split('.')[0].upper() in reserved:
            raise ProjectError(f'Nonportable project path: {value}')
    return text


def is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def safe_source(root: Path, relative: str) -> Path:
    path = root
    for part in relative_path(relative).split('/'):
        path = path / part
        if is_link(path):raise ProjectError(f'Symbolic links/junctions are not supported: {relative}')
    if not path.resolve().is_relative_to(root):raise ProjectError(f'Path leaves project: {relative}')
    return path


def matches(path: str, pattern: str) -> bool:
    """Component-aware globbing, including zero-directory ** matches."""
    parts = path.split('/');positions = {0}
    for token in pattern.split('/'):
        if token == '**':
            positions = set(range(min(positions), len(parts)+1)) if positions else set()
        else:
            positions = {i+1 for i in positions if i<len(parts) and fnmatch.fnmatchcase(parts[i], token)}
    return len(parts) in positions


def patterns(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(p,str) and p and not p.startswith(('/', '\\'))
            and not PureWindowsPath(p).drive and '..' not in p.replace('\\','/').split('/') for p in value):
        raise ProjectError(f'project.{key} must contain relative glob patterns')
    return tuple(p.replace('\\','/') for p in value)


@dataclass(frozen=True)
class ProjectFile:
    path: str
    kind: str
    sha256: str
    size: int
    source: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ModulePlan:
    file: ProjectFile
    preset: str
    backend: str
    selection: dict
    config: dict = field(repr=False)
    analysis: dict = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    error: str | None = None

    def as_dict(self, *, effective=True) -> dict:
        result = {'path': self.file.path, 'module_id': hashlib.sha256(self.file.path.encode()).hexdigest()[:20],
                  'output': self.file.path, 'preset': self.preset, 'backend': self.backend,
                  'selection': dict(self.selection), 'kind': self.file.kind, 'input_bytes': self.file.size,
                  'source_sha256': self.file.sha256, 'status': 'invalid' if self.error else 'pending',
                  'compatibility': {'valid': self.error is None, 'warnings': list(self.warnings), 'error': self.error},
                  'dependencies': deepcopy(self.analysis)}
        if effective:result['effective_config'] = deepcopy(self.config)
        return result


@dataclass(frozen=True)
class ProjectPlan:
    root: Path
    output: Path
    entry: str
    seed: str
    modules: tuple[ModulePlan, ...]
    resources: tuple[ProjectFile, ...]
    cycles: tuple[tuple[str, ...], ...]
    document: dict = field(repr=False)
    base: Path = field(repr=False)
    id: str = ''

    @property
    def valid(self) -> bool:
        return all(module.error is None for module in self.modules)

    def as_dict(self) -> dict:
        return {'plan_id': self.id, 'root': str(self.root), 'output': str(self.output), 'entry': self.entry,
                'format': 'directory', 'selection_seed': self.seed, 'valid': self.valid,
                'modules': [m.as_dict() for m in self.modules],
                'resources': [{'path': f.path, 'kind': 'resource', 'output': f.path, 'status': 'pending',
                               'input_bytes': f.size, 'source_sha256': f.sha256} for f in self.resources],
                'cycles': [list(c) for c in self.cycles]}


def _policy(value, kind, context):
    if value is None:return {'mode': 'default'}
    if not isinstance(value, dict) or value.get('mode') not in ('fixed', 'weighted'):
        raise ProjectError(f'project.{kind}_selection.mode must be fixed or weighted')
    mode = value['mode']
    choices = value.get('weights') if mode == 'weighted' else {value.get('value'): 1}
    if not isinstance(choices, dict) or not choices:
        raise ProjectError(f'project.{kind}_selection needs nonempty choices')
    known = get_profile_names(context)
    provided = []
    for name, weight in choices.items():
        if not isinstance(name, str):raise ProjectError(f'{kind} choices must be names')
        if kind == 'backend':
            try:name = normalize_vm_backend(name)
            except ValueError as error:raise ProjectError(str(error)) from error
        elif name != 'custom' and name not in known and canonical_name(name) is None:
            raise ProjectError(f'Unknown project preset: {name}')
        try:finite = isinstance(weight,(int,float)) and math.isfinite(weight)
        except OverflowError:finite = False
        if isinstance(weight, bool) or not finite or weight < 0:
            raise ProjectError(f'Invalid {kind} weight for {name}')
        provided.append((name,weight))
    maximum = max(weight for _,weight in provided)
    if maximum==0:raise ProjectError(f'All {kind} weights are zero')
    normalized: dict[str,float] = {}
    for name,weight in provided:normalized[name] = normalized.get(name,0) + weight/maximum
    return {'mode': mode, 'weights': normalized}


def _choose(policy: dict, seed: str, path: str, kind: str):
    if policy['mode'] == 'default':return None, 'default'
    choices = sorted(policy['weights']);weights = [policy['weights'][c] for c in choices]
    # Selection streams never consume build/security randomness.
    stream = random.Random(hashlib.sha256(json.dumps([seed,path,kind],ensure_ascii=False).encode()).digest())
    return stream.choices(choices, weights=weights, k=1)[0], policy['mode']


def _config(context: dict, preset: str | None, backend: str | None) -> dict:
    context = deepcopy(context)
    if backend is not None:
        target = context.get('config', context)
        target.setdefault('vm_options', {})['backend'] = backend
        selected = preset or target.get('profile')
        if selected in target.get('profiles', {}):
            target['profiles'][selected].setdefault('vm_options', {})['backend'] = backend
    if preset == 'custom':
        context.pop('profile', None);context.pop('profiles', None)
        preset = None
    config: dict = dict(resolve_config_profile(context, preset))
    if backend is not None:config.setdefault('vm_options', {})['backend'] = backend
    # Shared dump paths could overwrite inputs or one another outside staging.
    if config.get('debug_dumps'):raise ProjectError('Project Mode does not support shared debug_dumps paths')
    validate_config(config)
    return config


def _discover(root, output, include, exclude, copy_resources, resource_include):
    files = [];discovered = set();portable = {};pending = [root]
    while pending:
        folder = pending.pop()
        for node in sorted(folder.iterdir(),key=lambda p:p.name):
            if node == output or (node.parent == output.parent and node.name.startswith(('.karity-stage-', '.karity-backup-'))):continue
            rel = node.relative_to(root).as_posix()
            if any(matches(rel,p) for p in exclude):continue
            if is_link(node):raise ProjectError(f'Symbolic links/junctions are not supported: {rel}')
            if node.is_dir():pending.append(node);continue
            if not node.is_file():raise ProjectError(f'Unsupported project file: {rel}')
            lua = node.suffix.lower() == '.lua'
            if lua:discovered.add(rel)
            selected = any(matches(rel,p) for p in (include if lua else resource_include))
            if not selected or not lua and not copy_resources:continue
            relative_path(rel)
            for i in range(1,len(PurePosixPath(rel).parts)+1):
                prefix = '/'.join(PurePosixPath(rel).parts[:i]);key = prefix.casefold()
                if key in portable and portable[key] != prefix:raise ProjectError(f'Output path collision: {prefix} / {portable[key]}')
                portable[key] = prefix
            if rel.casefold() == REPORT_NAME.casefold():raise ProjectError(f'Reserved output name: {rel}')
            data = node.read_bytes() if lua else None
            try:source = data.decode('utf-8-sig') if data is not None else None
            except UnicodeError as error:raise ProjectError(f'Lua source is not UTF-8: {rel}') from error
            files.append(ProjectFile(rel,'lua' if lua else 'resource',
                hashlib.sha256(data).hexdigest() if data is not None else digest_file(node),
                len(data) if data is not None else node.stat().st_size,source))
    files.sort(key=lambda f:f.path)
    return files, discovered


def _seal(plan: ProjectPlan) -> str:
    public = plan.as_dict();public.pop('plan_id')
    return hashlib.sha256(json.dumps({'document':plan.document,'base':str(plan.base),'plan':public},
                                    sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def validate_plan(plan: ProjectPlan) -> None:
    """Revalidate the snapshot without executing any selection policy again."""
    if _seal(plan) != plan.id:raise ProjectError('Selection plan was modified; refresh the preview')
    if is_link(plan.root) or is_link(plan.output) or plan.root.resolve()!=plan.root or plan.output.resolve()!=plan.output:
        raise ProjectError('Project paths changed; refresh the preview')
    project = plan.document['project']
    files, _ = _discover(plan.root,plan.output,patterns(project.get('include',['**/*.lua']),'include'),
        patterns(project.get('exclude',['**/.git/**']),'exclude'),project.get('copy_resources',False),
        patterns(project.get('resource_include',['**/*']),'resource_include'))
    expected = sorted((m.file.path,m.file.sha256,m.file.size) for m in plan.modules)
    expected += sorted((f.path,f.sha256,f.size) for f in plan.resources)
    if sorted(expected) != [(f.path,f.sha256,f.size) for f in files]:
        raise ProjectError('Project files changed; refresh the preview')


def create_plan(document: dict, base: Path | str = '.') -> ProjectPlan:
    if not isinstance(document, dict) or not isinstance(document.get('project'), dict):
        raise ProjectError('Project configuration requires a project object')
    base = Path(base).resolve();project = deepcopy(document['project'])
    context = {k: deepcopy(v) for k,v in document.items() if k != 'project'}
    for key in ('root','output'):
        if not isinstance(project.get(key),str) or not project[key].strip() or '\0' in project[key]:
            raise ProjectError(f'project.{key} is required')
    raw_root = base / project['root'];raw_output = base / project['output']
    if is_link(raw_root) or is_link(raw_output):raise ProjectError('Project root/output cannot be a symbolic link or junction')
    root = raw_root.resolve();output = raw_output.resolve()
    if not root.is_dir():raise ProjectError('Project root is not a directory')
    if root == output or root.is_relative_to(output):raise ProjectError('Output cannot contain or replace the input project')
    if output.exists() and not output.is_dir():raise ProjectError('Output is not a directory')
    if project.get('format','directory') != 'directory':raise ProjectError('Only directory project output is supported')
    entry = relative_path(project.get('entry','main.lua'))
    include = patterns(project.get('include',['**/*.lua']), 'include')
    exclude = patterns(project.get('exclude',['**/.git/**']), 'exclude')
    resource_include = patterns(project.get('resource_include',['**/*']), 'resource_include')
    copy_resources = project.get('copy_resources',False)
    if not isinstance(copy_resources,bool):raise ProjectError('project.copy_resources must be a boolean')
    templates = project.get('module_paths',['?.lua','?/init.lua'])
    if not isinstance(templates,list) or not templates or not all(isinstance(t,str) and '?' in t and not t.startswith(('/','\\'))
            and not PureWindowsPath(t).drive and '\\' not in t and '..' not in t.split('/') for t in templates):
        raise ProjectError('project.module_paths must contain safe relative Lua search templates')
    policies = {kind: _policy(project.get(kind+'_selection'),kind,context) for kind in ('preset','backend')}
    overrides = project.get('module_overrides',{})
    if not isinstance(overrides,dict):raise ProjectError('project.module_overrides must be an object')
    normalized_overrides = {}
    for path, value in overrides.items():
        path = relative_path(path)
        if not isinstance(value,dict) or set(value)-{'preset','backend'}:raise ProjectError(f'Invalid override: {path}')
        for kind, name in value.items():_policy({'mode':'fixed','value':name},kind,context)
        if path in normalized_overrides:raise ProjectError(f'Duplicate override: {path}')
        normalized_overrides[path] = value
    seed = project.get('seed')
    if seed is None:seed = hashlib.sha256(('karity-project-selection-v1:'+str(root)).encode()).hexdigest()
    if isinstance(seed,bool) or not isinstance(seed,(str,int)) or not str(seed):raise ProjectError('project.seed must be a nonempty string or integer')
    seed = str(seed)
    files, discovered = _discover(root,output,include,exclude,copy_resources,resource_include)
    sources = {f.path:f.source for f in files if f.source is not None}
    if entry not in sources:raise ProjectError(f'Entry is missing or excluded: {entry}')
    if set(normalized_overrides)-sources.keys():raise ProjectError('Override refers to missing/excluded module: '+', '.join(sorted(set(normalized_overrides)-sources.keys())))
    def local_exists(path):
        return safe_source(root,path).is_file()
    analysis, cycles = analyze_modules(sources, discovered, tuple(templates),
                                      context.get('target',{}).get('lua_version','5.3'), local_exists=local_exists)
    modules = []
    for file in files:
        if file.kind != 'lua':continue
        choices = {};reasons = {}
        for kind in ('preset','backend'):
            choices[kind],reasons[kind] = _choose(policies[kind],seed,file.path,kind)
            if kind in normalized_overrides.get(file.path,{}):
                choices[kind] = normalized_overrides[file.path][kind];reasons[kind] = 'override'
        config = {};error = None;warnings = list(analysis[file.path]['warnings'])
        try:
            config = _config(context,choices['preset'],choices['backend'])
            backend = TargetProfile.from_config(cast(ObfuscatorConfig,config)).backend
            preset = config.get('_profile', choices['preset'] or 'custom')
            warnings.extend(config_warnings(config))
        except (ConfigError,ValueError) as exc:
            error = str(exc);backend = choices['backend'] or 'karity';preset = choices['preset'] or 'custom'
        modules.append(ModulePlan(file,preset,backend,reasons,config,analysis[file.path],tuple(warnings),error))
    plan = ProjectPlan(root,output,entry,seed,tuple(modules),tuple(f for f in files if f.kind=='resource'),
                       tuple(tuple(c) for c in cycles),deepcopy(document),base)
    return replace(plan,id=_seal(plan))
