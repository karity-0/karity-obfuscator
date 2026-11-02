"""Stage independent module builds and publish a complete directory."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import uuid
from typing import cast

from .config_types import ObfuscatorConfig
from .pipeline import Pipeline
from .profiling import Profiler, phase_scope
from .registry import PASS_REGISTRY, build_pipeline_from_config
from .project import (ProjectError, ProjectPlan, REPORT_NAME, digest_file, is_link,
                      relative_path, safe_source, validate_plan)


class ProjectBuildError(ProjectError):
    def __init__(self, message, report):
        super().__init__(message)
        self.report = report


def _owned_output(output: Path, root: Path) -> None:
    if not output.exists():return
    if is_link(output) or not output.is_dir():raise ProjectError('Output is not a normal directory')
    if not any(output.iterdir()):return
    try:
        report_path = output/REPORT_NAME
        if is_link(report_path):raise ValueError('linked report')
        report = json.loads(report_path.read_text(encoding='utf8'))
        if report.get('owner')!='karity-project' or report.get('root')!=str(root) or not report.get('published'):
            raise ValueError('not owned by this project')
        inventory = report['inventory']
        if not isinstance(inventory,dict):raise ValueError('invalid inventory')
        expected = {relative_path(p):checksum for p,checksum in inventory.items()}
        actual = set()
        for path in output.rglob('*'):
            if is_link(path):raise ValueError('linked output')
            if path.is_file() and path != report_path:
                rel = path.relative_to(output).as_posix();actual.add(rel)
                if rel not in expected or digest_file(path)!=expected[rel]:raise ValueError('modified output')
        if actual != set(expected):raise ValueError('missing/extra output files')
    except (OSError,ValueError,KeyError,TypeError) as error:
        raise ProjectError('Refusing to replace an unowned or modified output directory: '+str(output)) from error


def _remove_stage(path: Path, parent: Path) -> None:
    if path.parent != parent or not path.name.startswith(('.karity-stage-','.karity-backup-')) or is_link(path):
        raise ProjectError('Unsafe temporary directory cleanup')
    if path.resolve().parent != parent:raise ProjectError('Temporary directory moved')
    shutil.rmtree(path)


def _backends(profile: dict) -> list[str]:
    result = set();pending = [profile]
    while pending:
        item = pending.pop()
        if isinstance(item,dict):
            if item.get('phase')=='backend_lowering' and item.get('backend') in ('karity','classic','mov','bare'):
                result.add(item['backend'])
            pending.extend(item.values())
        elif isinstance(item,list):pending.extend(item)
    return sorted(result)


def build_project(plan: ProjectPlan) -> dict:
    started = time.perf_counter()
    report: dict = {'owner':'karity-project','schema':1,'plan_id':plan.id,'root':str(plan.root),
              'output':str(plan.output),'entry':plan.entry,'format':'directory','published':False,
              'selection_plan':plan.as_dict(),'modules':[], 'resources':[], 'cycles':[list(c) for c in plan.cycles],
              'inventory':{},'warnings':[],'error':None}
    for module in plan.modules:
        row = module.as_dict(effective=False)
        row.update(planned_preset=module.preset,planned_backend=module.backend,preset=None,backend=None,
                   actual_backends=[],status='pending',published=False)
        report['modules'].append(row)
    stage = None;backup = None;current = None
    try:
        if not plan.valid:raise ProjectError('Project has incompatible module configurations')
        validate_plan(plan)
        _owned_output(plan.output,plan.root)
        plan.output.parent.mkdir(parents=True,exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix='.karity-stage-',dir=plan.output.parent)).resolve()
        names = {getattr(info,'class_name',name):name for name,info in PASS_REGISTRY.items()}
        for module, row in zip(plan.modules,report['modules']):
            current = row;row['status'] = 'building';module_started = time.perf_counter()
            with phase_scope('project:'+module.file.path):
                source_path = safe_source(plan.root,module.file.path)
                if digest_file(source_path)!=module.file.sha256:raise ProjectError('Source changed: '+module.file.path)
                pipeline = build_pipeline_from_config(cast(ObfuscatorConfig,deepcopy(module.config)),Pipeline)
                profiler = Profiler()
                assert module.file.source is not None
                output = pipeline.run(module.file.source,profiler=profiler)
                destination = stage/module.file.path;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(output.encode('utf8'))
                profile = profiler.as_dict();backends = _backends(profile)
                actual = backends[0] if len(backends)==1 else 'mixed' if backends else None
                row.update(status='success',preset=module.preset,backend=actual,actual_backends=backends,
                           target={'lua_version':pipeline.target_profile.lua_version,'environment':pipeline.target_profile.environment.value},
                           vm_applied=bool(backends),executed_passes=[names.get(r.name,r.name) for r in profiler.records
                                                                   if r.name!='VMPass' or backends],
                           output_bytes=destination.stat().st_size,elapsed=time.perf_counter()-module_started,
                           profile=profile,selections=deepcopy(pipeline.last_selection_report),error=None)
                processed = any(name not in ('OutputSignaturePass','signature') for name in row['executed_passes'])
                row['protection_status'] = ('processed' if processed else 'unchanged'
                    if module.config.get('signature',{}).get('mode')=='none' else 'signature_only')
                report['inventory'][module.file.path] = digest_file(destination)
            current = None
        for resource in plan.resources:
            row = {'path':resource.path,'kind':'resource','status':'pending','published':False};report['resources'].append(row)
            current = row
            with phase_scope('project-copy:'+resource.path):
                source = safe_source(plan.root,resource.path)
                if digest_file(source)!=resource.sha256:raise ProjectError('Resource changed: '+resource.path)
                destination = stage/resource.path;destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,destination)
                if digest_file(destination)!=resource.sha256:raise ProjectError('Resource changed during copy: '+resource.path)
                row.update(status='copied',input_bytes=resource.size,output_bytes=resource.size)
                report['inventory'][resource.path] = resource.sha256
            current = None
        with phase_scope('project:publish'):
            validate_plan(plan)
            _owned_output(plan.output,plan.root)
            untransformed = sum(row.get('protection_status') in ('signature_only','unchanged') for row in report['modules'])
            if untransformed:
                report['warnings'].append(f'{untransformed} module(s) completed without transformation passes; see per-module protection_status.')
            for row in report['modules']+report['resources']:row['published'] = True
            report['published'] = True;report['elapsed'] = time.perf_counter()-started
            (stage/REPORT_NAME).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
            if plan.output.exists():
                backup = plan.output.with_name('.karity-backup-'+uuid.uuid4().hex)
                os.replace(plan.output,backup)
            try:os.replace(stage,plan.output)
            except OSError as error:
                if backup is not None and not plan.output.exists():
                    try:os.replace(backup,plan.output)
                    except OSError as rollback:
                        raise ProjectError(f'Publication failed; previous output retained at {backup}: {rollback}') from error
                    backup = None
                raise
            stage = None
            if backup is not None:
                try:
                    _owned_output(backup,plan.root)
                    _remove_stage(backup,plan.output.parent)
                except (OSError,ProjectError):
                    report['warnings'].append('Previous output retained at '+str(backup))
        return report
    except Exception as error:
        report['published'] = False;report['error'] = str(error);report['elapsed'] = time.perf_counter()-started
        for row in report['modules']+report['resources']:row['published'] = False
        if current is not None:current.update(status='failed',error=str(error))
        raise ProjectBuildError(str(error),report) from error
    finally:
        if stage is not None and stage.exists():
            try:_remove_stage(stage,plan.output.parent)
            except (OSError,ProjectError):report['warnings'].append('Staged output retained at '+str(stage))
