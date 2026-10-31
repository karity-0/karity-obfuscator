"""CLI adapter for the same plan consumed by Project Mode's GUI."""
import json
from pathlib import Path
import random
import sys

from .project import ProjectError, REPORT_NAME, create_plan
from .project_build import ProjectBuildError, build_project
from .registry import get_profile_names, validate_deployment_config, validate_release_config


def run_project_cli(args) -> int:
    plan = None;report_path = None
    try:
        if args.input or args.output:
            raise ProjectError('Use project.root/output in the project JSON, without a single-file input/output')
        unsupported = ('profile','passes','vm_output_passes','packer_output_passes','vm_option',
                       'lua_version','target_environment','compatibility','host_image','opcode_synthesis','synthesis_policy',
                       'lua_executable','luac_executable','lua_library','profile_report','selection_report',
                       'dump_ir','dump_morphed_ir','dump_protected_ir','dump_protection_plan','dump_backend_ir','dump_synthesis_plan')
        if any(getattr(args,key,None) for key in unsupported):
            raise ProjectError('Set module protection policies in the project JSON')
        path = Path(args.project).resolve()
        document = json.loads(path.read_text(encoding='utf8'))
        if args.list_profiles:
            print('\n'.join(get_profile_names(document)));return 0
        if args.print_config:args.dry_run = True
        plan = create_plan(document,path.parent)
        if args.seed is not None:
            if args.release_check or args.deployment_check:raise ProjectError('Deployment/release checks reject reproducible test build seeds')
            random.seed(args.seed)
        for module in plan.modules:
            if args.release_check:validate_release_config(module.config)
            if args.deployment_check:validate_deployment_config(module.config)
            for warning in module.warnings:print(f'warning: {module.file.path}: {warning}',file=sys.stderr)
        report_path = Path(args.project_report).resolve() if args.project_report and args.project_report!='-' else None
        if report_path is not None:
            if report_path.is_relative_to(plan.root) and not report_path.is_relative_to(plan.output):
                raise ProjectError('Project report cannot modify the input project')
            if report_path.is_relative_to(plan.output) and report_path!=plan.output/REPORT_NAME:
                raise ProjectError('Inside output, use the managed '+REPORT_NAME)
            if args.dry_run and report_path.is_relative_to(plan.output):
                raise ProjectError('Dry run does not write to the project output directory')
        if args.dry_run:
            report = {'dry_run':True,**plan.as_dict()}
        else:
            report = build_project(plan)
        text = json.dumps(report,ensure_ascii=False,indent=2)+'\n'
        if report_path is not None and not (not args.dry_run and report_path==plan.output/REPORT_NAME):
            report_path.parent.mkdir(parents=True,exist_ok=True);report_path.write_text(text,encoding='utf8')
        if args.dry_run or args.project_report=='-':print(text,end='')
        else:print(f'Project completed: {len(plan.modules)} Lua modules -> {plan.output}')
        return 0 if plan.valid else 1
    except (OSError,ValueError) as error:
        print('error: '+str(error),file=sys.stderr)
        if isinstance(error,ProjectBuildError) and args.project_report=='-':
            print(json.dumps(error.report,ensure_ascii=False,indent=2))
        elif isinstance(error,ProjectBuildError) and report_path is not None and plan is not None and not report_path.is_relative_to(plan.output):
            report_path.parent.mkdir(parents=True,exist_ok=True)
            report_path.write_text(json.dumps(error.report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
        return 1
