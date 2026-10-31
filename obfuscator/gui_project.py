"""Desktop project plans and result access; builds still use GuiBuild."""
from collections import OrderedDict
from copy import deepcopy
import json
import os
from pathlib import Path
import threading

import webview

from .project import ProjectError, create_plan, digest_file, is_link, relative_path, safe_source
from .project_build import ProjectBuildError, build_project


class ProjectApi:
    def _init_project(self):
        self._project_plans = OrderedDict()
        self._project_reports = {}
        self._project_lock = threading.RLock()

    def preview_project(self, payload):
        try:
            with self._build_lock:
                plan = create_plan(deepcopy(payload.get('document')),payload.get('base') or Path.cwd())
            with self._project_lock:
                self._project_plans[plan.id] = plan
                self._project_plans.move_to_end(plan.id)
                while len(self._project_plans)>8:
                    identity,_ = self._project_plans.popitem(last=False)
                    self._project_reports.pop(identity,None)
            return {'ok':True,'plan':plan.as_dict()}
        except (ValueError,OSError,TypeError) as error:
            return {'ok':False,'error':str(error)}

    def _run_project(self, payload):
        try:
            with self._project_lock:
                plan = self._project_plans.get(payload.get('plan_id'))
            if plan is None:raise ProjectError('Project preview expired; refresh it before building')
            if payload.get('document')!=plan.document:
                raise ProjectError('Project settings changed; refresh the preview')
            report = build_project(plan)
            with self._project_lock:self._project_reports[plan.id] = deepcopy(report)
            return {'ok':True,'project':True,'report':report,'elapsed':report['elapsed']}
        except ProjectBuildError as error:
            return {'ok':False,'project':True,'error':str(error),'report':error.report}
        except (ValueError,OSError,TypeError) as error:
            return {'ok':False,'project':True,'error':str(error)}

    def read_project_output(self, payload):
        try:
            identity = payload.get('plan_id');relative = relative_path(payload.get('path'))
            with self._project_lock:
                plan = self._project_plans.get(identity);report = self._project_reports.get(identity)
            if plan is None or not report or not report['published']:
                raise ProjectError('No published project output is available')
            if relative not in {m.file.path for m in plan.modules}:
                raise ProjectError('Output is not a Lua module in this plan')
            if is_link(plan.output) or plan.output.resolve()!=plan.output:
                raise ProjectError('Project output moved')
            path = safe_source(plan.output,relative)
            if digest_file(path)!=report['inventory'].get(relative):raise ProjectError('Output changed after the build')
            return {'ok':True,'path':relative,'content':path.read_text(encoding='utf8')}
        except (ValueError,OSError,TypeError) as error:
            return {'ok':False,'error':str(error)}

    def pick_project_folder(self, kind='root'):
        if kind not in ('root','output'):return {'ok':False,'error':'Unknown project folder field'}
        result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not result:return None
        return {'path':str(Path(result if isinstance(result,str) else result[0]).resolve())}

    def load_project(self):
        result = webview.windows[0].create_file_dialog(webview.OPEN_DIALOG,
            file_types=('Project JSON (*.json)','All files (*.*)'))
        if not result:return None
        try:
            path = Path(result if isinstance(result,str) else result[0]).resolve()
            document = json.loads(path.read_text(encoding='utf-8-sig'))
            if not isinstance(document,dict) or not isinstance(document.get('project'),dict):
                raise ProjectError('Not a Karity project configuration')
            return {'ok':True,'document':document,'base':str(path.parent),'path':str(path)}
        except (ValueError,OSError) as error:return {'ok':False,'error':str(error)}

    def save_project(self, payload):
        document = deepcopy(payload.get('document'))
        if not isinstance(document,dict) or not isinstance(document.get('project'),dict):
            return {'ok':False,'error':'Not a project configuration'}
        result = webview.windows[0].create_file_dialog(webview.SAVE_DIALOG,save_filename='project.karity.json',
            file_types=('Project JSON (*.json)',))
        if not result:return None
        try:
            path = Path(result if isinstance(result,str) else result[0]).resolve()
            base = Path(payload.get('base') or Path.cwd()).resolve()
            for key in ('root','output'):
                value = document['project'].get(key)
                if value and not Path(value).is_absolute():
                    actual = (base/value).resolve()
                    try:document['project'][key] = Path(os.path.relpath(actual,path.parent)).as_posix()
                    except ValueError:document['project'][key] = str(actual)
            path.write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
            return {'ok':True,'document':document,'base':str(path.parent),'path':str(path)}
        except (ValueError,OSError,TypeError) as error:return {'ok':False,'error':str(error)}
