"""One desktop build at a time; small cursor-based events, output on demand."""
from copy import deepcopy
import threading
import time
import uuid

from .profiling import observe_build


class GuiBuild:
    def __init__(self, build):
        self._build = build
        self._lock = threading.RLock()
        self._run = None
        self._closed = False

    def start(self, payload):
        with self._lock:
            if self._closed:
                return {'ok': False, 'error': 'Builder closed'}
            if self._run and not self._run['done']:
                return {'ok': False, 'error': 'A build is already running'}
            snapshot = deepcopy(payload)
            run = {'id': uuid.uuid4().hex, 'started': time.perf_counter(),
                   'done': False, 'events': [], 'result': None, 'failed_phase': None}
            self._run = run
            threading.Thread(target=self._work, args=(run, snapshot), daemon=True).start()
            return {'ok': True, 'id': run['id']}

    def _work(self, run, payload):
        def event(value):
            with self._lock:
                if self._closed:
                    return
                if value['status'] == 'error' and run['failed_phase'] is None:
                    run['failed_phase'] = value['phase']
                run['events'].append({**value, 'cursor': len(run['events']) + 1,
                                      'build_elapsed': time.perf_counter() - run['started']})
        try:
            with observe_build(event):
                result = self._build(payload)
        except Exception as exc:
            result = {'ok': False, 'error': str(exc)}
        with self._lock:
            run['result'] = {**result, 'failed_phase': run['failed_phase'],
                             'build_elapsed': time.perf_counter() - run['started']}
            run['done'] = True

    def poll(self, identity, cursor=0):
        with self._lock:
            run = self._run
            if not run or run['id'] != identity or self._closed:
                return {'ok': False, 'error': 'Build no longer available'}
            cursor = max(0, int(cursor))
            return {'ok': True, 'done': run['done'], 'cursor': len(run['events']),
                    'elapsed': (run['result']['build_elapsed'] if run['done'] else
                                time.perf_counter() - run['started']),
                    'events': deepcopy(run['events'][cursor:])}

    def result(self, identity):
        with self._lock:
            if not self._run or self._run['id'] != identity or self._closed:
                return {'ok': False, 'error': 'Build no longer available'}
            if not self._run['done']:
                return {'ok': False, 'error': 'Build is still running'}
            return deepcopy(self._run['result'])

    def close(self):
        with self._lock:
            self._closed = True
