"""Local browser-test bridge to the real API, using temporary GUI preferences."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import obfuscator_gui as gui


def main():
    with tempfile.TemporaryDirectory(prefix='karity-gui-web-') as folder:
        gui.CONFIG_PATH = Path(folder)/'config.json'
        gui.PREFERENCES_PATH = Path(folder)/'preferences.json'
        gui.PROJECT_CONFIG_PATH = Path(folder)/'missing.json'
        api = gui.Api()
        methods = {name: getattr(api,name) for name in (
            'get_bootstrap','get_version','save_preferences','save_config',
            'start_build','poll_build','get_build_result','validate_marker_options','validate_kes',
            'start_execution','poll_execution','send_execution_input','stop_execution',
        )}
        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(gui.WEB_DIR), **kwargs)
            def log_message(self, *args): pass
            def do_GET(self):
                if '--bridge' in sys.argv and self.path.split('?')[0] in ('/', '/index.html'):
                    # Optional real-API bridge for interactive browser QA. The
                    # server still uses disposable preferences and an allowlist.
                    bridge='<script>window.pywebview={api:new Proxy({}, {get:(_,method)=>(...args)=>fetch("/api",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({method,args})}).then(r=>r.json())})};</script>'
                    page=(gui.WEB_DIR/'index.html').read_text(encoding='utf-8').replace('<head>','<head>'+bridge).encode('utf-8')
                    self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
                    self.send_header('Content-Length',str(len(page)));self.end_headers();self.wfile.write(page)
                    return
                super().do_GET()
            def do_POST(self):
                try:
                    value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if value['method']=='close':
                        threading.Thread(target=server.shutdown, daemon=True).start()
                        result={'ok':True}
                    else:
                        result=methods[value['method']](*value.get('args',[]))
                    data=json.dumps(result,ensure_ascii=False).encode('utf-8')
                    self.send_response(200); self.send_header('Content-Type','application/json; charset=utf-8')
                    self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
                except Exception as exc:
                    self.send_error(500,str(exc))
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        print(f'http://127.0.0.1:{server.server_port}',flush=True)
        try: server.serve_forever()
        finally:
            server.server_close(); api._builds.close(); api._execution.close()

if __name__=='__main__': main()
