"""Streaming Lua processes for the desktop GUI, isolated from its UI thread."""
from __future__ import annotations

import codecs
from collections import deque
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from .toolchain import LuaToolchain


class LuaExecution:
    OUTPUT_LIMIT = 300_000

    def __init__(self):
        self._lock = threading.RLock()
        self._run = None
        self._closed = False

    def start(self, script: str, config: dict, source_path: str = "") -> dict:
        if not script.strip():
            return {"ok": False, "error": "No code to run"}
        with self._lock:
            if self._closed:
                return {"ok": False, "error": "Runner closed"}
            if self._run and not self._run["done"]:
                return {"ok": False, "error": "Code is already running"}
            folder = tempfile.TemporaryDirectory(prefix="karity-run-")
            try:
                source = Path(folder.name) / "source.lua"
                source.write_text(script, encoding="utf-8")
                wrapper = Path(folder.name) / "run.lua"
                # A wrapper keeps print/io.write live even when stdout is a pipe.
                literal = json_lua_path(source)
                wrapper.write_text(
                    'io.stdout:setvbuf("no"); io.stderr:setvbuf("no"); '
                    f'arg={{[0]={literal}}}; dofile({literal})', encoding="utf-8")
                toolchain = LuaToolchain.from_config(config)
                worker = Path(__file__).with_name("gui_execution_worker.py")
                python = Path(sys.executable)
                if python.name.lower() == "pythonw.exe":
                    python = python.with_name("python.exe")
                if toolchain.lua_library:
                    command = [str(python), str(worker), "library", str(wrapper),
                               toolchain.lua_version, toolchain.library()]
                else:
                    try:
                        command = [toolchain.lua(), str(wrapper)]
                    except FileNotFoundError:
                        if toolchain.lua_executable or toolchain.lua_version != "5.1":
                            raise
                        command = [str(python), str(worker), "lupa", str(wrapper), "5.1"]
                cwd = Path(source_path).resolve().parent if source_path else Path(__file__).resolve().parents[1]
                process = subprocess.Popen(
                    command, cwd=str(cwd), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            except Exception as exc:
                folder.cleanup()
                return {"ok": False, "error": str(exc)}
            run = {"id": uuid.uuid4().hex, "process": process, "folder": folder,
                   "events": deque(), "size": 0, "cursor": 0, "done": False,
                   "stopped": False, "exit_code": None, "started": time.monotonic()}
            run["input"] = queue.Queue(maxsize=16)
            self._run = run
            run["watcher"] = threading.Thread(target=self._watch, args=(run,), daemon=True)
            run["watcher"].start()
            return {"ok": True, "id": run["id"], "lua_version": toolchain.lua_version}

    def _append(self, run, stream, text):
        with self._lock:
            run["cursor"] += 1
            run["events"].append({"cursor": run["cursor"], "stream": stream, "text": text})
            run["size"] += len(text)
            while run["size"] > self.OUTPUT_LIMIT:
                run["size"] -= len(run["events"].popleft()["text"])

    def _read(self, run, stream, pipe):
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while data := pipe.read(8192):
                text = decoder.decode(data)
                if text:
                    self._append(run, stream, text)
            tail = decoder.decode(b"", final=True)
            if tail:
                self._append(run, stream, tail)
        finally:
            pipe.close()

    def _watch(self, run):
        process = run["process"]
        readers = [threading.Thread(target=self._read, args=(run, name, pipe), daemon=True)
                   for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr))]
        for reader in readers:
            reader.start()
        threading.Thread(target=self._write, args=(run,), daemon=True).start()
        code = process.wait()
        for reader in readers:
            reader.join(timeout=1)
        # Unblock a pending writer on process exit, including an idle input queue.
        try:
            run["input"].put_nowait(None)
        except queue.Full:
            pass
        run["folder"].cleanup()
        with self._lock:
            run.update(done=True, exit_code=code, elapsed=round(time.monotonic() - run["started"], 3))

    def _write(self, run):
        pipe = run["process"].stdin
        try:
            while run["process"].poll() is None:
                value = run["input"].get()
                if value is None:
                    break
                data = memoryview((value + "\n").encode("utf-8"))
                while data:
                    data = data[pipe.write(data):]
        except (OSError, ValueError):
            pass
        finally:
            pipe.close()

    def poll(self, run_id: str, cursor: int = 0) -> dict:
        with self._lock:
            run = self._run
            if not run or run["id"] != run_id:
                return {"ok": False, "error": "Execution no longer available"}
            events = [event for event in run["events"] if event["cursor"] > cursor]
            return {"ok": True, "events": events, "cursor": run["cursor"],
                    "truncated": bool(events and events[0]["cursor"] > cursor + 1),
                    **{key: run.get(key) for key in ("done", "stopped", "exit_code", "elapsed")}}

    def send_input(self, run_id: str, value: str) -> dict:
        with self._lock:
            run = self._run
            if not run or run["id"] != run_id or run["done"] or run["process"].poll() is not None:
                return {"ok": False, "error": "Code is not running"}
            if len(value) > 4096:
                return {"ok": False, "error": "Input is too long (4096 characters maximum)"}
            try:
                run["input"].put_nowait(value)
                return {"ok": True}
            except queue.Full:
                return {"ok": False, "error": "Input queue full"}

    def stop(self, run_id: str) -> dict:
        with self._lock:
            run = self._run
            if not run or run["id"] != run_id:
                return {"ok": False, "error": "Execution no longer available"}
            if run["process"].poll() is None:
                run["stopped"] = True
                run["process"].kill()
            return {"ok": True}

    def close(self):
        with self._lock:
            self._closed = True
            if self._run:
                self.stop(self._run["id"])
            watcher = self._run["watcher"] if self._run else None
        if watcher and watcher is not threading.current_thread():
            watcher.join(timeout=3)


def json_lua_path(path: Path) -> str:
    # Decimal escapes also handle non-ASCII user/temp directory names on Windows.
    return '"' + ''.join(chr(byte) if 32 <= byte < 127 and byte not in (34, 92)
                         else f"\\{byte:03d}" for byte in str(path).encode("utf-8")) + '"'
