"""Serial before/after benchmark, using two checkouts and the same interpreter.

Outputs stay in ignored temp-mosaic-benchmark; the JSON report is incremental.
Windows peak working set is read from the child process, not Python tracemalloc.
Run without other local builds for meaningful wall-clock comparisons.
"""
from pathlib import Path
import argparse
import ctypes
from ctypes import wintypes
import json
import os
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, log):
    started = time.perf_counter()
    peak = None
    handle = None
    if os.name == 'nt':
        class MemoryCounters(ctypes.Structure):
            _fields_ = [('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)] + [
                (name,ctypes.c_size_t) for name in ('PeakWorkingSetSize','WorkingSetSize',
                'QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage',
                'QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
        kernel = ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        psapi = ctypes.WinDLL('psapi',use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,ctypes.POINTER(MemoryCounters),wintypes.DWORD]
    with log.open('wb') as sink:
        process = subprocess.Popen(command,cwd=cwd,stdout=sink,stderr=subprocess.STDOUT,
            env={**os.environ,'PYTHONHASHSEED':'0'})
        if os.name == 'nt': handle = kernel.OpenProcess(0x410,False,process.pid)
        try:
            while True:
                if handle:
                    counters = MemoryCounters()
                    if psapi.GetProcessMemoryInfo(handle,ctypes.byref(counters),ctypes.sizeof(counters)):
                        peak = max(peak or 0,counters.PeakWorkingSetSize)
                code = process.poll()
                if code is not None: break
                time.sleep(0.05)
        finally:
            if handle: kernel.CloseHandle(handle)
    if code:
        raise RuntimeError(f'{command}: exit {code}; see {log}')
    return {'wall_seconds':time.perf_counter()-started,'peak_working_set_bytes':peak,
            'log':str(log.relative_to(ROOT))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seed',type=int,default=9300)
    parser.add_argument('--runtime-repeats',type=int,default=3)
    args = parser.parse_args()
    work = ROOT/'temp-mosaic-benchmark'
    work.mkdir(exist_ok=True)
    fixture = ROOT/'test/scripts/01_helloWorld.lua'
    report = {'fixture':'test/scripts/01_helloWorld.lua','input_bytes':fixture.stat().st_size,
        'seed':args.seed,'python':sys.version,'platform':platform.platform(),'pythonhashseed':'0',
        'memory':'child peak Windows working set, sampled every 50ms; excludes grandchildren',
        'timing':'serial processes; profiling on both revisions; runtime includes native Lua startup',
        'records':[]}
    def save():
        args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    for kind in ('source','mov','karity'):
        for profile in ('high','max'):
            for revision,checkout in (('before',args.before.resolve()),('after',ROOT)):
                name = f'{revision}-{kind}-{profile}'
                output,profile_report = work/(name+'.lua'),work/(name+'.json')
                print('benchmark-start',name,flush=True)
                if kind == 'source':
                    command = [sys.executable,'tools/profile_cff.py',str(fixture),'--profile',profile,
                        '--seed',str(args.seed),'--output',str(profile_report),'--source-output',str(output)]
                else:
                    command = [sys.executable,'main.py',str(fixture),'-o',str(output),'-c','config.example.json',
                        '--profile',profile,'--seed',str(args.seed),'--vm-option','backend='+kind,
                        '--profile-report',str(profile_report)]
                record = {'revision':revision,'kind':kind,'profile':profile,
                    **run(command,checkout,work/(name+'.log'))}
                raw = json.loads(profile_report.read_text(encoding='utf-8'))
                record['profiling'] = raw
                record['output_bytes'] = output.stat().st_size
                native = ROOT/'bin/lua.exe'
                if not native.is_file():
                    sys.path.insert(0,str(ROOT/'test'))
                    from lua_runtime import lua_executable
                    native = Path(lua_executable())
                timings = []
                expected = None
                for index in range(args.runtime_repeats):
                    started = time.perf_counter()
                    result = subprocess.run([str(native),str(output)],cwd=ROOT,capture_output=True,check=True)
                    timings.append(time.perf_counter()-started)
                    actual = result.stdout
                    if expected is None:
                        expected = subprocess.check_output([str(native),str(fixture)],cwd=ROOT)
                    assert actual==expected,(name,actual,expected)
                record['runtime_seconds'] = timings
                record['runtime_median_seconds'] = statistics.median(timings)
                report['records'].append(record)
                save()
                print('benchmark-ok',name,record['output_bytes'],round(record['wall_seconds'],3),
                    round(record['runtime_median_seconds'],3),record['peak_working_set_bytes'],flush=True)
    save()


if __name__ == '__main__': main()
