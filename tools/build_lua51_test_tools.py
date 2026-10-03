"""Build optional Lua 5.1 integration-test tools from the pinned official source."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

URL = 'https://www.lua.org/ftp/lua-5.1.5.tar.gz'
SHA256 = '2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--archive', type=Path, help='use an already downloaded official archive')
    parser.add_argument('--cc', default=shutil.which('gcc'))
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('this tool builds Windows binaries with MinGW GCC')
    if not args.cc:
        parser.error('GCC is required; pass --cc')
    output = (args.output or Path(tempfile.mkdtemp(prefix='karity-lua51-tools-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = args.archive.read_bytes() if args.archive else urllib.request.urlopen(URL, timeout=60).read()
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise ValueError('Lua archive SHA-256 mismatch')
    with tempfile.TemporaryDirectory(prefix='karity-lua51-source-') as folder:
        root = Path(folder).resolve()
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
            for member in source.getmembers():
                path = (root / member.name).resolve()
                if not path.is_relative_to(root) or not (member.isdir() or member.isfile()):
                    raise ValueError('unsafe source archive entry')
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(source.extractfile(member).read())
        src = root / 'lua-5.1.5' / 'src'
        core = [str(path) for path in sorted(src.glob('*.c')) if path.name not in {'lua.c', 'luac.c', 'print.c'}]
        common = [args.cc, '-O2', '-static-libgcc']
        commands = [
            [*common, '-shared', '-DLUA_BUILD_AS_DLL', '-o', str(output / 'lua51.dll'),
             *core, '-Wl,--out-implib,' + str(output / 'liblua51.a')],
            [*common, '-DLUA_BUILD_AS_DLL', '-o', str(output / 'lua51.exe'), str(src / 'lua.c'), str(output / 'liblua51.a')],
            [*common, '-o', str(output / 'luac51.exe'), *core, str(src / 'luac.c'), str(src / 'print.c')],
        ]
        for command in commands:
            subprocess.run(command, check=True, capture_output=True, timeout=120)
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
