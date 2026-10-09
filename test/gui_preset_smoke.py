"""Build and execute the four shipped presets."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator_gui import Api, _resolved_profiles
from obfuscator.toolchain import LuaToolchain
from obfuscator.passes.packer import PackerPass


def main():
    # Optional snapshots make a slow full VM build reusable when diagnosing
    # the separate packer stage; normal smoke runs leave no artifacts.
    artifact_dir = os.environ.get('KARITY_PRESET_ARTIFACTS')
    if artifact_dir:
        artifact_dir = Path(artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        original_pack = PackerPass.run
        def snapshot_pack(packer, source):
            (artifact_dir / 'before-pack.lua').write_text(source, encoding='utf-8')
            print(f'packing {len(source)} chars', flush=True)
            return original_pack(packer, source)
        PackerPass.run = snapshot_pack
    profiles = _resolved_profiles(json.loads((ROOT / 'config.example.json').read_text(encoding='utf-8')))
    script = '''local offset=2
    local function compute(value)
      local data={answer=value+offset,enabled=true}
      if data.enabled and value>0 then return data.answer,"ok" end
      return 0,"bad"
    end
    print(compute(10))'''
    with tempfile.TemporaryDirectory(prefix='karity-presets-') as folder:
        for name, config in profiles.items():
            if len(sys.argv) > 1 and name not in sys.argv[1:]:
                continue
            start = time.monotonic()
            print('building ' + name, flush=True)
            result = Api().run_obfuscation({'script': script, 'config': config, 'release_check': name == 'max'})
            assert result['ok'], result.get('error')
            assert not result['warnings'], result['warnings']
            path = Path(folder, name + '.lua')
            path.write_text(result['output'], encoding='utf-8')
            if artifact_dir:
                (artifact_dir / (name + '.lua')).write_text(result['output'], encoding='utf-8')
            # Three fully transformed VMs can produce tens of megabytes; allow
            # the max loader to finish while retaining a bounded execution.
            executed = subprocess.run([LuaToolchain.from_config(config).lua(), str(path)], capture_output=True, timeout=1800 if name == 'max' else 30)
            assert executed.returncode == 0, executed.stderr
            assert executed.stdout.replace(b'\r\n', b'\n') == b'12\tok\n', executed.stdout
            print(f"preset-ok {name} {len(result['output'])} chars {time.monotonic() - start:.2f}s", flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
