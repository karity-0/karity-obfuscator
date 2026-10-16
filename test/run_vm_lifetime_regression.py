"""Native/VM lifetime and effect boundaries on both targets and all backends."""
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.explore_vm_semantics import execute, main as explore


def main():
    with tempfile.TemporaryDirectory(prefix='vm-lifetime-') as folder:
        result = explore(['--output', folder, '--seeds', '124', '--generated', '0'])
        assert result == 0, 'native/VM observable lifetime or effect difference'
        result=explore(['--output', str(Path(folder)/'chunk'), '--seeds','124','--generated','0',
                        '--inputs', str(ROOT/'test/fixtures/vm_chunk_interface.lua'),
                        '--harness', str(ROOT/'test/fixtures/vm_chunk_interface_harness.lua')])
        assert result==0, 'native/VM chunk argument, return, or module callback difference'
        result=explore(['--output',str(Path(folder)/'packed-chunk'),'--seeds','124','--generated','0',
                        '--versions','5.3','--pack',
                        '--inputs',str(ROOT/'test/fixtures/vm_chunk_interface.lua'),
                        '--harness',str(ROOT/'test/fixtures/vm_chunk_interface_harness.lua')])
        assert result==0, 'packed VM chunk interface difference'
        for pack_args in ([],['--versions','5.3','--pack']):
            result=explore(['--output',str(Path(folder)/('embedded-packed' if pack_args else 'embedded')),
                            '--seeds','124','--generated','0','--modes','minimal',
                            '--inputs',str(ROOT/'test/fixtures/vm_embedded_interface.lua'),
                            '--harness',str(ROOT/'test/fixtures/vm_embedded_interface_harness.lua'),*pack_args])
            assert result==0, 'non-vararg embedding compatibility difference'
        from obfuscator.passes.packer import PackerPass
        source=ROOT/'test/fixtures/vm_chunk_interface.lua'
        harness=ROOT/'test/fixtures/vm_chunk_interface_harness.lua'
        expected=execute(source,'5.3',harness=harness)
        for index,passes in enumerate(([],['number_obf','meme_strings','minify'])):
            output=PackerPass(packer_output_passes=passes).run(source.read_text(encoding='utf-8'))
            artifact=Path(folder)/f'packed-source-{index}.lua'
            artifact.write_text(output,encoding='utf-8')
            actual=execute(artifact,'5.3',harness=harness)
            assert actual['returncode']==0 and actual['stdout']==expected['stdout'],actual
            print('source-packer-chunk-ok',passes,flush=True)
    print('vm-lifetime-regression-ok 34 scenarios + chunk/packed interfaces, 2 targets, 3 backends, 2 modes')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
