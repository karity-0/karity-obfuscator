from __future__ import annotations
import subprocess
import platform
import tempfile
import secrets
import string
import random
import zlib
import shutil
import os
from pathlib import Path

from ..passes.base import PostPass
from ..parser import Lua53Parser
from .serializer import (serialize, assign_vm_ids, collect_fuseable_pairs_for_vm)
from .kae_blob import encrypt_blob
from .vm_obfuscation import (prune_and_inject_handlers, apply_vop_to_vm,
                             apply_split_to_vm, apply_fuse_to_vm, ALL_SPLIT_OPS,
                             convert_dispatch_to_ruby, build_exec_variants,
                             collect_used_ops_for_vm, collect_used_orig_ops_for_vm)
from .junk_injection import inject_junk


if platform.system() == "Windows":
    _LUA    = Path(__file__).parent.parent.parent / "bin" / "lua.exe"
    _LUAC   = Path(__file__).parent.parent.parent / "bin" / "luac53.exe"
else:
    _LUA    = shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua5.3"
    _LUAC   = shutil.which("luac5.3") or shutil.which("luac53") or "luac5.3"

if not _LUA or (isinstance(_LUA, Path) and not _LUA.exists()):
    raise FileNotFoundError("lua5.3 not found.")

if not _LUAC or (isinstance(_LUAC, Path) and not _LUAC.exists()):
    raise FileNotFoundError("luac5.3 not found.")

_VM_LUA_PATH = Path(__file__).parent / "vm.lua"


def _compile(script: str) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False, mode="w", encoding="utf-8") as f:
        f.write(script)
        src_path = f.name

    out_path = src_path + ".luac"
    try:
        result = subprocess.run(
            [str(_LUAC), "-o", out_path, src_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"luac failed: {result.stderr.decode()}")

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(src_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


_B36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def _to_base36(data: bytes) -> str:
    """bytes → "KARITY/length:base36payload" (4바이트 청크, 각 6자리 고정)"""
    length = len(data)
    # length 인코딩
    ln, length_enc = length, ''
    while ln:
        length_enc = _B36[ln % 36] + length_enc
        ln //= 36

    # 4바이트씩 청크로 나눠 각각 6자리 base36으로 인코딩
    # 패딩: 4의 배수로 맞춤
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    parts = []
    for i in range(0, len(padded), 4):
        n = int.from_bytes(padded[i:i+4], 'little')
        chunk = ''
        for _ in range(7):
            chunk = _B36[n % 36] + chunk
            n //= 36
        parts.append(chunk)

    return '"KARITY/' + (length_enc or '0') + ':' + ''.join(parts) + '"'


_LUA_OP_COUNT = 47  # Lua 5.3 opcode 0~46
_VOP_SPACE    = 128  # 7비트 op × 256 variant = 32768, 실용 범위는 128*256


def _make_vop_map(used_vops: set[int] | None = None) -> dict[int, list[int]]:
    """원본op(0~46) → alias vop 목록 매핑.

    각 원본 op당 2~3개의 alias vop를 생성.
    serialize 시 alias 중 랜덤 선택해서 emit → 같은 op라도 매번 다른 vop.
    vop = op(7비트) | (variant(8비트) << 7)

    used_vops를 넘기면 그 집합에 누적 — 멀티VM에서 VM 간 vop 공간을 disjoint로
    유지하기 위해 공유 집합을 전달한다.
    """
    if used_vops is None:
        used_vops = set()
    vop_map: dict[int, list[int]] = {}

    for orig in range(_LUA_OP_COUNT):
        n_aliases = random.randint(2, 3)
        aliases = []
        for _ in range(n_aliases):
            while True:
                op_slot = random.randint(0, _VOP_SPACE - 1)
                variant = random.randint(0, 255)
                vop = op_slot | (variant << 7)
                if vop not in used_vops:
                    used_vops.add(vop)
                    aliases.append(vop)
                    break
        vop_map[orig] = aliases
    return vop_map


def _new_unique_vop(used: set[int]) -> int:
    while True:
        vop = random.randint(0, 0x7FFF)
        if vop not in used:
            used.add(vop)
            return vop


def _make_fuse_map(used_vops: set[int],
                   pairs: set[tuple[int, int]]) -> dict[tuple[int, int], int]:
    """fuse 가능한 각 (op1, op2) 쌍마다 고유 vop 1개 할당."""
    return {pair: _new_unique_vop(used_vops) for pair in sorted(pairs)}


def _make_split_map(used_vops: set[int],
                    split_ops: set[int]) -> dict[int, dict[str, tuple[int, ...]]]:
    """각 split 가능 op마다 2-part, 3-part 용 vop 튜플 할당.

    split_ops: split 핸들러를 만들 op 집합 (실제 바이트코드에 등장하는
    splittable op으로 한정 — 안 쓰는 op까지 CFF 핸들러를 만들면 체인 폭증).
    """
    split_map: dict[int, dict[str, tuple[int, ...]]] = {}
    for op in sorted(split_ops):
        split_map[op] = {
            "2": (_new_unique_vop(used_vops), _new_unique_vop(used_vops)),
            "3": (_new_unique_vop(used_vops), _new_unique_vop(used_vops),
                  _new_unique_vop(used_vops)),
        }
    return split_map


def _dump_function_stripped(vm_func_src: str, header: str = "") -> bytes:
    """
    vm_func_src(= "return function(...) ... end")를 최종 출력과 동일한
    enclosing 컨텍스트(`header` 주석 + `local a="..."` 프리픽스) 안에서
    load()로 로드해 얻은 내부 함수(_vmf에 해당)를 string.dump(f, true)로
    직렬화한 바이트를 반환한다.

    strip=true라도 함수의 linedefined/lastlinedefined 등은 enclosing
    chunk에서의 위치(앞에 몇 줄이 있는지)에 의존하므로, 최종 출력에서
    _vmf가 정의되는 컨텍스트(헤더 주석 포함)를 그대로 재현해야 빌드 타임
    dump와 런타임 dump가 바이트 단위로 일치한다.
    """
    wrapped = (
        f'{header}'
        f'local a="obfuscated using karity obfuscator"'
        f'{vm_func_src};'
    )

    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False, mode="w", encoding="utf-8") as f:
        f.write(wrapped)
        src_path = f.name

    dump_path   = src_path + ".dump"
    helper_path = src_path + ".helper.lua"

    src_path_lua  = src_path.replace("\\", "\\\\")
    dump_path_lua = dump_path.replace("\\", "\\\\")

    helper = (
        f'local fh=io.open("{src_path_lua}","rb")\n'
        f'local content=fh:read("a") fh:close()\n'
        f'local f=load(content)()\n'
        f'local out=io.open("{dump_path_lua}","wb")\n'
        f'out:write(string.dump(f,true)) out:close()\n'
    )
    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(helper)

    try:
        result = subprocess.run([str(_LUA), helper_path], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"lua dump failed: {result.stderr.decode()}")

        with open(dump_path, "rb") as f:
            return f.read()
    finally:
        for p in (src_path, dump_path, helper_path):
            if os.path.exists(p):
                os.unlink(p)


def _load_vm() -> str:
    src = _VM_LUA_PATH.read_text(encoding="utf-8")
    cutoff = src.find("\nif arg and arg[0]")
    if cutoff != -1:
        src = src[:cutoff]
    return src

_VM_RENAME_KEYS = [
    # proto 테이블 키
    "num_params", "is_vararg", "max_stack_size", "vm_id",
    "constants", "code", "upvalues", "protos",
    "instack", "idx",
    # reader 메서드명
    "u8", "u16", "u32", "u64", "i64", "f64", "str",
]

_NAME_CHARS = string.ascii_lowercase + string.digits

def _rand_name(length: int = 6) -> str:
    return '_' + ''.join(random.choices(_NAME_CHARS, k=length))

def _rename_vm_keys(src: str) -> str:
    """vm.lua 내의 테이블 키 및 reader 메서드명을 랜덤 이름으로 치환."""
    import re
    rename_map = {k: _rand_name() for k in _VM_RENAME_KEYS}
    for orig, new in rename_map.items():
        src = re.sub(rf'\b{re.escape(orig)}\b', new, src)
        src = src.replace(f'["{orig}"]', f'["{new}"]')
        src = src.replace(f"['{orig}']", f"['{new}']")
    return src


def _obfuscate_vm_output(script: str, pass_names: list[str]) -> str:
    """VM 출력물에 passes 재적용."""
    from ..pipeline import Pipeline
    from ..registry import PASS_REGISTRY

    pipeline = Pipeline()
    for name in pass_names:
        info = PASS_REGISTRY.get(name)
        if info is None:
            continue

        cls = info["cls"]

        if cls.__name__ == "VMPass":
            continue

        # function_obf는 디스패처(exec)와 그 내부 클로저를 변환에서 제외해야
        # 한다(거대 + 내부 클로저가 exec 로컬을 upvalue로 캡처해 깨지고, hot
        # path라 runtime도 망가짐). skip_vm_dispatcher로 exec/wrapper만 빼고
        # cold 헬퍼들(kae_decrypt/read_proto/run 등)에는 정상 적용한다.
        if cls.__name__ == "FunctionObfuscationPass":
            pipeline.add(cls(skip_vm_dispatcher=True))
        else:
            pipeline.add(cls())

    return pipeline.run(script)



_DEFAULT_VM_OPTIONS = {
    "vm": "karity",   # 디스패치 구조 선택: "karity"(if-elseif 루프) | "ruby"(테이블+꼬리호출)
    "vm_count": 1,    # 멀티VM: 함수(proto)를 N개 독립 VM에 분산(1=단일, >1=출력 ~N×)
    "fake_handlers": True,
    "mutate_handlers": True,
    "junk_instructions": True,
    "junk_rate": 0.15,
}


class VMPass(PostPass):
    def __init__(self, vm_output_passes: list[str] | None = None, vm_options: dict | None = None):
        self.vm_output_passes = vm_output_passes or []
        self.vm_options = {**_DEFAULT_VM_OPTIONS, **(vm_options or {})}

    def run(self, script: str) -> str:
        # 1. luac 컴파일
        luac_bytes = _compile(script)

        # 2. 파싱 → junk instruction 삽입
        proto = Lua53Parser(luac_bytes).parse()
        if self.vm_options.get("junk_instructions", True):
            proto = inject_junk(proto, rate=self.vm_options.get("junk_rate", 0.15))

        fake = self.vm_options["fake_handlers"]
        mut  = self.vm_options["mutate_handlers"]

        # 2b. 멀티VM: proto를 N개 VM에 분산 + VM마다 독립 맵 생성
        #     (vop 공간은 공유 used_vops로 VM 간 disjoint 유지)
        vm_count = max(1, int(self.vm_options.get("vm_count", 1)))
        vm_assign, n = assign_vm_ids(proto, vm_count)

        used_vops: set[int] = set()
        vm_maps: list = []
        used_ops_list: list[set[int]] = []
        for k in range(n):
            vop_map    = _make_vop_map(used_vops)
            split_ops  = ALL_SPLIT_OPS & collect_used_orig_ops_for_vm(proto, vm_assign, k)
            split_map  = _make_split_map(used_vops, split_ops)
            fuse_pairs = collect_fuseable_pairs_for_vm(proto, vm_assign, k)
            fuse_map   = _make_fuse_map(used_vops, fuse_pairs)
            vm_maps.append((vop_map, split_map, fuse_map))
            used_ops_list.append(collect_used_ops_for_vm(proto, vm_assign, k, vop_map))

        blob = serialize(proto, vm_assign, vm_maps)

        # 3. VM 코드 로드 + (단일/멀티) exec 생성
        vm_code = _rename_vm_keys(_load_vm())
        if n == 1:
            vop_map, split_map, fuse_map = vm_maps[0]
            vm_code = apply_vop_to_vm(vm_code, vop_map)
            vm_code = prune_and_inject_handlers(vm_code, used_ops_list[0],
                                                fake_handlers=fake, mutate=mut)
            vm_code = apply_split_to_vm(vm_code, split_map, mutate=mut)
            vm_code = apply_fuse_to_vm(vm_code, fuse_map, mutate=mut)
            # ruby 모드(단일 VM 한정): 디스패치를 테이블+꼬리호출로 변환
            if self.vm_options.get("vm") == "ruby":
                vm_code = convert_dispatch_to_ruby(vm_code)
        else:
            vm_code = build_exec_variants(vm_code, n, vm_maps, used_ops_list,
                                          fake_handlers=fake, mutate=mut)

        # 4. dump 대상 함수 소스 구성 + 재난독화 (이후 텍스트 변경 없음)
        vm_func_src = (
            f'return function(...)\n'
            f'local k1,k2,k3,k4,k5,k6,k7 = ... '
            f'{vm_code} return run end'
        )
        vm_func_src = _obfuscate_vm_output(vm_func_src, self.vm_output_passes)
    
        # 재난독화 결과 맨 앞의 헤더 주석을 분리 (dump/key 계산엔 영향 없음)
        from ..pipeline import Pipeline
        header = ""
        if vm_func_src.startswith(Pipeline.HEADER):
            header = Pipeline.HEADER
            vm_func_src = vm_func_src[len(header):]

        # 5. 확정된 vm_func_src를 load+dump(strip) → crc32 기반 key 재료
        dump_bytes = _dump_function_stripped(vm_func_src, header)
        dump_crc   = zlib.crc32(dump_bytes) & 0xFFFFFFFF

        alphabet  = string.ascii_letters + string.digits
        rand_tail = ''.join(secrets.choice(alphabet) for _ in range(16))
        _KEY = f"karityObfuscator/{format(dump_crc, '08x')}/{rand_tail}"

        # 6. blob 암호화: nonce(8B) + ciphertext
        nonce, ct = encrypt_blob(blob, _KEY)
        encrypted_blob = nonce + ct
        lua_blob = _to_base36(encrypted_blob)

        # 7. 최종 출력 조합 — vm_func_src(_vmf 본문)는 더 이상 재가공하지 않음
        # vm_func_src: "return function(...) ... end" → _vmf 본문으로 그대로 사용
        vmf_body = vm_func_src[len("return "):]

        raw = (
            f'{header}'
            f'local a="obfuscated using karity obfuscator"'
            f'local _vmf={vmf_body};'
            f'return (_vmf(1032,413,258,104,953,283,120))'
            f'({lua_blob},"{rand_tail}",_vmf)\n'
        )

        return raw