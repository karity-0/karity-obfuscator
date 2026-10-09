"""Constant providers consume resolved target data, never scan executables."""
from dataclasses import dataclass, replace
import hashlib
from typing import Protocol

from .capabilities import Capability, CompatibilityPolicy, TargetRequirements
from .image_resolver import ImageReference, ResolvedTargetData
from .profile import TargetProfile


@dataclass(frozen=True)
class LiteralConstant:
    value: object


@dataclass(frozen=True)
class HostImageConstant:
    reference: ImageReference


class ConstantProvider(Protocol):
    def materialize(self, value) -> LiteralConstant | HostImageConstant: ...


class LiteralProvider:
    def materialize(self, value):
        return LiteralConstant(value)


class HostImageProvider:
    requirements = TargetRequirements({Capability.LOCAL_MEMORY_READ},
                                      CompatibilityPolicy.BINARY_SPECIFIC)

    def __init__(self, profile: TargetProfile, images: tuple[ResolvedTargetData, ...],
                 fallback: ConstantProvider | None = None):
        profile.require(self.requirements, "host image constant materialization")
        if not images:
            raise ValueError("host image materialization requires resolved images")
        names = [image.module.casefold() for image in images]
        if len(set(names)) != len(names):
            raise ValueError("ambiguous host image module names")
        if len({image.pointer_width for image in images}) != 1:
            raise ValueError("host modules must share one pointer width")
        self.images = tuple(images)
        self.fallback = fallback or LiteralProvider()

    def materialize(self, value):
        # The first slice uses exact byte strings. Numeric constants keep their
        # existing typed serialization, including signed zero and integer kind.
        data = value.encode('utf-8') if isinstance(value, str) else value
        if isinstance(data, bytes) and data:
            for image in self.images:
                reference = image.find(data)
                if reference is not None:
                    return HostImageConstant(reference)
        return self.fallback.materialize(value)


@dataclass(frozen=True)
class MaterializationPlan:
    functions: object
    references: tuple[ImageReference, ...]
    slots: tuple[tuple[int, str, int, int], ...]

    def dump(self):
        lines = ['materialization-plan v1']
        for ordinal, function_id, constant, reference_index in self.slots:
            reference = self.references[reference_index - 1]
            lines.append(f'host-image function={function_id} ordinal={ordinal} constant={constant} '
                         f'module={reference.module!r} rva={reference.offset} '
                         f'bytes={len(reference.data)} sha256={reference.image_hash}')
        return '\n'.join(lines) + '\n'

    def prepare_runtime(self, source):
        if not self.references:
            return source
        by_function = {}
        for ordinal, _, constant, reference_index in self.slots:
            by_function.setdefault(ordinal, []).append(f'[{constant + 1}]={reference_index}')
        slots = '{' + ','.join(f'[{key}]={{' + ','.join(values) + '}'
                               for key, values in sorted(by_function.items())) + '}'
        marker = 'local function read_proto(r, acc_state)'
        if source.count(marker) != 1:
            raise ValueError('host materialization requires one prototype reader')
        source = source.replace(marker, emit_host_reader(self.references) +
                                '\nlocal _host_slots=' + slots + '\nlocal _host_ordinal=0\n' + marker +
                                '\n_host_ordinal=_host_ordinal+1;local _host_function=_host_ordinal')
        marker = 'n=r.u32(); p.upvalues={}'
        if source.count(marker) != 1:
            raise ValueError('host materialization constant boundary is missing')
        return source.replace(marker,
                              'for slot,reference in pairs(_host_slots[_host_function] or {}) do '
                              'p.constants[slot]={CK_STR,_kss(_host_read(reference))} end\n' + marker)


def plan_materialization(functions, provider: ConstantProvider) -> MaterializationPlan:
    """Copy the serialized representation; retain original common/lowered IR."""
    references, slots = [], []
    ordinal = 0

    def visit(function):
        nonlocal ordinal
        ordinal += 1
        current = ordinal
        constants = []
        for index, value in enumerate(function.source.constants):
            materialized = provider.materialize(value)
            if isinstance(materialized, HostImageConstant):
                references.append(materialized.reference)
                slots.append((current, function.source.id, index, len(references)))
                constants.append(b'')
            elif isinstance(materialized, LiteralConstant):
                constants.append(materialized.value)
            else:
                raise TypeError('unsupported constant materialization')
        children = [visit(child) for child in function.children]
        source = replace(function.source, constants=constants,
                         protos=[child.source for child in children])
        return replace(function, source=source, children=children)

    copied = visit(functions)
    return MaterializationPlan(copied, tuple(references), tuple(slots))


def _lua_string(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return '"' + ''.join(f'\\{value:03d}' for value in data) + '"'


def emit_host_reader(references: tuple[ImageReference, ...]) -> str:
    """Emit CE-local reads with module identity, width and content checks.

    API contract: Cheat Engine's bin/celua.txt. MD5 is used by its native file
    and string APIs to reject accidental image/content mismatches; this is not
    a collision-resistant proof against a hostile host. SHA-256 remains in
    build metadata for artifact provenance.
    """
    entries = []
    modules = {}
    for reference in references:
        identity = (reference.image_hash, reference.image_md5, reference.pointer_width)
        previous = modules.setdefault(reference.module.casefold(), identity)
        if previous != identity:
            raise ValueError("conflicting host image identities")
        entries.append('{' + ','.join((
            _lua_string(reference.module.lower()), f'{reference.offset}.0',
            f'{len(reference.data)}.0', _lua_string(reference.image_md5),
            f'{reference.pointer_width}.0', _lua_string(hashlib.md5(reference.data).hexdigest()),
        )) + '}')
    return '''local _host_refs={''' + ','.join(entries) + '''}
local _host_bases={}
local function _host_read(index)
    local ref=_host_refs[index]
    local base=_host_bases[ref[1]]
    if not base then
        local found=nil
        for _,module in ipairs(enumModules(getCheatEngineProcessID())) do
            if string.lower(module.Name)==ref[1] then
                if found then error("ambiguous host module") end
                found=module
            end
        end
        if not found or (found.Is64Bit and 8 or 4)~=ref[5] then error("host module mismatch") end
        if string.lower(md5file(found.PathToFile))~=ref[4] then error("host image mismatch") end
        base=found.Address
        if type(base)~="number" or base<=0 then error("invalid host module base") end
        _host_bases[ref[1]]=base
    end
    local bytes=readBytesLocal(base+ref[2],ref[3],true)
    if type(bytes)~="table" or #bytes~=ref[3] then error("host constant read failed") end
    local result={}
    for i=1,#bytes do result[i]=string.char(bytes[i]) end
    local value=table.concat(result)
    if string.lower(stringToMD5String(value))~=ref[6] then error("host constant mismatch") end
    return value
end
'''
