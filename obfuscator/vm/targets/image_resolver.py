"""Read-only PE image analysis for build-time host constant resolution.

File offsets never escape this module as runtime addresses. Layout reference:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


@dataclass(frozen=True)
class ImageReference:
    module: str
    offset: int  # RVA, relative to the loaded module base.
    data: bytes
    image_hash: str
    pointer_width: int
    image_md5: str


@dataclass(frozen=True)
class ImageSection:
    name: str
    rva: int
    data: bytes
    characteristics: int

    @property
    def constant_source(self):
        # Require readable initialized data that cannot be written, executed or
        # discarded by the loader. Relocations are excluded separately.
        return (self.characteristics & 0x40000040 == 0x40000040
                and not self.characteristics & 0xA2000000)


@dataclass(frozen=True)
class ResolvedTargetData:
    module: str
    image_hash: str
    pointer_width: int
    machine: int
    timestamp: int
    image_size: int
    image_version: tuple[int, int]
    sections: tuple[ImageSection, ...]
    relocations: tuple[tuple[int, int], ...]
    loader_writes: tuple[tuple[int, int], ...]
    image_md5: str

    def find(self, data: bytes) -> ImageReference | None:
        if not isinstance(data, bytes) or not data:
            raise ValueError("host image constants must be nonempty bytes")
        for section in self.sections:
            if not section.constant_source:
                continue
            start = 0
            while (position := section.data.find(data, start)) >= 0:
                rva = section.rva + position
                if not any(rva < end and begin < rva + len(data)
                           for begin, end in self.relocations + self.loader_writes):
                    return ImageReference(self.module, rva, data, self.image_hash,
                                          self.pointer_width, self.image_md5)
                start = position + 1
        return None


class CEBinaryResolver:
    """Resolve executable or DLL metadata without loading the selected binary."""

    def resolve(self, path: str | Path) -> ResolvedTargetData:
        path = Path(path)
        return self.parse(path.read_bytes(), path.name)

    def parse(self, data: bytes, module: str) -> ResolvedTargetData:
        if not module or any(c in module for c in '/\\\0'):
            raise ValueError("module must be a file name")

        def read(fmt, offset):
            size = struct.calcsize(fmt)
            if offset < 0 or offset + size > len(data):
                raise ValueError("truncated PE image")
            return struct.unpack_from(fmt, data, offset)

        if data[:2] != b'MZ':
            raise ValueError("host image is not PE")
        pe, = read('<I', 0x3c)
        if data[pe:pe + 4] != b'PE\0\0':
            raise ValueError("invalid PE signature")
        machine, count, timestamp, _, _, optional_size, _ = read('<HHIIIHH', pe + 4)
        optional = pe + 24
        magic, = read('<H', optional)
        widths = {(0x14c, 0x10b): 4, (0x8664, 0x20b): 8}
        width = widths.get((machine, magic))
        if width is None:
            raise ValueError("host image must be x86 PE32 or x64 PE32+")
        directory_offset = 96 if width == 4 else 112
        if optional_size < directory_offset or not 0 < count <= 96:
            raise ValueError("invalid PE header size or section count")
        read(f'<{optional_size}s', optional)
        image_size, headers_size = read('<II', optional + 56)
        version = read('<HH', optional + 44)
        if not 0 < headers_size <= len(data) or image_size < headers_size:
            raise ValueError("invalid PE image size")
        sections = []
        ranges = []
        for index in range(count):
            offset = optional + optional_size + index * 40
            name, virtual_size, rva, raw_size, raw_offset, _, _, _, _, flags = read('<8sIIIIIIHHI', offset)
            extent = max(virtual_size, raw_size)
            if rva < headers_size or rva + extent > image_size:
                raise ValueError("section outside mapped image")
            if any(rva < end and begin < rva + extent for begin, end in ranges):
                raise ValueError("overlapping PE sections")
            ranges.append((rva, rva + extent))
            raw, = read(f'<{raw_size}s', raw_offset)
            # Raw alignment padding beyond VirtualSize is not constant storage.
            mapped = raw[:virtual_size] if virtual_size else raw
            sections.append(ImageSection(name.rstrip(b'\0').decode('ascii', 'replace'), rva, mapped, flags))

        def read_rva(rva, size):
            for section in sections:
                offset = rva - section.rva
                if 0 <= offset and offset + size <= len(section.data):
                    return section.data[offset:offset + size]
            raise ValueError("PE directory outside initialized section data")

        directory_count, = read('<I', optional + directory_offset - 4)
        if directory_count * 8 > optional_size - directory_offset:
            raise ValueError("truncated PE directories")
        loader_writes = []
        for directory in (12, 13):  # IAT and delay-load imports.
            if directory_count <= directory:
                continue
            rva, size = read('<II', optional + directory_offset + directory * 8)
            if size:
                read_rva(rva, size)
                # Delay-load thunks can live outside the descriptor range;
                # conservatively reject the containing data section.
                for section in sections:
                    if section.rva <= rva < section.rva + len(section.data):
                        loader_writes.append((section.rva, section.rva + len(section.data)))
        relocations = []
        if directory_count > 5:
            rva, size = read('<II', optional + directory_offset + 5 * 8)
            relocation_data = read_rva(rva, size) if size else b''
            position = 0
            while position < len(relocation_data):
                if position + 8 > len(relocation_data):
                    raise ValueError("truncated relocation block")
                page, block_size = struct.unpack_from('<II', relocation_data, position)
                if block_size < 8 or block_size % 2 or position + block_size > len(relocation_data):
                    raise ValueError("invalid relocation block size")
                for item in range(position + 8, position + block_size, 2):
                    entry, = struct.unpack_from('<H', relocation_data, item)
                    kind, offset = entry >> 12, entry & 0xfff
                    if kind == 0:
                        continue
                    if kind != (3 if width == 4 else 10):
                        raise ValueError("unsupported host image relocation")
                    begin = page + offset
                    if begin + width > image_size:
                        raise ValueError("relocation outside mapped image")
                    relocations.append((begin, begin + width))
                position += block_size
        return ResolvedTargetData(module, hashlib.sha256(data).hexdigest(), width,
                                  machine, timestamp, image_size, version,
                                  tuple(sections), tuple(sorted(relocations)),
                                  tuple(sorted(set(loader_writes))),
                                  hashlib.md5(data).hexdigest())
