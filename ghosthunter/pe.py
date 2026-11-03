"""Just enough PE parsing to rebuild, from the file on disk, the bytes a module's code should have in
memory: section layout, base relocations, the import address table, and the export names."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SCN_CNT_CODE = 0x00000020
SCN_MEM_EXECUTE = 0x20000000


class PEError(ValueError):
    pass


@dataclass
class Section:
    name: str
    rva: int
    vsize: int
    raw_ptr: int
    raw_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & (SCN_MEM_EXECUTE | SCN_CNT_CODE))


@dataclass
class PE:
    data: bytes
    is64: bool
    image_base: int
    size_of_image: int
    size_of_headers: int
    entry_rva: int
    sections: list[Section]
    dirs: list[tuple[int, int]]                          # (rva, size) per data directory
    relocs: list[tuple[int, int]] = field(default_factory=list)   # (rva, width)
    _exports: dict[int, str] | None = None

    # ── layout ──────────────────────────────────────────────────────────────
    def section_at(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.rva <= rva < s.rva + max(s.vsize, s.raw_size):
                return s
        return None

    def rva_to_off(self, rva: int) -> int | None:
        if rva < self.size_of_headers:
            return rva
        s = self.section_at(rva)
        if not s or rva - s.rva >= s.raw_size:
            return None
        return s.raw_ptr + rva - s.rva

    def mapped(self, rva: int, size: int) -> bytes:
        """Bytes of [rva, rva+size) as the loader lays them out (zeros past a section's raw data)."""
        out = bytearray(size)
        end = rva + size
        spans = [(0, self.size_of_headers, 0)] + [(s.rva, s.raw_size, s.raw_ptr) for s in self.sections]
        for start, length, ptr in spans:
            lo, hi = max(rva, start), min(end, start + length)
            if lo < hi:
                chunk = self.data[ptr + lo - start:ptr + hi - start]
                out[lo - rva:lo - rva + len(chunk)] = chunk
        return bytes(out)

    def section_image(self, s: Section, load_base: int) -> bytes:
        """A section's bytes as they should be in memory at load_base, relocations applied."""
        size = s.vsize or s.raw_size
        img = bytearray(size)
        raw = self.data[s.raw_ptr:s.raw_ptr + min(s.raw_size, size)]
        img[:len(raw)] = raw
        delta = load_base - self.image_base
        if delta:
            for rva, width in self.relocs:
                o = rva - s.rva
                if 0 <= o <= size - width:
                    fmt = "<Q" if width == 8 else "<I"
                    mask = (1 << (width * 8)) - 1
                    val = struct.unpack_from(fmt, img, o)[0]
                    struct.pack_into(fmt, img, o, (val + delta) & mask)
        return bytes(img)

    def iat_ranges(self) -> list[tuple[int, int]]:
        """RVA ranges the loader writes at load time: the IAT and the delay-load IAT pointers."""
        out = []
        if len(self.dirs) > 12 and self.dirs[12][1]:
            out.append((self.dirs[12][0], self.dirs[12][0] + self.dirs[12][1]))
        if len(self.dirs) > 13 and self.dirs[13][1]:
            # delay-load descriptors: 32 bytes each, the IAT RVA at +12
            rva, size = self.dirs[13]
            ptr = 8 if self.is64 else 4
            for k in range(0, size, 32):
                d = self.mapped(rva + k, 32)
                if len(d) < 32 or not any(d):
                    break
                iat, names = struct.unpack_from("<I", d, 12)[0], struct.unpack_from("<I", d, 16)[0]
                n = 0
                while n < 4096:
                    if not any(self.mapped(names + n * ptr, ptr)):
                        break
                    n += 1
                if iat:
                    out.append((iat, iat + (n + 1) * ptr))
        return out

    def exports(self) -> dict[int, str]:
        """{rva: name} of exported functions."""
        if self._exports is not None:
            return self._exports
        self._exports = {}
        if not self.dirs or not self.dirs[0][1]:
            return self._exports
        rva, size = self.dirs[0]
        hdr = self.mapped(rva, 40)
        n_funcs, n_names, a_funcs, a_names, a_ords = struct.unpack_from("<IIIII", hdr, 20)
        if n_names > 65536 or n_funcs > 65536:
            return self._exports
        funcs = self.mapped(a_funcs, 4 * n_funcs)
        names = self.mapped(a_names, 4 * n_names)
        ords = self.mapped(a_ords, 2 * n_names)
        for i in range(n_names):
            name_rva = struct.unpack_from("<I", names, 4 * i)[0]
            ordinal = struct.unpack_from("<H", ords, 2 * i)[0]
            if ordinal >= n_funcs:
                continue
            f = struct.unpack_from("<I", funcs, 4 * ordinal)[0]
            if rva <= f < rva + size:                    # forwarder, not code
                continue
            raw = self.mapped(name_rva, 128)
            self._exports.setdefault(f, raw.split(b"\0", 1)[0].decode("ascii", "replace"))
        return self._exports


def parse(data: bytes) -> PE:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("no MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PEError("no PE signature")
    n_sections, = struct.unpack_from("<H", data, e_lfanew + 6)
    opt_size, = struct.unpack_from("<H", data, e_lfanew + 20)
    opt = e_lfanew + 24
    magic, = struct.unpack_from("<H", data, opt)
    if magic == 0x20B:
        is64 = True
        image_base, = struct.unpack_from("<Q", data, opt + 24)
        n_dirs_off, dirs_off = opt + 108, opt + 112
    elif magic == 0x10B:
        is64 = False
        image_base, = struct.unpack_from("<I", data, opt + 28)
        n_dirs_off, dirs_off = opt + 92, opt + 96
    else:
        raise PEError(f"unknown optional header magic {magic:#x}")
    entry_rva, = struct.unpack_from("<I", data, opt + 16)
    size_of_image, size_of_headers = struct.unpack_from("<II", data, opt + 56)
    n_dirs = min(struct.unpack_from("<I", data, n_dirs_off)[0], 16)
    dirs = [struct.unpack_from("<II", data, dirs_off + 8 * i) for i in range(n_dirs)]
    sections = []
    sec = opt + opt_size
    for i in range(min(n_sections, 96)):
        o = sec + 40 * i
        if o + 40 > len(data):
            break
        name = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
        flags, = struct.unpack_from("<I", data, o + 36)
        sections.append(Section(name, rva, vsize, raw_ptr, raw_size, flags))
    pe = PE(data, is64, image_base, size_of_image, size_of_headers, entry_rva, sections, dirs)
    pe.relocs = _relocations(pe)
    return pe


def _relocations(pe: PE) -> list[tuple[int, int]]:
    if len(pe.dirs) <= 5 or not pe.dirs[5][1]:
        return []
    rva, size = pe.dirs[5]
    blob = pe.mapped(rva, size)
    out, pos = [], 0
    while pos + 8 <= len(blob):
        page, block = struct.unpack_from("<II", blob, pos)
        if block < 8:
            break
        for k in range(pos + 8, min(pos + block, len(blob)) - 1, 2):
            entry, = struct.unpack_from("<H", blob, k)
            kind, off = entry >> 12, entry & 0xFFF
            if kind == 10:
                out.append((page + off, 8))
            elif kind == 3:
                out.append((page + off, 4))
        pos += block
    return out


def looks_like_pe(buf: bytes) -> bool:
    """An MZ/PE header at the start of a buffer (a module mapped by hand, not by the loader)."""
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return False
    e = struct.unpack_from("<I", buf, 0x3C)[0]
    return e + 4 <= len(buf) and e < 0x1000 and buf[e:e + 4] == b"PE\0\0"


def headerless_pe(buf: bytes) -> bool:
    """A PE whose MZ was wiped to hide it but whose PE header and section table are still there."""
    if len(buf) < 0x400 or buf[:2] == b"MZ":
        return False
    e = struct.unpack_from("<I", buf, 0x3C)[0]
    if not (0x40 <= e < 0x400) or buf[e:e + 4] != b"PE\0\0":
        return False
    machine, = struct.unpack_from("<H", buf, e + 4)
    return machine in (0x14C, 0x8664, 0xAA64)
