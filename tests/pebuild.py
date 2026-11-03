"""Build small, valid PE images for tests: a code section, base relocations and named exports."""

from __future__ import annotations

import struct

FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def make_pe(code: bytes, *, image_base: int = 0x180000000, relocs: list[int] = (), exports: dict[str, int] | None = None,
            dll_name: str = "test.dll") -> bytes:
    """A 64-bit PE: .text at RVA 0x1000 holding `code`, an export table and DIR64 relocations at the given RVAs."""
    exports = exports or {}
    text_rva = 0x1000
    rdata_rva = text_rva + _align(max(len(code), 1), SECT_ALIGN)
    # export directory
    names = sorted(exports)
    edir = bytearray(40)
    tables = bytearray()
    funcs_off = 40
    tables += b"".join(struct.pack("<I", exports[n]) for n in names)
    names_off = funcs_off + 4 * len(names)
    tables += b"\0" * (4 * len(names))
    ords_off = names_off + 4 * len(names)
    tables += b"".join(struct.pack("<H", i) for i in range(len(names)))
    strings = bytearray()
    str_base = 40 + len(tables)
    name_rvas = []
    dll_rva = rdata_rva + str_base + len(strings)
    strings += dll_name.encode() + b"\0"
    for n in names:
        name_rvas.append(rdata_rva + str_base + len(strings))
        strings += n.encode() + b"\0"
    for i, r in enumerate(name_rvas):
        struct.pack_into("<I", tables, names_off - 40 + 4 * i, r)
    struct.pack_into("<IIIIIII", edir, 12, dll_rva, 1, len(names), len(names),
                     rdata_rva + funcs_off, rdata_rva + names_off, rdata_rva + ords_off)
    rdata = bytes(edir + tables + strings)
    reloc_rva = rdata_rva + _align(len(rdata), SECT_ALIGN)
    blocks = bytearray()
    pages: dict[int, list[int]] = {}
    for r in relocs:
        pages.setdefault(r & ~0xFFF, []).append(r & 0xFFF)
    for page, offs in sorted(pages.items()):
        entries = [(10 << 12) | o for o in offs]
        if len(entries) % 2:
            entries.append(0)
        blocks += struct.pack("<II", page, 8 + 2 * len(entries)) + b"".join(struct.pack("<H", e) for e in entries)
    reloc = bytes(blocks) or b"\0" * 8
    sections = [(".text", text_rva, code, 0x60000020), (".rdata", rdata_rva, rdata, 0x40000040),
                (".reloc", reloc_rva, reloc, 0x42000040)]
    headers_size = FILE_ALIGN
    e_lfanew = 0x80
    opt_size = 240
    hdr = bytearray(headers_size)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, e_lfanew + 4, 0x8664, len(sections), 0, 0, 0, opt_size, 0x2022)
    opt = e_lfanew + 24
    size_of_image = reloc_rva + _align(len(reloc), SECT_ALIGN)
    struct.pack_into("<HBBIIIII", hdr, opt, 0x20B, 14, 0, _align(len(code), FILE_ALIGN), 0, 0, text_rva, text_rva)
    struct.pack_into("<Q", hdr, opt + 24, image_base)
    struct.pack_into("<II", hdr, opt + 32, SECT_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHH", hdr, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<II", hdr, opt + 56, size_of_image, headers_size)
    struct.pack_into("<HH", hdr, opt + 68, 3, 0x0160)                 # console, dynamic base + NX + high-entropy VA
    struct.pack_into("<QQQQ", hdr, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112, rdata_rva, len(rdata))      # export directory
    struct.pack_into("<II", hdr, opt + 112 + 5 * 8, reloc_rva, len(reloc))
    body = bytearray()
    sec = opt + opt_size
    raw = headers_size
    for i, (name, rva, data, flags) in enumerate(sections):
        raw_size = _align(len(data), FILE_ALIGN)
        struct.pack_into("<8sIIIIIIHHI", hdr, sec + 40 * i, name.encode(), len(data), rva, raw_size, raw, 0, 0, 0, 0, flags)
        body += data + b"\0" * (raw_size - len(data))
        raw += raw_size
    return bytes(hdr) + bytes(body)
