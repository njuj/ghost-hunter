"""What a process looks like from the outside: its memory regions, the modules mapped into it and its
threads. The analysis works on this snapshot only, so it can be tested on any OS with made-up data."""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from functools import cached_property
from typing import Callable

MEM_COMMIT = 0x1000
MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE = 0x1000000, 0x40000, 0x20000

PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY = 0x01, 0x02, 0x04, 0x08
PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x10, 0x20, 0x40, 0x80
PAGE_GUARD = 0x100
EXECUTABLE = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
WRITABLE_EXEC = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

PROT_NAMES = {PAGE_NOACCESS: "---", PAGE_READONLY: "R", PAGE_READWRITE: "RW", PAGE_WRITECOPY: "RWC",
              PAGE_EXECUTE: "X", PAGE_EXECUTE_READ: "RX", PAGE_EXECUTE_READWRITE: "RWX", PAGE_EXECUTE_WRITECOPY: "RWXC"}
TYPE_NAMES = {MEM_IMAGE: "image", MEM_MAPPED: "mapped", MEM_PRIVATE: "private"}


def prot_name(p: int) -> str:
    return PROT_NAMES.get(p & 0xFF, f"{p:#x}")


@dataclass
class Region:
    base: int
    size: int
    alloc_base: int
    alloc_protect: int
    protect: int
    type: int
    mapped_path: str | None = None        # the file behind an image or mapped view, as a DOS path
    file_exists: bool = True

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def executable(self) -> bool:
        return bool(self.protect & EXECUTABLE) and not self.protect & PAGE_GUARD

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end


@dataclass
class Module:
    path: str
    base: int
    size: int

    @property
    def name(self) -> str:
        return self.path.replace("/", "\\").rsplit("\\", 1)[-1]

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.size


@dataclass
class Thread:
    tid: int
    start: int


@dataclass
class Process:
    pid: int
    name: str
    path: str | None
    regions: list[Region]
    threads: list[Thread] = field(default_factory=list)
    image_base: int | None = None                   # from the PEB: where the process thinks its exe is
    wow64: bool = False
    read: Callable[[int, int], bytes] = lambda addr, size: b""
    private_code_pages: Callable[[int, int], list[int]] = lambda base, size: []   # non-shared resident pages

    @cached_property
    def modules(self) -> list[Module]:
        """Image mappings grouped by allocation base."""
        mods: dict[int, Module] = {}
        for r in self.regions:
            if r.type != MEM_IMAGE:
                continue
            m = mods.get(r.alloc_base)
            if m is None:
                mods[r.alloc_base] = Module(r.mapped_path or "?", r.alloc_base, r.end - r.alloc_base)
            else:
                m.size = max(m.size, r.end - m.base)
        return sorted(mods.values(), key=lambda m: m.base)

    def module_at(self, addr: int) -> Module | None:
        for m in self.modules:
            if m.contains(addr):
                return m
        return None

    @cached_property
    def _starts(self) -> list[int]:
        self.regions.sort(key=lambda r: r.base)
        return [r.base for r in self.regions]

    def region_at(self, addr: int) -> Region | None:
        i = bisect.bisect_right(self._starts, addr) - 1
        return self.regions[i] if i >= 0 and self.regions[i].contains(addr) else None


@dataclass
class Finding:
    rule: str
    severity: str                  # critical, high, medium, low, info
    title: str
    detail: str
    address: int | None = None
    size: int | None = None
    preview: bytes = b""
    technique: str | None = None   # MITRE ATT&CK

    def to_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "title": self.title, "detail": self.detail,
                "address": f"{self.address:#x}" if self.address is not None else None, "size": self.size,
                "preview": self.preview.hex(), "technique": self.technique}


SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
