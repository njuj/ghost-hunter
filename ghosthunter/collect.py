"""Reading a live Windows process from the outside, read-only: its memory map (VirtualQueryEx), the
files behind its mappings, its threads' start addresses, its PEB and which code pages are no longer
shared with the file on disk (QueryWorkingSetEx). Nothing is written to any process."""

from __future__ import annotations

import ctypes
import os
import string
import sys
from ctypes import wintypes as W

from .model import MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, Process, Region, Thread

if sys.platform != "win32":                       # pragma: no cover
    raise ImportError("live collection needs Windows")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ = 0x0400, 0x1000, 0x0010
THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION = 0x0040, 0x0800
TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD = 0x2, 0x4
INVALID_HANDLE = ctypes.c_void_p(-1).value


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", W.DWORD),
                ("PartitionId", W.WORD), ("RegionSize", ctypes.c_size_t), ("State", W.DWORD), ("Protect", W.DWORD),
                ("Type", W.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", W.DWORD), ("cntThreads", W.DWORD),
                ("th32ParentProcessID", W.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", W.DWORD),
                ("szExeFile", W.WCHAR * 260)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ThreadID", W.DWORD),
                ("th32OwnerProcessID", W.DWORD), ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", W.DWORD)]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p), ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p)]


class WS_EX(ctypes.Structure):
    _fields_ = [("VirtualAddress", ctypes.c_void_p), ("VirtualAttributes", ctypes.c_size_t)]


def _sig(fn, res, *args):
    fn.restype, fn.argtypes = res, list(args)


_sig(k32.OpenProcess, W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
_sig(k32.OpenThread, W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
_sig(k32.CloseHandle, W.BOOL, W.HANDLE)
_sig(k32.VirtualQueryEx, ctypes.c_size_t, W.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t)
_sig(k32.ReadProcessMemory, W.BOOL, W.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_sig(k32.K32GetMappedFileNameW, W.DWORD, W.HANDLE, ctypes.c_void_p, W.LPWSTR, W.DWORD)
_sig(k32.K32QueryWorkingSetEx, W.BOOL, W.HANDLE, ctypes.c_void_p, W.DWORD)
_sig(k32.QueryFullProcessImageNameW, W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD))
_sig(k32.IsWow64Process, W.BOOL, W.HANDLE, ctypes.POINTER(W.BOOL))
_sig(k32.CreateToolhelp32Snapshot, W.HANDLE, W.DWORD, W.DWORD)
_sig(k32.Process32FirstW, W.BOOL, W.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
_sig(k32.Process32NextW, W.BOOL, W.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
_sig(k32.Thread32First, W.BOOL, W.HANDLE, ctypes.POINTER(THREADENTRY32))
_sig(k32.Thread32Next, W.BOOL, W.HANDLE, ctypes.POINTER(THREADENTRY32))
_sig(k32.QueryDosDeviceW, W.DWORD, W.LPCWSTR, W.LPWSTR, W.DWORD)
_sig(ntdll.NtQueryInformationProcess, ctypes.c_long, W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.ULONG, ctypes.POINTER(W.ULONG))
_sig(ntdll.NtQueryInformationThread, ctypes.c_long, W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.ULONG, ctypes.POINTER(W.ULONG))


def _device_map() -> dict[str, str]:
    """\\Device\\HarddiskVolume3 -> C:"""
    out = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in string.ascii_uppercase:
        if k32.QueryDosDeviceW(f"{letter}:", buf, 1024):
            out[buf.value] = f"{letter}:"
    return out


_DEVICES: dict[str, str] | None = None


def dos_path(nt_path: str) -> str:
    global _DEVICES
    if _DEVICES is None:
        _DEVICES = _device_map()
    for dev, letter in _DEVICES.items():
        if nt_path.lower().startswith(dev.lower() + "\\"):
            return letter + nt_path[len(dev):]
    return nt_path


def list_processes() -> list[tuple[int, str, int]]:
    """[(pid, exe name, parent pid)]"""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.szExeFile, e.th32ParentProcessID))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def _threads_by_pid() -> dict[int, list[int]]:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    out: dict[int, list[int]] = {}
    if snap == INVALID_HANDLE:
        return out
    try:
        t = THREADENTRY32()
        t.dwSize = ctypes.sizeof(t)
        ok = k32.Thread32First(snap, ctypes.byref(t))
        while ok:
            out.setdefault(t.th32OwnerProcessID, []).append(t.th32ThreadID)
            ok = k32.Thread32Next(snap, ctypes.byref(t))
    finally:
        k32.CloseHandle(snap)
    return out


def _thread_start(tid: int) -> int | None:
    h = k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None
    try:
        addr = ctypes.c_void_p()
        status = ntdll.NtQueryInformationThread(h, 9, ctypes.byref(addr), ctypes.sizeof(addr), None)  # Win32StartAddress
        return addr.value if status == 0 and addr.value else None
    finally:
        k32.CloseHandle(h)


class AccessDenied(OSError):
    pass


class LiveProcess:
    """An open, read-only handle on a process. Use as a context manager."""

    def __init__(self, pid: int):
        self.pid = pid
        self.h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.h:
            raise AccessDenied(ctypes.get_last_error(), f"cannot open process {pid}")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        k32.CloseHandle(self.h)

    def read(self, addr: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        if k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
            return buf.raw[:got.value]
        # partly unreadable: read page by page
        out = bytearray()
        for page in range(addr, addr + size, 0x1000):
            n = min(0x1000 - page % 0x1000, addr + size - page)
            if k32.ReadProcessMemory(self.h, ctypes.c_void_p(page), buf, n, ctypes.byref(got)):
                out += buf.raw[:got.value]
            else:
                out += b"\0" * n
        return bytes(out)

    def private_code_pages(self, base: int, size: int) -> list[int]:
        """Resident pages of an image range that are no longer shared with the file: written to after load."""
        pages = list(range(base & ~0xFFF, base + size, 0x1000))
        out = []
        for i in range(0, len(pages), 4096):
            chunk = pages[i:i + 4096]
            arr = (WS_EX * len(chunk))()
            for k, p in enumerate(chunk):
                arr[k].VirtualAddress = p
            if not k32.K32QueryWorkingSetEx(self.h, arr, ctypes.sizeof(arr)):
                continue
            for k, p in enumerate(chunk):
                attrs = arr[k].VirtualAttributes
                valid, shared = attrs & 1, (attrs >> 15) & 1
                if valid and not shared:
                    out.append(p)
        return out

    def regions(self) -> list[Region]:
        out = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        name = ctypes.create_unicode_buffer(1024)
        paths: dict[int, tuple[str | None, bool]] = {}
        while k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if mbi.State == MEM_COMMIT:
                alloc = mbi.AllocationBase or 0
                path, exists = None, True
                if mbi.Type in (MEM_IMAGE, MEM_MAPPED):
                    if alloc not in paths:
                        n = k32.K32GetMappedFileNameW(self.h, ctypes.c_void_p(base), name, 1024)
                        p = dos_path(name.value) if n else None
                        paths[alloc] = (p, bool(p) and os.path.exists(p))
                    path, exists = paths[alloc]
                out.append(Region(base, size, alloc, mbi.AllocationProtect, mbi.Protect, mbi.Type, path, exists))
            nxt = base + size
            if nxt <= addr or nxt >= 1 << 47:
                break
            addr = nxt
        return out

    def image_path(self) -> str | None:
        buf = ctypes.create_unicode_buffer(1024)
        n = W.DWORD(1024)
        return buf.value if k32.QueryFullProcessImageNameW(self.h, 0, buf, ctypes.byref(n)) else None

    def wow64(self) -> bool:
        b = W.BOOL()
        return bool(k32.IsWow64Process(self.h, ctypes.byref(b)) and b.value)

    def peb_image_base(self) -> int | None:
        pbi = PROCESS_BASIC_INFORMATION()
        if ntdll.NtQueryInformationProcess(self.h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None) != 0 or not pbi.PebBaseAddress:
            return None
        raw = self.read(pbi.PebBaseAddress + 0x10, 8)
        return int.from_bytes(raw, "little") if len(raw) == 8 else None


def snapshot(pid: int, name: str = "", threads: dict[int, list[int]] | None = None) -> tuple[Process, LiveProcess]:
    """A Process snapshot backed by a live handle (keep the LiveProcess open while analysing)."""
    lp = LiveProcess(pid)
    tids = (threads if threads is not None else _threads_by_pid()).get(pid, [])
    ths = [Thread(t, s) for t in tids if (s := _thread_start(t))]
    path = lp.image_path()
    proc = Process(pid, name or (os.path.basename(path) if path else str(pid)), path, lp.regions(), ths,
                   lp.peb_image_base(), lp.wow64(), lp.read, lp.private_code_pages)
    return proc, lp


def all_threads() -> dict[int, list[int]]:
    return _threads_by_pid()
