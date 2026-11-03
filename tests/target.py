"""A harmless test subject: a process that does one injection-shaped thing *to itself*, prints "ready"
and sleeps until it is killed. No code it plants is ever executed: the planted thread stays
suspended, the hooked function is never called, the stomped DLL is mapped without running.

    python target.py clean | thread | pe | hook | iat | stomp | rwx
"""

import ctypes
import os
import sys
import time
from ctypes import wintypes as W

sys.path.insert(0, os.path.dirname(__file__))
from pebuild import make_pe  # noqa: E402

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, W.DWORD, W.DWORD]
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, W.DWORD, ctypes.POINTER(W.DWORD)]
k32.CreateThread.restype = W.HANDLE
k32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)]
k32.GetModuleHandleW.restype = W.HMODULE
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [W.HMODULE, ctypes.c_char_p]
k32.LoadLibraryExW.restype = W.HMODULE
k32.LoadLibraryExW.argtypes = [W.LPCWSTR, W.HANDLE, W.DWORD]

MEM = 0x3000                      # MEM_COMMIT | MEM_RESERVE
RX, RW, RWX = 0x20, 0x04, 0x40
CREATE_SUSPENDED = 0x4
DONT_RESOLVE_DLL_REFERENCES = 0x1


def alloc(data: bytes, final_protect: int) -> int:
    addr = k32.VirtualAlloc(None, max(len(data), 0x1000), MEM, RW)
    ctypes.memmove(addr, data, len(data))
    old = W.DWORD()
    k32.VirtualProtect(addr, max(len(data), 0x1000), final_protect, ctypes.byref(old))
    return addr


def patch(addr: int, data: bytes) -> None:
    old = W.DWORD()
    k32.VirtualProtect(addr, len(data), RWX, ctypes.byref(old))
    ctypes.memmove(addr, data, len(data))
    k32.VirtualProtect(addr, len(data), old.value, ctypes.byref(old))


def main(mode: str) -> None:
    info = {}
    if mode == "thread":
        code = alloc(b"\xc3" * 64, RX)                          # ret; the thread never even starts
        tid = W.DWORD()
        k32.CreateThread(None, 0, code, None, CREATE_SUSPENDED, ctypes.byref(tid))
        info = {"addr": code, "tid": tid.value}
    elif mode == "pe":
        info = {"addr": alloc(make_pe(b"\xc3" * 32, exports={"Run": 0x1000}), RX)}
    elif mode == "rwx":
        info = {"addr": alloc(b"\x90" * 32 + b"\xc3", RWX)}
    elif mode == "hook":
        target = alloc(b"\xc3" * 16, RX)                        # where the hook leads: private memory
        beep = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"Beep")
        patch(beep, b"\xff\x25\x00\x00\x00\x00" + target.to_bytes(8, "little"))   # jmp [rip+0]; never called
        info = {"addr": beep, "target": target}
    elif mode == "iat":
        target = alloc(b"\xc3" * 16, RX)
        exe =k32.GetModuleHandleW(None)                       # python.exe's own import table
        lfanew = ctypes.c_uint32.from_address(exe + 0x3C).value
        iat_rva, iat_size = ctypes.c_uint32.from_address(exe + lfanew + 24 + 112 + 12 * 8).value, ctypes.c_uint32.from_address(exe + lfanew + 24 + 112 + 12 * 8 + 4).value
        slot = exe + iat_rva + iat_size - 16                   # the last import, which this process has already used
        while not ctypes.c_uint64.from_address(slot).value:
            slot -= 8
        patch(slot, target.to_bytes(8, "little"))
        info = {"addr": slot, "target": target}
    elif mode == "stomp":
        dll = os.path.join(os.environ["SystemRoot"], "System32", "dbghelp.dll")
        base = k32.LoadLibraryExW(dll, None, DONT_RESOLVE_DLL_REFERENCES)   # mapped, DllMain not run
        patch(base + 0x1000, b"\xcc" * 0x3000)                  # overwrite 12 KB of its code with int3
        info = {"addr": base + 0x1000}
    elif mode != "clean":
        raise SystemExit(f"unknown mode {mode}")
    print("ready", " ".join(f"{k}={v}" for k, v in info.items()), flush=True)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "clean")
