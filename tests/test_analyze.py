"""The analysis on made-up process snapshots: every check, and the normal cases it must leave alone.
Runs on any OS."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghosthunter import pe as pelib  # noqa: E402
from ghosthunter.analyze import Context, analyze, jump_target  # noqa: E402
from ghosthunter.model import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, Process, Region, Thread  # noqa: E402
from pebuild import make_pe  # noqa: E402

RX, RWX, R, RW = 0x20, 0x40, 0x02, 0x04
EXE = r"C:\app\app.exe"
DLL = r"C:\Windows\System32\fake.dll"
EXE_BASE, DLL_BASE, HEAP = 0x7FF600000000, 0x7FFA00000000, 0x20000000


class Memory:
    def __init__(self):
        self.blocks: dict[int, bytearray] = {}
        self.dirty: set[int] = set()

    def put(self, addr: int, data: bytes, dirty: bool = False):
        self.blocks[addr] = bytearray(data)
        if dirty:
            self.dirty.update(range(addr & ~0xFFF, addr + len(data), 0x1000))

    def write(self, addr: int, data: bytes):
        for base, buf in self.blocks.items():
            if base <= addr < base + len(buf):
                buf[addr - base:addr - base + len(data)] = data
                self.dirty.add(addr & ~0xFFF)
                return
        raise KeyError(hex(addr))

    def read(self, addr: int, size: int) -> bytes:
        for base, buf in self.blocks.items():
            if base <= addr < base + len(buf):
                return bytes(buf[addr - base:addr - base + size])
        return b""

    def private_pages(self, base: int, size: int) -> list[int]:
        return sorted(p for p in self.dirty if base <= p < base + size)


def image_regions(base: int, path: str, pe: pelib.PE) -> list[Region]:
    regs = [Region(base, 0x1000, base, 0x80, R, MEM_IMAGE, path)]
    for s in pe.sections:
        regs.append(Region(base + s.rva, 0x1000, base, 0x80, RX if s.executable else R, MEM_IMAGE, path))
    return regs


def load(mem: Memory, base: int, data: bytes) -> pelib.PE:
    """Map a PE the way the loader would: headers, then each section, relocations applied."""
    pe = pelib.parse(data)
    mem.put(base, data[:pe.size_of_headers])
    for s in pe.sections:
        mem.put(base + s.rva, pe.section_image(s, base))
    return pe


EXE_PE = make_pe(b"\x48\x83\xec\x28\xc3" + b"\x90" * 27, image_base=0x140000000)
DLL_CODE = b"\x48\x8b\xc4\xc3" + b"\x90" * 12 + struct.pack("<Q", 0x180001000) + b"\xcc" * 40
DLL_PE = make_pe(DLL_CODE, relocs=[0x1010], exports={"DoWork": 0x1000, "Other": 0x1020})


def make_process(mem: Memory | None = None, *, extra: list[Region] = (), threads=(), name="app.exe",
                 image_base: int | None = EXE_BASE, files: dict | None = None):
    mem = mem or Memory()
    exe = load(mem, EXE_BASE, EXE_PE)
    dll = load(mem, DLL_BASE, DLL_PE)
    regions = image_regions(EXE_BASE, EXE, exe) + image_regions(DLL_BASE, DLL, dll) + list(extra)
    proc = Process(4242, name, EXE, regions, list(threads), image_base, False, mem.read, mem.private_pages)
    files = files or {EXE.lower(): EXE_PE, DLL.lower(): DLL_PE}
    ctx = Context(read_file=lambda p: files[p.lower()])
    return proc, mem, ctx


def rules(findings):
    return [(f.rule, f.severity) for f in findings]


class CleanProcess(unittest.TestCase):
    def test_a_normal_process_has_nothing_to_report(self):
        proc, _, ctx = make_process()
        self.assertEqual(analyze(proc, ctx), [])

    def test_relocations_alone_are_not_modifications(self):
        # the DLL loaded away from its preferred base: its pointer was relocated, and its page is private
        mem = Memory()
        proc, mem, ctx = make_process(mem)
        mem.dirty.add(DLL_BASE + 0x1000)
        self.assertEqual(analyze(proc, ctx), [])


class Injection(unittest.TestCase):
    def test_thread_started_in_private_memory(self):
        mem = Memory()
        mem.put(HEAP, b"\x90" * 0x1000)
        proc, _, ctx = make_process(mem, extra=[Region(HEAP, 0x1000, HEAP, RX, RX, MEM_PRIVATE)], threads=[Thread(7, HEAP + 0x10)])
        self.assertEqual(rules(analyze(proc, ctx)), [("thread-start", "critical")])

    def test_threads_starting_in_modules_are_normal(self):
        proc, _, ctx = make_process(threads=[Thread(1, EXE_BASE + 0x1000), Thread(2, DLL_BASE + 0x1000)])
        self.assertEqual(analyze(proc, ctx), [])

    def test_pe_in_private_memory_and_a_wiped_header(self):
        mem = Memory()
        mem.put(HEAP, make_pe(b"\xc3"))
        wiped = bytearray(make_pe(b"\xc3"))
        wiped[:2] = b"\0\0"
        mem.put(HEAP + 0x100000, bytes(wiped))
        proc, _, ctx = make_process(mem, extra=[Region(HEAP, 0x3000, HEAP, RX, RX, MEM_PRIVATE),
                                                Region(HEAP + 0x100000, 0x3000, HEAP + 0x100000, RX, RX, MEM_PRIVATE)])
        found = analyze(proc, ctx)
        self.assertEqual(rules(found), [("pe-in-memory", "critical")] * 2)
        self.assertIn("MZ header wiped", found[1].title)

    def test_known_shellcode_stub(self):
        mem = Memory()
        mem.put(HEAP, bytes.fromhex("fc4883e4f0e8c0000000") + b"\0" * 64)
        proc, _, ctx = make_process(mem, extra=[Region(HEAP, 0x1000, HEAP, RWX, RWX, MEM_PRIVATE)])
        self.assertEqual(rules(analyze(proc, ctx)), [("shellcode", "critical")])


class Hollowing(unittest.TestCase):
    def test_main_image_replaced_by_private_memory(self):
        mem = Memory()
        mem.put(HEAP, make_pe(b"\xc3"))
        proc, _, ctx = make_process(mem, extra=[Region(HEAP, 0x3000, HEAP, RWX, RX, MEM_PRIVATE)], image_base=HEAP)
        found = rules(analyze(proc, ctx))
        self.assertIn(("hollowed", "critical"), found)
        self.assertIn(("pe-in-memory", "critical"), found)

    def test_main_image_from_another_file(self):
        proc, _, ctx = make_process(image_base=DLL_BASE)
        self.assertEqual(rules(analyze(proc, ctx)), [("hollowed", "critical")])


class Hooks(unittest.TestCase):
    def test_hook_into_private_memory_is_critical(self):
        mem = Memory()
        mem.put(HEAP, b"\xc3" * 0x1000)
        proc, mem, ctx = make_process(mem, extra=[Region(HEAP, 0x1000, HEAP, RX, RX, MEM_PRIVATE)])
        mem.write(DLL_BASE + 0x1000, b"\xff\x25\x00\x00\x00\x00" + HEAP.to_bytes(8, "little"))
        found = analyze(proc, ctx)
        self.assertEqual(rules(found), [("inline-hook", "critical")])     # the landing memory is not reported twice
        self.assertIn("fake.dll!DoWork", found[0].detail)

    def _sandboxed(self, export: str, chromium: bool):
        """A child process whose ntdll stub jumps into private memory, the way Chromium's broker patches it."""
        mem = Memory()
        ntdll, chrome, CHROME_BASE = r"C:\Windows\System32\ntdll.dll", r"C:\app\chrome.dll", DLL_BASE + 0x10000000
        nt_pe = make_pe(DLL_CODE, relocs=[0x1010], exports={export: 0x1000, "Other": 0x1020})
        exe, nt = load(mem, EXE_BASE, EXE_PE), load(mem, DLL_BASE, nt_pe)
        regions = image_regions(EXE_BASE, EXE, exe) + image_regions(DLL_BASE, ntdll, nt)
        files = {EXE.lower(): EXE_PE, ntdll.lower(): nt_pe}
        if chromium:
            regions += image_regions(CHROME_BASE, chrome, load(mem, CHROME_BASE, DLL_PE))
            files[chrome.lower()] = DLL_PE
        mem.put(HEAP, b"\xc3" * 0x1000)
        regions.append(Region(HEAP, 0x1000, HEAP, RX, RX, MEM_PRIVATE))
        proc = Process(4242, "app.exe", EXE, regions, [], EXE_BASE, False, mem.read, mem.private_pages)
        mem.write(DLL_BASE + 0x1000, b"\xff\x25\x00\x00\x00\x00" + HEAP.to_bytes(8, "little"))
        return analyze(proc, Context(read_file=lambda p: files[p.lower()]))

    def test_chromium_sandbox_interception_is_low(self):
        found = self._sandboxed("NtOpenFile", chromium=True)
        self.assertEqual(rules(found), [("inline-hook", "low")])
        self.assertIn("Chromium's sandbox", found[0].title)

    def test_same_hook_outside_chromium_or_on_other_function_stays_critical(self):
        self.assertEqual(rules(self._sandboxed("NtOpenFile", chromium=False)), [("inline-hook", "critical")])
        self.assertEqual(rules(self._sandboxed("NtWriteVirtualMemory", chromium=True)), [("inline-hook", "critical")])

    def test_hook_through_a_trampoline_into_another_dll_is_attributed(self):
        mem = Memory()
        tramp = DLL_BASE - 0x100000                                    # within reach of a rel32 jump
        mem.put(tramp, b"\xff\x25\x00\x00\x00\x00" + (EXE_BASE + 0x1000).to_bytes(8, "little") + b"\0" * 0xFF0)
        proc, mem, ctx = make_process(mem, extra=[Region(tramp, 0x1000, tramp, RX, RX, MEM_PRIVATE)])
        mem.write(DLL_BASE + 0x1000, b"\xe9" + struct.pack("<i", tramp - (DLL_BASE + 0x1005)))
        found = analyze(proc, ctx)
        # the program hooks a DLL into its own code: low, and the trampoline page is explained by the hook
        self.assertEqual(rules(found), [("inline-hook", "low")])
        self.assertIn("hooked by app.exe", found[0].title)

    def test_patched_code_that_is_not_a_jump(self):
        proc, mem, ctx = make_process()
        mem.write(DLL_BASE + 0x1030, b"\x90\x90\x90\x90")
        self.assertEqual(rules(analyze(proc, ctx)), [("modified-code", "high")])

    def test_data_pointer_in_a_code_section_is_ignored(self):
        mem = Memory()
        mem.put(HEAP, b"\0" * 0x1000)
        proc, mem, ctx = make_process(mem, extra=[Region(HEAP, 0x1000, HEAP, R, R, MEM_MAPPED)])
        mem.write(DLL_BASE + 0x1010, HEAP.to_bytes(8, "little"))     # a pointer slot now aims at read-only data
        self.assertEqual(analyze(proc, ctx), [])

    def test_module_stomping(self):
        proc, mem, ctx = make_process()
        mem.write(DLL_BASE + 0x1030, b"\xcc" * 0x20)
        big = make_pe(b"\x90" * 0x3000)
        files = {EXE.lower(): EXE_PE, DLL.lower(): big}
        mem2 = Memory()
        proc, mem2, ctx = make_process(mem2, files=files)
        load(mem2, DLL_BASE, big)
        proc.regions[:] = [r for r in proc.regions if r.alloc_base != DLL_BASE] + image_regions(DLL_BASE, DLL, pelib.parse(big))
        mem2.write(DLL_BASE + 0x1100, b"\xcc" * 0x1800)
        found = analyze(proc, ctx)
        self.assertEqual(rules(found), [("modified-code", "critical")])
        self.assertIn("module stomping", found[0].title)


class Other(unittest.TestCase):
    def test_phantom_module(self):
        proc, _, ctx = make_process()
        for r in proc.regions:
            if r.alloc_base == DLL_BASE:
                r.file_exists = False
        self.assertEqual(rules(analyze(proc, ctx)), [("phantom-module", "high")])

    def test_unbacked_executable_memory_by_process_kind(self):
        mem = Memory()
        mem.put(HEAP, b"\x90" * 0x1000)
        mem.put(HEAP + 0x10000, b"\x90" * 0x1000)
        rx = [Region(HEAP, 0x1000, HEAP, RX, RX, MEM_PRIVATE)]
        rwx = rx + [Region(HEAP + 0x10000, 0x1000, HEAP + 0x10000, RWX, RWX, MEM_PRIVATE)]
        self.assertEqual(rules(analyze(make_process(mem, extra=rx)[0], make_process()[2])), [("unbacked-exec", "low")])
        self.assertEqual(rules(analyze(make_process(mem, extra=rwx)[0], make_process()[2])), [("unbacked-exec", "medium")])
        jit = make_process(mem, extra=rwx, name="node.exe")
        self.assertEqual(rules(analyze(jit[0], jit[2])), [("unbacked-exec", "info")])

    def test_jump_encodings(self):
        read = {0x2000 + 6: (0x7777).to_bytes(8, "little")}.get
        r = lambda a, n: read(a, b"")[:n]  # noqa: E731
        self.assertEqual(jump_target(b"\xe9\x10\x00\x00\x00", 0x1000, r), 0x1015)
        self.assertEqual(jump_target(b"\xff\x25\x00\x00\x00\x00", 0x2000, r), 0x7777)
        self.assertEqual(jump_target(b"\x48\xb8" + (0x1234).to_bytes(8, "little") + b"\xff\xe0", 0, r), 0x1234)
        self.assertEqual(jump_target(b"\x49\xbb" + (0x4321).to_bytes(8, "little") + b"\x41\xff\xe3", 0, r), 0x4321)
        self.assertEqual(jump_target(b"\x68\x78\x56\x34\x12\xc3", 0, r), 0x12345678)
        self.assertEqual(jump_target(b"\xba\x78\x56\x34\x12\xff\xe2", 0, r), 0x12345678)     # mov edx; jmp edx
        self.assertIsNone(jump_target(b"\x48\x8b\xc4\xc3", 0, r))


class PE(unittest.TestCase):
    def test_parse_relocate_and_exports(self):
        pe = pelib.parse(DLL_PE)
        self.assertTrue(pe.is64)
        self.assertEqual(pe.exports(), {0x1000: "DoWork", 0x1020: "Other"})
        self.assertEqual(pe.relocs, [(0x1010, 8)])
        text = pe.sections[0]
        moved = pe.section_image(text, 0x7FFA00000000)
        self.assertEqual(struct.unpack_from("<Q", moved, 0x10)[0], 0x7FFA00000000 + 0x1000)
        self.assertTrue(pelib.looks_like_pe(DLL_PE))
        self.assertFalse(pelib.looks_like_pe(b"MZ" + b"\0" * 100))

    def test_real_system_dll_when_available(self):
        path = Path(r"C:\Windows\System32\kernel32.dll")
        if not path.exists():
            self.skipTest("not on Windows")
        pe = pelib.parse(path.read_bytes())
        names = set(pe.exports().values())
        self.assertIn("CreateFileW", names)
        self.assertTrue(any(s.executable for s in pe.sections))
        self.assertTrue(pe.relocs)


if __name__ == "__main__":
    unittest.main()
