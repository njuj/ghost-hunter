"""From a process snapshot to findings. Each check looks for one thing the Windows loader would never
have done on its own:

  pe-in-memory      a PE image sitting in private memory (reflective / manual mapping)
  thread-start      a thread that began in memory no file stands behind (classic injection)
  shellcode         executable memory that starts like a well-known shellcode stub
  hollowed          the process's main image is not the file it was started from (process hollowing)
  inline-hook       an exported function whose first bytes were rewritten into a jump
  iat-hook          an import table entry pointing into memory no file stands behind
  modified-code     code pages of a DLL that differ from the DLL on disk (module stomping, patching)
  phantom-module    a DLL mapped from a file that no longer exists (doppelganging, phantom hollowing)
  unbacked-exec     the rest of the executable memory without a file behind it (JIT engines do this too)
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from . import pe as pelib
from .model import (EXECUTABLE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, WRITABLE_EXEC, Finding, Module, Process,
                    Region, prot_name)

# Engines that legitimately write and run code in private memory.
JIT_MODULES = {"clrjit.dll", "coreclr.dll", "clr.dll", "mscorwks.dll", "jvm.dll", "v8.dll", "libcef.dll",
               "chrome.dll", "msedge.dll", "chakra.dll", "jscript9.dll", "edgehtml.dll", "mono-2.0-bdwgc.dll",
               "mono.dll", "libmonosgen-2.0.dll", "node.dll", "qt6qml.dll", "qt5qml.dll", "mozjs.dll", "xul.dll",
               "luajit.dll", "lua51.dll", "msedgewebview2.exe", "mrt100_app.dll", "mshtml.dll"}
JIT_PROCESSES = {"node.exe", "java.exe", "javaw.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
                 "opera.exe", "msedgewebview2.exe", "powershell.exe", "pwsh.exe", "dotnet.exe", "code.exe",
                 "cursor.exe", "slack.exe", "discord.exe", "teams.exe", "ms-teams.exe", "spotify.exe", "claude.exe",
                 "electron.exe", "obsidian.exe", "notion.exe", "figma.exe", "whatsapp.exe", "steamwebhelper.exe"}
V8_MARKERS = ("v8_context_snapshot.bin", "snapshot_blob.bin", "icudtl.dat")

# Runtimes that rewrite their own code while they run (GC write barriers, lazily bound imports).
SELF_PATCHING = {"clr.dll", "coreclr.dll", "mscorwks.dll", "msys-2.0.dll", "cygwin1.dll", "jvm.dll", "mono-2.0-bdwgc.dll"}

# Starts of widely published shellcode stubs (Metasploit/Cobalt Strike style API-hashing loaders).
STUBS = [
    (bytes.fromhex("fc4883e4f0e8"), "x64 API-hashing stager prologue (cld; and rsp,-16; call)"),
    (bytes.fromhex("fce8820000006089e5"), "x86 API-hashing stager prologue (cld; call; pushad; mov ebp,esp)"),
    (bytes.fromhex("fce8890000006089e5"), "x86 API-hashing stager prologue (cld; call; pushad; mov ebp,esp)"),
    (bytes.fromhex("4d5a41525548"), "reflective loader stub in a PE header ('MZARUH')"),
    (bytes.fromhex("4d5ae800000000"), "reflective loader stub in a PE header (MZ; call $+5)"),
]


@dataclass
class Context:
    """Caches shared across processes: parsed DLLs from disk, and the expected code of each mapping."""
    files: dict[str, pelib.PE | None] = field(default_factory=dict)
    images: dict[tuple[str, int, int], bytes] = field(default_factory=dict)
    read_file: object = None

    def pe(self, path: str) -> pelib.PE | None:
        key = path.lower()
        if key not in self.files:
            try:
                if self.read_file:
                    data = self.read_file(path)
                else:
                    with open(path, "rb") as fh:
                        data = fh.read()
                self.files[key] = pelib.parse(data)
            except (OSError, pelib.PEError, struct.error):
                self.files[key] = None
        return self.files[key]


def is_jit_host(proc: Process) -> bool:
    if proc.name.lower() in JIT_PROCESSES:
        return True
    if any(m.name.lower() in JIT_MODULES for m in proc.modules):
        return True
    if proc.path:
        folder = os.path.dirname(proc.path)
        try:
            return any(os.path.exists(os.path.join(folder, m)) for m in V8_MARKERS)
        except OSError:
            return False
    return False


def _allocations(proc: Process) -> dict[int, list[Region]]:
    out: dict[int, list[Region]] = {}
    for r in proc.regions:
        if r.type in (MEM_PRIVATE, MEM_MAPPED):
            out.setdefault(r.alloc_base, []).append(r)
    return out


def jump_target(code: bytes, addr: int, read, is64: bool = True) -> int | None:
    """Where a hook's first instruction sends execution, for the usual hook encodings."""
    if len(code) >= 5 and code[0] == 0xE9:
        return (addr + 5 + struct.unpack_from("<i", code, 1)[0]) & (2 ** 64 - 1)
    if len(code) >= 6 and code[0] == 0xFF and code[1] == 0x25:
        disp = struct.unpack_from("<i", code, 2)[0]
        slot = addr + 6 + disp if is64 else disp & 0xFFFFFFFF
        raw = read(slot, 8 if is64 else 4)
        return int.from_bytes(raw, "little") if raw else None
    if len(code) >= 12 and code[:2] == b"\x48\xb8" and code[10:12] == b"\xff\xe0":
        return struct.unpack_from("<Q", code, 2)[0]
    if len(code) >= 13 and code[:2] == b"\x49\xbb" and code[10:13] == b"\x41\xff\xe3":
        return struct.unpack_from("<Q", code, 2)[0]
    if len(code) >= 6 and code[0] == 0x68 and code[5] == 0xC3:
        return struct.unpack_from("<I", code, 1)[0]
    if len(code) >= 2 and code[0] == 0xEB:
        return addr + 2 + struct.unpack_from("<b", code, 1)[0]
    # mov r32, imm32 ; jmp/call r32   (B8+r imm32, FF E0+r / FF D0+r): WOW64 and 32-bit hooks
    if len(code) >= 7 and 0xB8 <= code[0] <= 0xBF and code[5] == 0xFF and code[6] in (0xE0 + code[0] - 0xB8, 0xD0 + code[0] - 0xB8):
        return struct.unpack_from("<I", code, 1)[0]
    return None


def _where(proc: Process, addr: int | None) -> tuple[str, bool]:
    """('ntdll.dll+0x1234' or 'private RX memory at 0x...', is_unbacked)"""
    if addr is None:
        return "an address it could not read", False
    m = proc.module_at(addr)
    if m:
        return f"{m.name}+{addr - m.base:#x}", False
    r = proc.region_at(addr)
    if r:
        return f"{'private' if r.type == MEM_PRIVATE else 'mapped'} {prot_name(r.protect)} memory at {addr:#x}", True
    return f"unmapped address {addr:#x}", True


def _norm(p: str | None) -> str:
    return os.path.normcase(os.path.normpath(p)) if p else ""


# ── the checks ───────────────────────────────────────────────────────────────

def check_hollowing(proc: Process) -> list[Finding]:
    if proc.image_base is None or not proc.path:
        return []
    r = proc.region_at(proc.image_base)
    if r is None:
        return [Finding("hollowed", "critical", "The process's main image is gone from memory",
                        f"the PEB points to {proc.image_base:#x}, where nothing is mapped", proc.image_base,
                        technique="T1055.012")]
    if r.type != MEM_IMAGE:
        return [Finding("hollowed", "critical", "Process hollowing: the main image is private memory",
                        f"{proc.name} was started from {proc.path}, but the image its PEB points to at "
                        f"{proc.image_base:#x} is {prot_name(r.protect)} private memory, not a mapped file",
                        proc.image_base, r.size, proc.read(proc.image_base, 64), "T1055.012")]
    if r.mapped_path and _norm(r.mapped_path) != _norm(proc.path) and os.path.basename(_norm(r.mapped_path)) != os.path.basename(_norm(proc.path)):
        return [Finding("hollowed", "critical", "Process hollowing: the main image is a different file",
                        f"started as {proc.path}, but the image in memory is mapped from {r.mapped_path}",
                        proc.image_base, technique="T1055.012")]
    return []


def check_private_code(proc: Process, jit: bool, trampolines: dict[int, str] | None = None) -> list[Finding]:
    trampolines = trampolines or {}
    findings: list[Finding] = []
    explained = 0
    starts: dict[int, list[int]] = {}
    for t in proc.threads:
        r = proc.region_at(t.start)
        if r is not None and r.type != MEM_IMAGE:
            starts.setdefault(r.alloc_base, []).append(t.tid)
        elif r is None and proc.regions:
            starts.setdefault(t.start, []).append(t.tid)
    rest: list[Region] = []
    for base, regs in sorted(_allocations(proc).items()):
        exec_regs = [r for r in regs if r.executable]
        if not exec_regs and base not in starts:
            continue
        head = proc.read(base, 0x1000) if exec_regs else b""
        size = sum(r.size for r in regs)
        prots = "/".join(sorted({prot_name(r.protect) for r in exec_regs})) or prot_name(regs[0].protect)
        kind = "private" if regs[0].type == MEM_PRIVATE else "mapped"
        hit = False
        if exec_regs and (pelib.looks_like_pe(head) or pelib.headerless_pe(head)):
            wiped = not pelib.looks_like_pe(head)
            findings.append(Finding("pe-in-memory", "critical",
                                    "A DLL or EXE mapped by hand into memory" + (" (its MZ header wiped)" if wiped else ""),
                                    f"{size:,} bytes of {kind} {prots} memory at {base:#x} hold a PE image that no file "
                                    f"on disk stands behind: reflective DLL injection or manual mapping",
                                    base, size, head[:64], "T1620"))
            hit = True
        for stub, what in STUBS:
            for r in exec_regs:
                first = head[r.base - base:r.base - base + len(stub)] if r.base - base < len(head) else proc.read(r.base, len(stub))
                if first == stub:
                    findings.append(Finding("shellcode", "critical", "Executable memory starts like known shellcode",
                                            f"{what}, in {kind} {prot_name(r.protect)} memory at {r.base:#x}",
                                            r.base, r.size, proc.read(r.base, 64), "T1055"))
                    hit = True
        if base in starts:
            tids = starts[base]
            findings.append(Finding("thread-start", "high" if jit else "critical",
                                    f"{len(tids)} thread{'s' if len(tids) > 1 else ''} started in memory no file stands behind",
                                    f"thread{'s' if len(tids) > 1 else ''} {', '.join(map(str, tids[:8]))} began in {kind} "
                                    f"{prots} memory at {base:#x} ({size:,} bytes): code injected and started with "
                                    f"CreateRemoteThread or a similar call" + (" (this process also runs a JIT engine)" if jit else ""),
                                    base, size, proc.read(base, 64), "T1055"))
            hit = True
        if not hit and exec_regs:
            if base in trampolines:
                explained += 1
            else:
                rest.extend(exec_regs)
    if rest:
        rwx = [r for r in rest if r.protect & WRITABLE_EXEC]
        mapped = [r for r in rest if r.type == MEM_MAPPED]
        total = sum(r.size for r in rest)
        sev = "info" if jit else "medium" if (rwx or mapped) else "low"
        what = f"{len(rest)} region{'s' if len(rest) > 1 else ''} ({total:,} bytes)"
        if rwx:
            what += f", {len(rwx)} of them writable and executable"
        first = rest[0]
        findings.append(Finding("unbacked-exec", sev, "Executable memory with no file behind it",
                                f"{what}. " + ("Expected here: this process runs a JIT engine (JavaScript, .NET or Java)."
                                               if jit else "Normal for JIT engines; in other programs it is where injected code lives."),
                                first.base, total, proc.read(first.base, 32)))
    return findings


def _diff_runs(a: bytes, b: bytes, skip: list[tuple[int, int]], offset: int) -> list[tuple[int, int]]:
    """[(start, end)] where a and b differ, outside the skip ranges (offsets relative to the section)."""
    runs: list[tuple[int, int]] = []
    i, n = 0, min(len(a), len(b))
    while i < n:
        if a[i] != b[i] and not any(lo <= offset + i < hi for lo, hi in skip):
            j = i
            while j < n and (a[j] != b[j] or (j + 1 < n and a[j + 1] != b[j + 1])):
                j += 1
            if runs and i - runs[-1][1] < 8:
                runs[-1] = (runs[-1][0], j)
            else:
                runs.append((i, j))
            i = j
        i += 1
    return runs


def resolve(proc: Process, addr: int | None) -> tuple[int | None, list[int]]:
    """Follow a hook through trampolines (jumps in private memory) to where the code really goes."""
    chain: list[int] = []
    cur = addr
    for _ in range(4):
        if cur is None or proc.module_at(cur) or proc.region_at(cur) is None:
            break
        nxt = jump_target(proc.read(cur, 16), cur, proc.read, not proc.wow64)
        if nxt is None or nxt == cur:
            break
        chain.append(cur)
        cur = nxt
    return cur, chain


@dataclass
class _Hook:
    module: Module
    label: str            # "DrawTextW" or "+0x1a2b0"
    addr: int
    size: int
    dest: int | None
    hops: int


def _pointer(proc: Process, addr: int, size: int) -> int | None:
    """If a changed run is a pointer (aligned, pointing at mapped memory), where it points."""
    width = 4 if proc.wow64 else 8
    base = addr - addr % width
    if addr + size > base + 2 * width:
        return None
    raw = proc.read(base, width)
    val = int.from_bytes(raw, "little") if len(raw) == width else 0
    return val if val and proc.region_at(val) is not None else None


def check_modules(proc: Process, ctx: Context, jit: bool, trampolines: dict[int, str] | None = None) -> list[Finding]:
    trampolines = {} if trampolines is None else trampolines
    findings: list[Finding] = []
    hooks: list[_Hook] = []
    patched: dict[str, list[tuple[Module, str, int, int]]] = {}
    selfpatch: dict[str, int] = {}
    main = _norm(proc.path)
    for m in proc.modules:
        region = proc.region_at(m.base)
        if region and region.mapped_path and not region.file_exists:
            findings.append(Finding("phantom-module", "high", "Code mapped from a file that no longer exists",
                                    f"{m.path} is mapped at {m.base:#x} but the file is gone from disk "
                                    f"(process doppelganging, phantom DLL hollowing, or a deleted dropper)",
                                    m.base, m.size, technique="T1055.013"))
            continue
        pe = ctx.pe(m.path) if m.path and m.path != "?" else None
        if pe is None:
            continue
        code = [(s, m.base + s.rva, s.vsize or s.raw_size) for s in pe.sections if s.executable]
        dirty = [(s, start, size, pages) for s, start, size in code if (pages := proc.private_code_pages(start, size))]
        if not dirty:
            continue
        skip = pe.iat_ranges()
        exports = pe.exports()
        for s, start, size, pages in dirty:
            key = (m.path.lower(), m.base, s.rva)
            if key not in ctx.images:
                ctx.images[key] = pe.section_image(s, m.base)
            expected = ctx.images[key]
            for page in pages:
                off = page - start
                lo, hi = max(0, off), min(size, off + 0x1000)
                if hi <= lo:
                    continue
                live = proc.read(start + lo, hi - lo)
                for a, b in _diff_runs(live, expected[lo:hi], skip, s.rva + lo):
                    rva = s.rva + lo + a
                    fn = next(((f, name) for f, name in exports.items() if f <= rva < f + 16), None)
                    at = m.base + (fn[0] if fn else rva)
                    target = jump_target(proc.read(at, 16), at, proc.read, not proc.wow64)
                    if target is None and fn:                        # the jump can sit a few bytes in (after mov eax, n)
                        code = proc.read(at, 24)
                        for o in range(1, 12):
                            target = jump_target(code[o:], at + o, proc.read, not proc.wow64)
                            if target is not None and proc.region_at(target) is not None:
                                break
                            target = None
                    if target is None and not fn:                    # a table of function pointers rewritten
                        width = 4 if proc.wow64 else 8
                        site = start + lo + a
                        if site + (b - a) <= site - site % width + 2 * width:   # maybe a pointer slot, not code
                            target = _pointer(proc, site, b - a)
                            slot = site - site % width - start - lo
                            was = int.from_bytes(expected[lo + slot:lo + slot + width], "little") if slot >= 0 else -1
                            if target is not None:
                                if not proc.region_at(target).executable:
                                    continue                         # a data pointer written into the section
                                at = site
                            elif 0 <= was < pe.size_of_image:
                                continue                             # an offset table filled in at run time: data
                    if m.name.lower() in SELF_PATCHING:
                        selfpatch[m.path] = selfpatch.get(m.path, 0) + (b - a)
                    elif target is not None or fn:
                        dest, chain = resolve(proc, target)
                        owner = proc.module_at(dest) if dest is not None else None
                        # the private memory a hook passes through or lands in is reported with the hook
                        for hop in chain + ([] if owner or dest is None else [dest]):
                            r = proc.region_at(hop)
                            if r is not None:
                                trampolines[r.alloc_base] = owner.path if owner else ""
                        hooks.append(_Hook(m, fn[1] if fn else f"+{rva:#x}", at, b - a, dest, len(chain)))
                    else:
                        patched.setdefault(m.path, []).append((m, s.name, start + lo + a, b - a))
    # hooks, grouped by where they lead
    groups: dict[str, list[_Hook]] = {}
    for h in hooks:
        if h.dest is None:
            key = "?"
        else:
            dm = proc.module_at(h.dest)
            key = dm.path if dm else f"@{(proc.region_at(h.dest).alloc_base if proc.region_at(h.dest) else h.dest):#x}"
        groups.setdefault(key, []).append(h)
    for key, hs in groups.items():
        names = ", ".join(f"{h.module.name}!{h.label}" for h in hs[:6]) + (f" and {len(hs) - 6} more" if len(hs) > 6 else "")
        n = f"{len(hs)} function{'s' if len(hs) > 1 else ''}"
        if key == "?":
            findings.append(Finding("inline-hook", "high", f"{n} rewritten in memory", f"{names}: their first bytes changed",
                                    hs[0].addr, sum(h.size for h in hs), proc.read(hs[0].addr, 16), "T1562"))
        elif key.startswith("@"):
            findings.append(Finding("inline-hook", "critical", f"{n} hooked into memory no file stands behind",
                                    f"{names} now jump to private memory at {key[1:]}: injected code runs before the real function",
                                    hs[0].addr, sum(h.size for h in hs), proc.read(hs[0].addr, 16), "T1055"))
        else:
            own = _norm(key) == main
            findings.append(Finding("inline-hook", "low" if own else "medium",
                                    f"{n} hooked by {os.path.basename(key)}",
                                    f"{names} now jump into {key}" + (" (the program hooks itself)" if own else
                                    ": usually a security product, an overlay or a customisation tool; malware does it to hide"),
                                    hs[0].addr, sum(h.size for h in hs), proc.read(hs[0].addr, 16), "T1056.004"))
    for path, n in selfpatch.items():
        findings.append(Finding("modified-code", "info", f"{os.path.basename(path)} patched its own code",
                                f"{n:,} bytes differ from disk: this runtime rewrites parts of itself while it runs (expected)"))
    for path, ps in patched.items():
        m = ps[0][0]
        total = sum(p[3] for p in ps)
        size = sum(s.vsize for s in (ctx.pe(path).sections if ctx.pe(path) else []) if s.executable) or 1
        stomped = total > 4096 or (total >= 512 and total / size > 0.05)
        findings.append(Finding("modified-code", "critical" if stomped else "high",
                                f"{m.name} was overwritten in memory (module stomping)" if stomped else f"Code of {m.name} was changed in memory",
                                f"{total:,} bytes in {len(ps)} place{'s' if len(ps) > 1 else ''} differ from {path} on disk"
                                + (" (the program's own image)" if _norm(path) == main else ""),
                                ps[0][2], total, proc.read(ps[0][2], 32), "T1055" if stomped else "T1562"))
    return findings


def check_imports(proc: Process, ctx: Context, trampolines: dict[int, str]) -> list[Finding]:
    """Import address tables whose entries lead into private memory instead of a DLL."""
    findings = []
    width = 4 if proc.wow64 else 8
    for m in proc.modules:
        pe = ctx.pe(m.path) if m.path and m.path != "?" else None
        if pe is None or len(pe.dirs) <= 12 or not pe.dirs[12][1]:
            continue
        rva, size = pe.dirs[12]
        raw = proc.read(m.base + rva, min(size, 0x10000))
        bad: dict[int, list[int]] = {}
        led: dict[str, list[int]] = {}
        for k in range(0, len(raw) - width + 1, width):
            val = int.from_bytes(raw[k:k + width], "little")
            if not val or proc.module_at(val):
                continue
            r = proc.region_at(val)
            if r is not None and r.executable and r.type != MEM_IMAGE:
                dest, _ = resolve(proc, val)
                owner = proc.module_at(dest) if dest is not None else None
                if owner:                                            # a stub that forwards into a real DLL
                    led.setdefault(owner.path, []).append(m.base + rva + k)
                    trampolines[r.alloc_base] = owner.path
                else:
                    bad.setdefault(r.alloc_base, []).append(m.base + rva + k)
                    trampolines[r.alloc_base] = ""
        for base, slots in bad.items():
            findings.append(Finding("iat-hook", "critical", f"{len(slots)} import{'s' if len(slots) > 1 else ''} of {m.name} redirected into private memory",
                                    f"entries of {m.name}'s import table now point into {prot_name(proc.region_at(base).protect)} memory "
                                    f"at {base:#x} instead of the DLLs it imports: calls go through injected code first",
                                    slots[0], len(slots) * width, proc.read(base, 32), "T1055"))
        for path, slots in led.items():
            findings.append(Finding("iat-hook", "medium", f"{len(slots)} import{'s' if len(slots) > 1 else ''} of {m.name} redirected to {os.path.basename(path)}",
                                    f"entries of {m.name}'s import table go through a stub into {path}",
                                    slots[0], len(slots) * width, technique="T1056.004"))
    return findings


def analyze(proc: Process, ctx: Context | None = None) -> list[Finding]:
    ctx = ctx or Context()
    jit = is_jit_host(proc)
    trampolines: dict[int, str] = {}
    hooks = check_modules(proc, ctx, jit, trampolines)
    imports = check_imports(proc, ctx, trampolines)
    findings = check_hollowing(proc) + check_private_code(proc, jit, trampolines) + hooks + imports
    from .model import RANK
    return sorted(findings, key=lambda f: (RANK[f.severity], f.address or 0))
