# ghost-hunter

**Find code injected into running Windows processes.** ghost-hunter looks for reflectively loaded DLLs, shellcode threads, hollowed processes, inline and import-table hooks, and stomped modules. It reads each process from the outside and never writes to one. It needs nothing but Python's standard library.

[![ci](https://github.com/njuj/ghost-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/ghost-hunter/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00e5ff?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00e5ff?labelColor=0b0f17)
![os](https://img.shields.io/badge/os-Windows-00e5ff?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00e5ff?labelColor=0b0f17)

Malware likes to live inside someone else's process. Once it is there it has no file of its own, and its code runs under the name of `explorer.exe` or `svchost.exe`. EDR products look for that. ghost-hunter does the same in about 1,200 readable lines, and it explains every finding in plain words.

```text
$ ghost-hunter --pid 316 --pid 14016 --pid 1648 --pid 6092

 python.exe  pid 316
   ✖ CRITICAL 1 thread started in memory no file stands behind  0x134286f0000  T1055
              └ thread 11548 began in private RX memory at 0x134286f0000 (4,096 bytes): code injected and
                started with CreateRemoteThread or a similar call

 python.exe  pid 14016
   ✖ CRITICAL A DLL or EXE mapped by hand into memory  0x1af30480000  T1620
              └ 4,096 bytes of private RX memory at 0x1af30480000 hold a PE image that no file on disk
                stands behind: reflective DLL injection or manual mapping
                4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00

 python.exe  pid 1648
   ✖ CRITICAL 1 function hooked into memory no file stands behind  0x7ffbd9cafa20  T1055
              └ kernel32.dll!Beep now jump to private memory at 0x1433cb30000: injected code runs before
                the real function
                ff 25 00 00 00 00 00 00 b3 3c 43 01 00 00 e8 21

 python.exe  pid 6092
   ✖ CRITICAL dbghelp.dll was overwritten in memory (module stomping)  0x7ffbc04c1008  T1055
              └ 11,931 bytes in 28 places differ from C:\Windows\System32\dbghelp.dll on disk

 4 critical
```

*(These four processes are the test suite's harmless targets. Each one plants a single injection-shaped artefact in itself and never runs it. See [Testing](#testing).)*

## Run it

```bash
pip install git+https://github.com/njuj/ghost-hunter
ghost-hunter                       # every process you can open
ghost-hunter --name explorer.exe   # or by name / --pid
ghost-hunter --dump out/           # also save suspicious regions (feed them to a static scanner)
ghost-hunter --json                # for scripts and SIEMs
```

Run it from an elevated prompt to include other users' and system processes. Protected processes (PPL, such as antivirus engines) cannot be opened from user mode by anyone. Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings, `2` it could not run.

## What it checks

| rule | what the Windows loader would never do on its own | ATT&CK |
|---|---|---|
| `pe-in-memory` | a PE image in private memory, including one whose `MZ` was wiped to hide it | T1620 |
| `thread-start` | a thread whose start address is in memory with no file behind it | T1055 |
| `shellcode` | executable memory starting like a well-known API-hashing stager or reflective loader stub | T1055 |
| `hollowed` | the image the PEB points to is private memory, or a different file from the one the process started from | T1055.012 |
| `inline-hook` | an exported function rewritten into a jump (`jmp rel32`, `jmp [rip]`, `mov reg, imm; jmp reg`, `push; ret`), followed through trampolines to where it really lands | T1055 / T1056.004 |
| `iat-hook` | import-table entries pointing into private memory instead of the DLL they import | T1055 |
| `modified-code` | code pages that differ from the DLL on disk. It flags module stomping when kilobytes were overwritten | T1055 |
| `phantom-module` | an image mapped from a file that no longer exists (doppelgänging, phantom DLL hollowing) | T1055.013 |
| `unbacked-exec` | the remaining executable memory with no file behind it. It is `info` in JIT engines, `low` elsewhere, and `medium` when it is writable too | |

**How the code comparison works.** ghost-hunter asks Windows which code pages of each DLL are no longer shared with the file on disk (`QueryWorkingSetEx`). It then rebuilds only those pages from the file, with relocations applied at the real load address and the import table left out, and diffs them byte for byte. Clean modules cost one system call. Relocations are never mistaken for patches.

**Attribution keeps the noise down.** A hook that jumps through a trampoline into another DLL is reported as *"38 functions hooked by translucent-windows.dll"*, not as 38 alarms. Something that appears in many processes, like an overlay or a theming tool, is shown once under *across many processes*. Runtimes that patch themselves (the .NET CLR, Cygwin/MSYS), JIT engines (V8, Chakra, .NET, Java), and data pointers written into code sections are all recognised.

## On a real machine

I ran it on my everyday Windows 11 PC, without administrator rights. It opened 81 processes in about 13 seconds:

- **1 critical:** `asus_framework.exe`. ASUS's Armoury framework rewrites 7 `ntdll` functions (`NtOpenProcess`, `NtMapViewOfSection`…) into jumps to private memory. That is legitimate software doing exactly what malware does. ghost-hunter cannot judge intent; it shows you where to look.
- **Medium, attributed:** Windhawk theme mods hooking 38 functions in nearly every process, RivaTuner's overlay hooking `dxgi.dll`, and Discord's voice module hooking thread APIs.
- **Low:** Chrome, Discord and Claude (all Chromium) hooking their own `ntdll`. That is Chromium's sandbox.

The first version reported 1,324 criticals on the same machine. Following the trampolines and grouping by destination is what turned that into one.

## Testing

```bash
python -m unittest discover -s tests -v
```

There are 28 tests:

- **On any OS:** the analysis runs on made-up process snapshots. This covers each check, plus the normal cases it must leave alone: relocated DLLs, threads starting in modules, JIT memory, data pointers in code sections, and a program hooking itself.
- **Live, on Windows** (in CI on GitHub's Windows runners): [`tests/target.py`](tests/target.py) starts a harmless Python process. It plants exactly one artefact in **itself**: a suspended thread on a `ret` instruction, a tiny PE in private memory, a `jmp` written over `Beep` (which it never calls), a rewritten import slot, or 12 KB of `int3` over a copy of `dbghelp.dll` that it maps without running. ghost-hunter must find exactly that, at the right address, and nothing serious in a clean process.

## Limits

- **User mode only.** Kernel rootkits and anything hidden from `VirtualQueryEx` are out of reach.
- **No call-stack analysis yet.** A sleeping beacon whose threads start inside a real module and whose code is encrypted while it sleeps (sleep masking) can get past these checks.
- **Paged-out code pages are not compared.** `QueryWorkingSetEx` only reports resident pages, which in practice are the ones being executed.
- **Exception-handler and hardware-breakpoint hooks are not detected.** Neither are hooks that use instructions other than the common jump forms; those are still reported as modified code.

## Layout

```
ghosthunter/collect.py   the live, read-only view of a process (ctypes: VirtualQueryEx, QueryWorkingSetEx, NtQueryInformationThread…)
ghosthunter/model.py     the snapshot: regions, modules, threads (no Windows needed)
ghosthunter/pe.py        enough PE parsing to rebuild what a DLL's code should be in memory
ghosthunter/analyze.py   the checks
ghosthunter/cli.py       output, grouping, --json, --dump
tests/                   synthetic snapshots, a PE builder, and the live harmless target
```

## License

MIT © kira
