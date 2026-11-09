"""ghost-hunter: find code injected into running Windows processes. Read-only.
Exit codes: 0 nothing at or above --fail-on · 1 findings · 2 could not run."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .model import RANK, SEVERITIES, Finding, Process

ICON = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "info": "·"}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ghost-hunter",
                                 description="Find code injected into running Windows processes: reflective DLLs, "
                                             "shellcode threads, hollowed processes, hooks and stomped modules.")
    ap.add_argument("--pid", type=int, action="append", default=[], help="scan this process (repeatable); default: all")
    ap.add_argument("--name", action="append", default=[], help="scan processes with this exe name (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this (default: low)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high", help="exit 1 at or above this (default: high)")
    ap.add_argument("--dump", metavar="DIR", help="save suspicious memory regions here for offline analysis")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _ansi(enabled: bool):
    if enabled and os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x4)
    return (lambda s, c: f"\x1b[{c}m{s}\x1b[0m") if enabled else (lambda s, c: s)


def _hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b[:16])


def render(results: list[tuple[Process, list[Finding]]], skipped: int, elapsed: float, min_sev: str, color: bool) -> str:
    paint = _ansi(color)
    lines = [paint(f" ghost-hunter v{__version__}", "1;36") +
             paint(f"  ·  {len(results)} processes  ·  {elapsed:.1f}s", "2"), ""]
    counts = dict.fromkeys(SEVERITIES, 0)
    # the same medium/low finding in many processes is one system-wide tool (an overlay, a theming engine),
    # not many separate events: show it once
    seen: dict[tuple, list[tuple[Process, Finding]]] = {}
    for proc, findings in results:
        for f in findings:
            if RANK[f.severity] >= RANK["medium"]:
                seen.setdefault((f.rule, f.severity, f.title), []).append((proc, f))
    wide = {k for k, v in seen.items() if len({p.pid for p, _ in v}) >= 4}
    shown_wide = [k for k in wide if RANK[k[1]] <= RANK[min_sev]]
    if shown_wide:
        lines.append(paint(" across many processes", "1") + paint("  (one tool, not separate events)", "2"))
        for k in sorted(shown_wide, key=lambda k: (RANK[k[1]], -len(seen[k]))):
            f = seen[k][0][1]
            n = len({p.pid for p, _ in seen[k]})
            lines.append(f"   {paint(f'{ICON[f.severity]} {f.severity.upper():<8}', COLOR[f.severity])} {f.title}"
                         + paint(f"  in {n} processes", "2"))
            lines.append(paint(f"              └ {f.detail}", "2"))
        lines.append("")
    for proc, findings in results:
        for f in findings:
            counts[f.severity] += 1
        shown = [f for f in findings if RANK[f.severity] <= RANK[min_sev] and (f.rule, f.severity, f.title) not in wide]
        if not shown:
            continue
        arch = " (32-bit)" if proc.wow64 else ""
        lines.append(paint(f" {proc.name}", "1") + paint(f"  pid {proc.pid}{arch}  {proc.path or ''}", "2"))
        for f in shown:
            where = f"  {f.address:#x}" if f.address is not None else ""
            tech = f"  {f.technique}" if f.technique else ""
            lines.append(f"   {paint(f'{ICON[f.severity]} {f.severity.upper():<8}', COLOR[f.severity])} {f.title}"
                         + paint(where + tech, "2"))
            lines.append(paint(f"              └ {f.detail}", "2"))
            if f.preview and RANK[f.severity] <= RANK["high"]:
                lines.append(paint(f"                {_hex(f.preview)}", "35"))
        lines.append("")
    if skipped:
        lines.append(paint(f" {skipped} processes could not be opened (protected processes; without administrator rights, also other users' and system processes)", "2"))
    summary = "  ·  ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "nothing injected found"
    lines.append(paint(f" {summary}", "1"))
    return "\n".join(lines) + "\n"


def dump(proc: Process, findings: list[Finding], folder: str) -> list[str]:
    os.makedirs(folder, exist_ok=True)
    written = []
    for f in findings:
        if f.address is None or not f.size or RANK[f.severity] > RANK["high"] or f.rule in ("modified-code",):
            continue
        r = proc.region_at(f.address)
        size = min(f.size, 64 << 20)
        data = proc.read(f.address if r is None else r.alloc_base, size)
        path = os.path.join(folder, f"{proc.name}_{proc.pid}_{f.address:#x}_{f.rule}.bin")
        with open(path, "wb") as fh:
            fh.write(data)
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):   # a piped Windows console is cp1252: never crash on a glyph
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    if sys.platform != "win32":
        print("ghost-hunter: this scans live Windows processes, so it needs Windows", file=sys.stderr)
        return 2
    from . import collect
    from .analyze import Context, analyze

    started = time.perf_counter()
    ctx = Context()
    threads = collect.all_threads()
    names = {n.lower() for n in args.name}
    targets = [(pid, name) for pid, name, _ in collect.list_processes()
               if pid not in (0, 4) and pid != os.getpid()
               and (not args.pid and not names or pid in args.pid or name.lower() in names)]
    results, skipped, dumped = [], 0, []
    for pid, name in targets:
        try:
            proc, lp = collect.snapshot(pid, name, threads)
        except OSError:
            skipped += 1
            continue
        with lp:
            try:
                findings = analyze(proc, ctx)
            except OSError:
                skipped += 1
                continue
            if args.dump:
                dumped += dump(proc, findings, args.dump)
        results.append((proc, findings))
    elapsed = time.perf_counter() - started
    if (args.pid or names) and not results:
        print("ghost-hunter: no matching process could be opened", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"version": __version__, "skipped": skipped, "processes": [
            {"pid": p.pid, "name": p.name, "path": p.path, "wow64": p.wow64,
             "findings": [f.to_dict() for f in fs]} for p, fs in results]}, indent=2))
    else:
        color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        sys.stdout.write(render(results, skipped, elapsed, args.min_severity, color))
        if dumped:
            print(f" dumped {len(dumped)} region(s) to {args.dump}")
    worst = min((RANK[f.severity] for _, fs in results for f in fs), default=99)
    return 1 if worst <= RANK[args.fail_on] else 0
