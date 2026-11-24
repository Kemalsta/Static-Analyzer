"""
safety.py - Ethical guardrails for the Static Malware Analyzer.

Covers the rubric items:
  * Safe Defaults & Kill Switch  -> KillSwitch, ensure_safe_sample, size/file caps
  * Legal Disclaimer & RoE       -> DISCLAIMER, confirm_disclaimer
  * Data Handling                -> scope enforcement, read-only helpers, output guard
"""
from __future__ import annotations

import signal
import struct
import sys
import threading
from pathlib import Path


def eprint(*args, **kwargs):
    """All tool messages go to stderr so stdout stays clean for --json."""
    print(*args, file=sys.stderr, **kwargs)


# --------------------------------------------------------------------------
# Legal disclaimer + Rules of Engagement
# --------------------------------------------------------------------------
DISCLAIMER = """
==============================================================================
  LEGAL NOTICE & RULES OF ENGAGEMENT
==============================================================================
  This tool performs STATIC analysis only: it reads file bytes and reports
  PE header information. It never executes, loads or modifies a file.

  Under Malaysia's Computer Crimes Act 1997 (Akta Kesalahan Komputer 1997),
  unauthorised access to computer material (s.3), unauthorised modification
  of computer contents (s.5) and related acts are criminal offences. Other
  countries have similar laws.

  By continuing you confirm that:
    1. You OWN every file you analyse, or have EXPLICIT WRITTEN PERMISSION
       from its owner to analyse it.
    2. Your use is lawful and educational / defensive (e.g. coursework,
       incident response, research in an isolated lab).
    3. You will stay inside the declared scope (--scope-root); the tool
       refuses any path outside it.
    4. You will not use results to harm, extort or attack anyone.
    5. Vulnerabilities or live malware you discover will be reported
       responsibly (to the vendor or a national CERT, e.g. MyCERT in
       Malaysia) and not published carelessly.

  Press Ctrl+C at any time to abort safely.
  This notice is not legal advice. Ask your institution if unsure.
==============================================================================
"""

ACCEPT_PHRASE = "I AGREE"


def confirm_disclaimer(input_fn=input) -> bool:
    """Show the disclaimer and require the user to type the acceptance phrase."""
    eprint(DISCLAIMER)
    try:
        eprint(f'Type "{ACCEPT_PHRASE}" to continue (anything else exits): ', end="", flush=True)
        answer = input_fn()
    except (EOFError, KeyboardInterrupt):
        eprint()
        return False
    return answer.strip().upper() == ACCEPT_PHRASE


# --------------------------------------------------------------------------
# Kill switch
# --------------------------------------------------------------------------
class AbortRequested(Exception):
    """Raised by KillSwitch.check() once the user has asked to stop."""


class KillSwitch:
    """
    Ctrl+C (SIGINT) / SIGTERM sets a flag. Long-running loops call check()
    and unwind cleanly. A SECOND Ctrl+C forces an immediate exit.
    """

    def __init__(self):
        self._event = threading.Event()
        self._presses = 0

    def install(self):
        signal.signal(signal.SIGINT, self._handler)
        try:
            signal.signal(signal.SIGTERM, self._handler)
        except (ValueError, OSError, AttributeError):
            pass  # not available on every platform / thread

    def _handler(self, signum, frame):
        self._presses += 1
        if self._presses >= 2:
            raise KeyboardInterrupt
        self._event.set()
        eprint("\n[!] KILL SWITCH: stopping after the current step "
               "(press Ctrl+C again to force quit)...")

    def trigger(self):
        self._event.set()

    @property
    def aborted(self) -> bool:
        return self._event.is_set()

    def check(self):
        if self._event.is_set():
            raise AbortRequested()

    def sleep(self, seconds: float):
        """Interruptible sleep: wakes immediately when the kill switch fires."""
        if seconds > 0:
            self._event.wait(seconds)
        self.check()


# --------------------------------------------------------------------------
# Scope enforcement
# --------------------------------------------------------------------------
class ScopeError(Exception):
    """Target is outside the permitted scope (or invalid)."""


def in_scope(target, root) -> bool:
    """True if `target` is `root` or lives under it. Uses resolved real paths so
    '../' tricks and symlinks cannot escape the scope."""
    t, r = Path(target).resolve(), Path(root).resolve()
    return t == r or r in t.parents


def check_scope(target, root) -> Path:
    root_p = Path(root)
    if not root_p.is_dir():
        raise ScopeError(f"Scope root is not an existing directory: {root}")
    if not Path(target).exists():
        raise ScopeError(f"Target not found: {target}")
    if not in_scope(target, root):
        raise ScopeError(
            f"REFUSED: target '{Path(target).resolve()}' is outside the permitted scope "
            f"'{root_p.resolve()}'"
        )
    return Path(target).resolve()


def enumerate_targets(target: Path, scope_root, recursive: bool, max_files: int):
    """
    Return (files, notes). A single file yields [file]. A directory yields its
    regular files (optionally recursive), capped at max_files. Every file is
    re-checked against the scope so a symlink inside the directory cannot
    escape it.
    """
    notes = []
    if target.is_file():
        return [target], notes

    if not target.is_dir():
        raise ScopeError(f"Target is neither a file nor a directory: {target}")

    iterator = target.rglob("*") if recursive else target.iterdir()
    files = []
    for p in sorted(iterator):
        try:
            if not p.is_file():
                continue
            if not in_scope(p, scope_root):
                notes.append(f"Skipped (resolves outside scope): {p}")
                continue
        except OSError as exc:
            notes.append(f"Skipped (cannot access): {p} ({exc})")
            continue
        files.append(p.resolve())
        if len(files) >= max_files:
            notes.append(f"File limit reached ({max_files}); remaining files were not analysed")
            break
    return files, notes


# --------------------------------------------------------------------------
# Data handling
# --------------------------------------------------------------------------
def check_output_path(out_path, analysed_files) -> Path:
    """Refuse to overwrite anything. Reports must go to a NEW file."""
    out = Path(out_path).resolve()
    if out.exists():
        raise ScopeError(f"Refusing to overwrite existing file: {out}")
    if out in {Path(f).resolve() for f in analysed_files}:
        raise ScopeError("Output path may not be a file being analysed")
    if not out.parent.is_dir():
        raise ScopeError(f"Output directory does not exist: {out.parent}")
    return out


# --------------------------------------------------------------------------
# Safe default test target
# --------------------------------------------------------------------------
def build_safe_sample() -> bytes:
    """
    Build a tiny, harmless, hand-made 32-bit PE entirely in memory: one .text
    section containing a single 'ret' byte. It is NOT meant to be run and is
    saved with a '.pe' extension so it cannot be double-clicked by accident.
    """
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)           # e_lfanew

    coff = struct.pack("<HHIIIHH",
                       0x014C,                          # Machine: x86
                       1,                               # NumberOfSections
                       1700000000,                      # fixed timestamp (2023-11-14)
                       0, 0,
                       224,                             # SizeOfOptionalHeader
                       0x0102)                          # EXECUTABLE_IMAGE | 32BIT_MACHINE

    opt = struct.pack("<HBB7I2I6H4I2H4I2I",
                      0x10B, 14, 0,
                      0x200, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000,
                      0x1000, 0x200,
                      6, 0, 0, 0, 6, 0,
                      0, 0x2000, 0x200, 0,
                      3, 0x8140,                        # console, ASLR | DEP | TS-aware
                      0x100000, 0x1000, 0x100000, 0x1000,
                      0, 16)
    opt += b"\x00" * (16 * 8)                           # empty data directories

    section = struct.pack("<8sIIIIIIHHI",
                          b".text", 1, 0x1000, 0x200, 0x200, 0, 0, 0, 0,
                          0x60000020)                   # CODE | EXECUTE | READ

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + section
    headers = headers.ljust(0x200, b"\x00")
    body = (b"\xC3" + b"\x00" * 0x1FF)                  # 'ret' + padding
    return headers + body


def ensure_safe_sample(path: Path) -> Path:
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(build_safe_sample())
    return path