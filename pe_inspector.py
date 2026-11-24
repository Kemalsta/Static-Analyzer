"""
pe_inspector.py - Static PE (Portable Executable) header inspector.

Reads bytes only. Never executes, loads, or modifies the file.

Design rule: NEVER trust a field in the file. Every offset and size is
validated against the real file length before it is used, and any structural
problem raises NotPE (a clean, catchable error) instead of crashing.

Public API (for integration with the entropy / IOC modules in Part 2):
    inspect_pe(data: bytes) -> dict      main entry point, raises NotPE
    rva_to_offset(sections, rva) -> int | None
    section_bytes(data, section) -> bytes
"""
from __future__ import annotations

import struct
import time
from datetime import datetime, timezone

MAX_SECTIONS = 96          # Windows loader limit; protects against absurd counts
DOS_HEADER_SIZE = 64
COFF_HEADER_SIZE = 20
SECTION_ENTRY_SIZE = 40
MAX_DATA_DIRS = 16


class NotPE(Exception):
    """Raised when the input is not a (valid, parseable) PE file."""


# --------------------------------------------------------------------------
# Lookup tables
# --------------------------------------------------------------------------
MACHINE_TYPES = {
    0x0000: "Unknown / any",
    0x014C: "x86 (i386)",
    0x0200: "Itanium (IA-64)",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64",
}

COFF_CHARACTERISTICS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0010: "AGGRESSIVE_WS_TRIM",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x0400: "REMOVABLE_RUN_FROM_SWAP",
    0x0800: "NET_RUN_FROM_SWAP",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

SUBSYSTEMS = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console (CUI)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows boot application",
}

DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE (ASLR)",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT (DEP)",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DATA_DIRECTORY_NAMES = [
    "Export", "Import", "Resource", "Exception", "Security (Certificate)",
    "Base Relocation", "Debug", "Architecture", "Global Ptr", "TLS",
    "Load Config", "Bound Import", "IAT", "Delay Import",
    "CLR Runtime Header", "Reserved",
]

STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".xdata", ".bss", ".tls", ".crt", ".didat", ".gfids",
    ".debug", ".sdata", ".CRT", "CODE", "DATA", "BSS", ".code", ".orpc",
}

# Section-name prefixes commonly left behind by packers/protectors.
PACKER_SECTION_HINTS = {
    "UPX": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
    ".themida": "Themida", ".vmp": "VMProtect", ".mpress": "MPRESS",
    ".enigma": "Enigma Protector", ".nsp": "NsPack", ".packed": "generic packer",
}

# Optional header layouts: (struct format, field names, fixed size in bytes)
_PE32_FIELDS = [
    "magic", "major_linker_version", "minor_linker_version",
    "size_of_code", "size_of_initialized_data", "size_of_uninitialized_data",
    "address_of_entry_point", "base_of_code", "base_of_data", "image_base",
    "section_alignment", "file_alignment",
    "major_os_version", "minor_os_version",
    "major_image_version", "minor_image_version",
    "major_subsystem_version", "minor_subsystem_version",
    "win32_version_value", "size_of_image", "size_of_headers", "checksum",
    "subsystem", "dll_characteristics",
    "size_of_stack_reserve", "size_of_stack_commit",
    "size_of_heap_reserve", "size_of_heap_commit",
    "loader_flags", "number_of_rva_and_sizes",
]
_PE32_FMT = "<HBB7I2I6H4I2H4I2I"          # 96 bytes
_PE32PLUS_FIELDS = [f for f in _PE32_FIELDS if f != "base_of_data"]
_PE32PLUS_FMT = "<HBB5IQ2I6H4I2H4Q2I"      # 112 bytes

assert struct.calcsize(_PE32_FMT) == 96
assert struct.calcsize(_PE32PLUS_FMT) == 112
assert len(_PE32_FIELDS) == 30 and len(_PE32PLUS_FIELDS) == 29


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _unpack(fmt: str, data: bytes, offset: int, what: str):
    """Bounds-checked struct.unpack_from. Raises NotPE instead of struct.error."""
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise NotPE(
            f"File truncated while reading {what} "
            f"(needs {size} bytes at offset 0x{max(offset, 0):X}, file is {len(data)} bytes)"
        )
    return struct.unpack_from(fmt, data, offset)


def decode_flags(value: int, table: dict) -> list:
    return [name for bit, name in table.items() if value & bit]


def _fmt_timestamp(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "invalid"


def _add(findings: list, severity: str, message: str) -> None:
    findings.append({"severity": severity, "message": message})


# --------------------------------------------------------------------------
# Header parsers
# --------------------------------------------------------------------------
def parse_dos_header(data: bytes) -> dict:
    if len(data) < DOS_HEADER_SIZE:
        raise NotPE(f"File too small for a DOS header ({len(data)} bytes, need {DOS_HEADER_SIZE})")
    if data[:2] != b"MZ":
        raise NotPE("Missing 'MZ' signature - this is not a PE file")
    names = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc",
             "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs",
             "e_lfarlc", "e_ovno"]
    values = struct.unpack_from("<14H", data, 0)
    dos = dict(zip(names, values))
    dos["e_magic"] = "MZ"
    dos["e_lfanew"] = struct.unpack_from("<I", data, 0x3C)[0]
    return dos


def parse_coff_header(data: bytes, offset: int) -> dict:
    (machine, nsections, timestamp, symtab_ptr, nsymbols,
     size_opt, characteristics) = _unpack("<HHIIIHH", data, offset, "COFF/File header")
    return {
        "offset": offset,
        "machine": machine,
        "machine_name": MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})"),
        "number_of_sections": nsections,
        "time_date_stamp": timestamp,
        "time_date_stamp_utc": _fmt_timestamp(timestamp),
        "pointer_to_symbol_table": symtab_ptr,
        "number_of_symbols": nsymbols,
        "size_of_optional_header": size_opt,
        "characteristics": characteristics,
        "characteristics_flags": decode_flags(characteristics, COFF_CHARACTERISTICS),
        "is_dll": bool(characteristics & 0x2000),
    }


def parse_optional_header(data: bytes, offset: int, declared_size: int, warnings: list):
    """Return (optional_header_dict | None, data_directories_list)."""
    if declared_size == 0:
        warnings.append("SizeOfOptionalHeader is 0 (object file or stripped header)")
        return None, []

    available = min(declared_size, max(len(data) - offset, 0))
    if available < declared_size:
        warnings.append(
            f"Optional header truncated: declared {declared_size} bytes, only {available} in file"
        )
    if available < 2:
        warnings.append("Optional header too small to contain a magic value")
        return None, []

    magic = struct.unpack_from("<H", data, offset)[0]
    if magic == 0x10B:
        fmt, names, fixed, kind = _PE32_FMT, _PE32_FIELDS, 96, "PE32"
    elif magic == 0x20B:
        fmt, names, fixed, kind = _PE32PLUS_FMT, _PE32PLUS_FIELDS, 112, "PE32+ (64-bit)"
    else:
        raise NotPE(f"Unknown optional header magic 0x{magic:04X} (expected 0x10B or 0x20B)")

    if available < fixed:
        warnings.append(
            f"Optional header ({available} bytes) smaller than the standard {fixed} bytes for {kind}; "
            "skipping its fields"
        )
        return None, []

    opt = dict(zip(names, struct.unpack_from(fmt, data, offset)))
    opt["offset"] = offset
    opt["format"] = kind
    opt["subsystem_name"] = SUBSYSTEMS.get(opt["subsystem"], f"Unknown ({opt['subsystem']})")
    opt["dll_characteristics_flags"] = decode_flags(opt["dll_characteristics"], DLL_CHARACTERISTICS)

    # Data directories (16 x 8 bytes) follow the fixed part.
    declared_dirs = opt["number_of_rva_and_sizes"]
    if declared_dirs > MAX_DATA_DIRS:
        warnings.append(f"NumberOfRvaAndSizes is {declared_dirs} (normally 16); capped at {MAX_DATA_DIRS}")
    room = (available - fixed) // 8
    count = min(declared_dirs, MAX_DATA_DIRS, room)
    dirs = []
    for i in range(count):
        rva, size = struct.unpack_from("<II", data, offset + fixed + i * 8)
        if rva or size:
            dirs.append({"index": i, "name": DATA_DIRECTORY_NAMES[i], "rva": rva, "size": size})
    return opt, dirs


def parse_sections(data: bytes, table_offset: int, count: int, warnings: list) -> list:
    if count > MAX_SECTIONS:
        warnings.append(f"NumberOfSections is {count}; only the first {MAX_SECTIONS} are parsed")
        count = MAX_SECTIONS
    sections = []
    for i in range(count):
        off = table_offset + i * SECTION_ENTRY_SIZE
        if off + SECTION_ENTRY_SIZE > len(data):
            warnings.append(f"Section table truncated: only {i} of {count} entries are present in the file")
            break
        (raw_name, vsize, vaddr, rsize, rptr, relptr, lineptr,
         nreloc, nline, chars) = struct.unpack_from("<8sIIIIIIHHI", data, off)
        name_bytes = raw_name.rstrip(b"\x00")
        printable = all(32 <= b < 127 for b in name_bytes)
        sections.append({
            "index": i,
            "name": name_bytes.decode("ascii", errors="replace"),
            "name_printable": printable,
            "virtual_size": vsize,
            "virtual_address": vaddr,
            "raw_size": rsize,
            "raw_pointer": rptr,
            "pointer_to_relocations": relptr,
            "pointer_to_linenumbers": lineptr,
            "number_of_relocations": nreloc,
            "number_of_linenumbers": nline,
            "characteristics": chars,
            "flags": decode_flags(chars, SECTION_FLAGS),
            "readable": bool(chars & IMAGE_SCN_MEM_READ),
            "writable": bool(chars & IMAGE_SCN_MEM_WRITE),
            "executable": bool(chars & IMAGE_SCN_MEM_EXECUTE),
        })
    return sections


# --------------------------------------------------------------------------
# Helpers for later modules (entropy, IOC extraction)
# --------------------------------------------------------------------------
def rva_to_offset(sections: list, rva: int):
    """Translate a Relative Virtual Address to a file offset (None if unmapped)."""
    for s in sections:
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= rva < s["virtual_address"] + span:
            delta = rva - s["virtual_address"]
            if delta < s["raw_size"]:
                return s["raw_pointer"] + delta
            return None  # inside the section in memory, but not backed by file data
    return None


def section_bytes(data: bytes, section: dict) -> bytes:
    """Raw bytes of a section, clamped to the real file length (safe for malformed files)."""
    start = section["raw_pointer"]
    end = min(start + section["raw_size"], len(data))
    return data[start:end] if start < len(data) else b""


# --------------------------------------------------------------------------
# Heuristic analysis (hints, NOT verdicts)
# --------------------------------------------------------------------------
def _analyze(info: dict, file_size: int) -> None:
    findings = info["findings"]
    coff, opt, sections = info["coff_header"], info["optional_header"], info["sections"]

    if info["dos_header"]["e_lfanew"] < DOS_HEADER_SIZE:
        _add(findings, "MEDIUM", "PE header overlaps the DOS header (e_lfanew < 0x40) - unusual, seen in crafted files")

    # Timestamp
    ts = coff["time_date_stamp"]
    if ts == 0:
        _add(findings, "INFO", "Compile timestamp is zero (stripped, or a reproducible build)")
    elif ts > time.time() + 86400:
        _add(findings, "MEDIUM", f"Compile timestamp is in the future ({coff['time_date_stamp_utc']}) - possibly forged")
    elif ts < 631152000:  # 1990-01-01
        _add(findings, "LOW", f"Compile timestamp predates 1990 ({coff['time_date_stamp_utc']}) - likely forged or corrupt")

    if not sections:
        _add(findings, "MEDIUM", "File has zero sections")

    # Per-section checks
    for s in sections:
        label = s["name"] if s["name_printable"] and s["name"] else f"#{s['index']}"
        if not s["name_printable"]:
            _add(findings, "MEDIUM", f"Section #{s['index']} has non-printable characters in its name")
        if s["writable"] and s["executable"]:
            _add(findings, "HIGH", f"Section {label} is both WRITABLE and EXECUTABLE (self-modifying / unpacking code pattern)")
        if s["raw_pointer"] + s["raw_size"] > file_size:
            _add(findings, "MEDIUM", f"Section {label} raw data extends past end of file (truncated or tampered)")
        if s["executable"] and s["raw_size"] == 0:
            _add(findings, "MEDIUM", f"Executable section {label} has no raw data (code may be created at runtime)")
        elif s["raw_size"] and s["virtual_size"] > 10 * s["raw_size"] and s["virtual_size"] > 0x10000:
            _add(findings, "LOW", f"Section {label} virtual size is >10x its raw size (possible unpacking space)")
        for prefix, packer in PACKER_SECTION_HINTS.items():
            if s["name"].lower().startswith(prefix.lower()):
                _add(findings, "MEDIUM", f"Section name {label} is associated with the {packer} packer/protector")
                break
        else:
            if s["name_printable"] and s["name"] and s["name"] not in STANDARD_SECTION_NAMES:
                _add(findings, "INFO", f"Non-standard section name: {label}")

    # Entry point
    if opt is not None:
        ep = opt["address_of_entry_point"]
        info["entry_point_rva"] = ep
        if ep == 0:
            if not coff["is_dll"]:
                _add(findings, "LOW", "Entry point RVA is 0 in a non-DLL image")
        else:
            host = None
            for s in sections:
                span = max(s["virtual_size"], s["raw_size"])
                if s["virtual_address"] <= ep < s["virtual_address"] + span:
                    host = s
                    break
            if host is None:
                _add(findings, "HIGH", f"Entry point RVA 0x{ep:X} lies outside every section")
            else:
                info["entry_point_section"] = host["name"]
                if not host["executable"]:
                    _add(findings, "MEDIUM", f"Entry point is in section {host['name']} which is not marked executable")
                if sections and host is max(sections, key=lambda x: x["virtual_address"]) and len(sections) > 1:
                    _add(findings, "MEDIUM", f"Entry point is in the LAST section ({host['name']}) - common in packed or infected files")

        # Exploit-mitigation flags (informational)
        flags = opt["dll_characteristics_flags"]
        if not any(f.startswith("DYNAMIC_BASE") for f in flags):
            _add(findings, "INFO", "ASLR (DYNAMIC_BASE) is not enabled")
        if not any(f.startswith("NX_COMPAT") for f in flags):
            _add(findings, "INFO", "DEP (NX_COMPAT) is not enabled")

    # Overlay: bytes after the last section's raw data
    backed = [s["raw_pointer"] + s["raw_size"] for s in sections if s["raw_size"] > 0]
    if backed:
        end = max(backed)
        if end < file_size:
            info["overlay_size"] = file_size - end
            info["overlay_offset"] = end
            _add(findings, "INFO",
                 f"{info['overlay_size']} bytes of overlay data after the last section "
                 "(could be an Authenticode signature, installer payload, or appended data)")


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def inspect_pe(data: bytes) -> dict:
    """
    Parse DOS header, PE signature, COFF header, Optional header, data
    directories and the section table.

    Raises NotPE for anything that is not a parseable PE.
    All other problems are collected in info['warnings'] / info['findings'].
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise NotPE("Input must be bytes")
    data = bytes(data)

    warnings: list = []
    findings: list = []

    dos = parse_dos_header(data)
    e_lfanew = dos["e_lfanew"]
    if e_lfanew + 4 > len(data):
        raise NotPE(f"e_lfanew (0x{e_lfanew:X}) points outside the file ({len(data)} bytes)")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise NotPE(f"Missing 'PE\\0\\0' signature at offset 0x{e_lfanew:X}")

    coff = parse_coff_header(data, e_lfanew + 4)
    opt_offset = e_lfanew + 4 + COFF_HEADER_SIZE
    opt, ddirs = parse_optional_header(data, opt_offset, coff["size_of_optional_header"], warnings)

    sections = parse_sections(
        data, opt_offset + coff["size_of_optional_header"], coff["number_of_sections"], warnings
    )

    info = {
        "file_size": len(data),
        "dos_header": dos,
        "pe_signature_offset": e_lfanew,
        "coff_header": coff,
        "optional_header": opt,
        "data_directories": ddirs,
        "sections": sections,
        "entry_point_rva": None,
        "entry_point_section": None,
        "overlay_size": 0,
        "overlay_offset": None,
        "findings": findings,
        "warnings": warnings,
    }
    _analyze(info, len(data))
    return info