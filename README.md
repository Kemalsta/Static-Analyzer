# Static-Analyzer
Cyber Forensic Assignment

**Static-Analyzer** (`static-malware-analyzer`, version `1.0.0-part1`) is a static Windows Portable Executable (PE) header inspector and safety-guarded triage CLI written in Python using the standard library. It reads target files strictly in read-only binary mode (`"rb"`) and **never** executes, loads, or modifies analysed files.

---

## Description

`Static-Analyzer` parses binary structures and produces structural warnings and non-verdict heuristic hints across three core modules:

* **`main.py` (CLI & Reporting):** Parses command-line options (`-t`/`--target`, `--scope-root`, `-r`/`--recursive`, `--max-files`, `--max-size-mb`, `--delay`, `--json`, `-o`/`--output`, `--version`), enforces the upfront legal disclaimer and scope/output guards, hashes files (`SHA-256` and `MD5`), and outputs human-readable text reports or structured JSON.
* **`pe_inspector.py` (Bounds-Checked PE Parser & Heuristic Checks):** Validates and parses the DOS header (`MZ`, `e_lfanew`), `'PE\0\0'` signature, COFF/File header, Optional header (`PE32` `0x10B` and `PE32+` `0x20B`), non-empty data directories, section table (capped at `MAX_SECTIONS = 96`), and trailing overlay data. Exposes `inspect_pe()`, `rva_to_offset()`, and `section_bytes()`, and records heuristic hints (`HIGH`, `MEDIUM`, `LOW`, `INFO`) alongside parser warnings.
* **`safety.py` (Guardrails & Sample Generator):** Provides the interactive legal disclaimer (`confirm_disclaimer()`), two-stage `KillSwitch` (`SIGINT`/`SIGTERM`), resolved-path scope validation (`in_scope()`, `check_scope()`, `enumerate_targets()`), non-destructive output checking (`check_output_path()`), `stderr` logging (`eprint()`), and `build_safe_sample()` / `ensure_safe_sample()` to create a minimal 32-bit `.pe` test file containing a single `ret` (`0xC3`) instruction.

---

## Attack Category

* **Primary Category:** Static Malware Triage & PE Structural / Evasion Indicator Analysis
* **Detected Structural & Heuristic Indicators:**
  * **Packer / Protector Hints:** Section names matching known packers/protectors (`UPX`, `.aspack`, `.adata`, `.petite`, `.themida`, `.vmp`, `.mpress`, `.enigma`, `.nsp`, `.packed`) or non-standard/non-printable section names.
  * **Suspicious Section Permissions & Sizing:** Sections marked both writable and executable (`WRITABLE` + `EXECUTABLE`), executable sections with zero raw size (`raw_size == 0`), or large `virtual_size > 10 * raw_size` (when `virtual_size > 0x10000`).
  * **Entry-Point & Header Anomalies:** Entry-point RVAs falling outside any section, landing in a non-executable section, or sitting in the last section of a multi-section file; `e_lfanew < 0x40` overlapping the DOS header; raw section data extending past file size; trailing overlay bytes; or unusual `TimeDateStamp` values (zero, far future, or pre-1990).
  * **Mitigation Flags (Informational):** Missing `DYNAMIC_BASE` (ASLR) or `NX_COMPAT` (DEP) in `DllCharacteristics`.

---

## Attack Lifecycle Mapping

Static PE header and heuristic analysis supports defensive triage and indicator mapping across early and mid-lifecycle stages (such as Lockheed Martin Cyber Kill Chain and MITRE ATT&CK):

* **Weaponization & Staging:** Identifies packer/protector section hints, appended overlay data (such as installers, archives, or embedded payloads after the last section), and anomalous compile timestamps (`TimeDateStamp`).
* **Defense Evasion:** Flags `WRITABLE` + `EXECUTABLE` sections, oversized virtual-to-raw section ratios associated with runtime unpacking/stub allocation, non-printable or unusual section names, entry points in the last section, and missing `ASLR` (`DYNAMIC_BASE`) or `DEP` (`NX_COMPAT`) mitigations.
* **Execution Preconditions & Triage Correlation:** Highlights entry-point RVAs outside sections or in non-executable sections, while computing `SHA-256` and `MD5` digests to track evidence integrity and correlate artifacts defensively.

---

## Installation

`Static-Analyzer` requires no third-party packages at runtime (Python standard library only). `requirements.txt` includes `pefile` as an optional commented dependency for cross-checking parser output during testing.

```bash
git clone [https://github.com/Kemalsta/Static-Analyzer.git](https://github.com/Kemalsta/Static-Analyzer.git)
cd Static-Analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
