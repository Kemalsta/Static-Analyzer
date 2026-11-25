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
git clone https://github.com/Kemalsta/Static-Analyzer.git
cd Static-Analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage Examples

Running `main.py` first displays the legal disclaimer and requires typing `I AGREE` before any file is analysed.

```bash
# 1. Analyse the built-in harmless sample (samples/safe_sample.pe)
python main.py

# 2. Analyse a single file within an explicit scope root
python main.py --target C:\Windows\System32\notepad.exe --scope-root C:\Windows\System32

# 3. Recursively scan a directory tree with file and size caps
python main.py -t ./my_samples --recursive --max-files 50 --max-size-mb 64

# 4. Pause 2 seconds between files to test or demonstrate the kill switch (Ctrl+C)
python main.py -t ./my_samples --delay 2

# 5. Print JSON to stdout and save to a new output file (refuses to overwrite)
python main.py --json -o output/report.json
```

### Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Completed with all targeted inputs analysed cleanly |
| `1` | Completed, but one or more files could not be parsed or no files were found |
| `2` | Disclaimer declined or input aborted before analysis began |
| `3` | Invalid numeric CLI option, target/scope error, or invalid/existing output path |
| `130` | Aborted via `KillSwitch` / `KeyboardInterrupt` |

---

## Ethical Considerations

* **Defensive & Educational Purpose Only:** Built for coursework, forensic lab triage, and authorized defensive analysis—never for unauthorized access, exploitation, or harm.
* **Hints, Not Verdicts:** Heuristic findings in `_analyze()` are structural clues, not proof of maliciousness. Legitimate compilers, installers, or protected software can trigger similar indicators, while real malware may not.
* **Data & Confidentiality Care:** Keep scanned samples and analysis outputs protected, avoid exposing sensitive paths or artifacts unintentionally, and handle discovered threats or weaknesses responsibly.

---

## Rules of Engagement (RoE)

* **Authorized Scope:** Only scan files and directories that you own or have explicit written permission / course or lab authorization to inspect. `check_scope()` and `enumerate_targets()` resolve real paths (`Path.resolve()`) and reject targets or symlinks outside `--scope-root` (which defaults to the current working directory, or the `samples` directory when using the default built-in sample).
* **Time Windows:** Execute scans and demonstrations only within approved academic lab sessions, coursework schedules, or authorized assessment windows.
* **Permitted Techniques:** Read-only binary file inspection (`"rb"`), cryptographic hashing (`SHA-256`, `MD5`), PE header/data-directory/section/overlay parsing, heuristic structural checks, and text or JSON report generation.
* **Prohibited Actions:** Never execute, inject, or run untrusted/malware binaries on host or unauthorized systems; never scan targets outside `--scope-root`; never overwrite existing files (`check_output_path()` enforces writing only to a new path); never exfiltrate or share unauthorized samples or data.
* **Emergency Stop Procedures:** Press `Ctrl+C` (`KillSwitch`) to trigger a graceful stop after the current step (`AbortRequested`, exit code `130`), or press `Ctrl+C` a second time to force an immediate exit (`KeyboardInterrupt`). If an unexpected, sensitive, or live malware artifact is encountered, stop immediately, isolate the workspace/VM, preserve logs, and report to your instructor, supervisor, or lab administrator.

---

## Responsible Disclosure

* **Who:** Report confirmed vulnerabilities, suspicious live malware, or security issues to the repository/system owner, affected software vendor or national CERT (such as **MyCERT** in Malaysia), and your course instructor or supervisor where applicable.
* **When:** Report promptly once an issue or sample is confirmed, giving owners/responders time to investigate and remediate before any public discussion or release.
* **How:** Use a private, official, or designated reporting channel with clear reproduction steps, affected versions/hashes, and impact details—do not publish exploit material, live credentials, or unredacted sensitive data.

---

## Legal Disclaimer

This tool is provided for educational and authorized security/forensic analysis purposes only. Under Malaysia's **Computer Crimes Act 1997 (Akta Kesalahan Komputer 1997)**, offences such as unauthorised access to computer material (s. 3) and unauthorised modification of computer contents (s. 5) carry serious criminal penalties, and comparable laws apply in other jurisdictions. Nothing in this repository constitutes legal advice; users are solely responsible for ensuring their actions comply with applicable laws and institutional rules.

---

## Limitations

* **Static Header & Heuristic Scope Only:** Does not execute code, unpack packed binaries dynamically, parse import/export tables in full, or compute section entropy/strings directly (though `rva_to_offset()` and `section_bytes()` are provided to support future modules).
* **False Positives & False Negatives:** Standard or legitimate binaries may trigger warnings (e.g., missing `ASLR`/`DEP`, overlay data, custom section names), while obfuscated, packed, or runtime-dependent threats may go undetected.
* **Resource & Parsing Caps:** Enforces `--max-files` (default `100`), `--max-size-mb` (default `64` MB), `MAX_SECTIONS = 96`, and `MAX_DATA_DIRS = 16`, and treats malformed or truncated inputs as `NotPE` errors or parser warnings rather than full structural analysis.
