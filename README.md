# COMP H2702 — Scenario C: File Triage & Hash Analysis

A **local, safe Python 3 tool** for inspecting teaching sample files. It inventories each file, calculates its SHA-256 hash, compares hashes with the supplied reference CSV, groups identical-content files and exports reports. **No external requests, API keys or third-party packages are needed.**

## Files
- `file_triage.py` — Python application.
- `samples/` — five original safe teaching samples supplied by the lecturer.
- `hashes_reference.csv` — lecturer-supplied reference data.
- `output/` — generated TXT, CSV and JSON results (created automatically).

## Run on Windows (PowerShell / VS Code terminal)
1. Install Python 3 if not already installed.
2. Download/unzip this project folder.
3. Open a terminal in the folder containing `file_triage.py`.
4. Run `py file_triage.py` (or `python file_triage.py` if `py` is unavailable).
5. Read the console summary and open `output/triage_report.txt`, `output/triage_results.csv` or `output/triage_results.json`.

To analyse another **safe** folder without editing the script:

```powershell
py file_triage.py "C:\path\to\safe_folder"
```

To select another reference CSV or output folder:

```powershell
py file_triage.py samples --references hashes_reference.csv --output output
```

## How it works
1. `load_references()` reads and validates reference hashes.
2. `analyse_folder()` inventories files and calls `sha256_file()`.
3. `find_duplicates()` groups identical SHA-256 values.
4. `format_report()` explains the results and their limitations.
5. `save_reports()` exports TXT, CSV and JSON. `main()` orchestrates the workflow.

The program uses lists, dictionaries, loops, conditionals, functions, file I/O and exception handling. It reads every regular file directly inside the selected folder (not nested subfolders). Invalid reference rows are skipped with warnings. Missing reference files cause a warning and files are classified UNKNOWN; the tool does **not** claim they are malicious.

## Expected results with the original teaching samples
Five files: three KNOWN (`sample_a.txt`, `sample_b.txt`, `sample_d.bin`) and two UNKNOWN (`sample_c.txt`, `sample_e.bin`). `sample_a.txt` and `sample_b.txt` have identical SHA-256 hashes despite different filenames. `sample_c.txt` has a different hash from the baseline text.

## Error-handling demonstration
Run `py file_triage.py --references missing.csv` to demonstrate a missing reference file. The program warns and continues; no file is falsely described as matching a reference. Run `py file_triage.py missing_folder` to demonstrate clear folder validation.

## Cybersecurity interpretation
A matching hash means content matches a reference entry, **not** that it is harmless. UNKNOWN means no reference match, **not** that the file is malware. Hashing is useful for integrity comparison, identifying duplicate evidence and triage prioritisation, but it does not analyse executable behaviour. These samples are safe teaching data; no files are uploaded externally.
