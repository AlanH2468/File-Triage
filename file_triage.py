"""Local-only SHA-256 file triage for safe teaching samples (COMP H2702)."""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def load_references(csv_path):
    """Load and validate reference hashes; skip malformed rows with warnings."""
    references = {}
    warnings = []
    try:
        with csv_path.open('r', newline='', encoding='utf-8-sig') as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or not {'sha256', 'label'} <= set(reader.fieldnames):
                raise ValueError('CSV must have sha256 and label columns')
            for number, row in enumerate(reader, start=2):
                digest = (row.get('sha256') or '').strip().lower()
                label = (row.get('label') or '').strip()
                if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest) or not label:
                    warnings.append(f'Invalid reference row {number}; skipped')
                    continue
                if digest in references and references[digest] != label:
                    warnings.append(f'Conflicting reference row {number}; kept first label')
                    continue
                references[digest] = label
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        warnings.append(f'Could not load reference file {csv_path}: {error}')
    return references, warnings


def sha256_file(path):
    """Hash in chunks so even large files do not need to fit in memory."""
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def analyse_folder(folder, references):
    """Inventory every regular file in the chosen sample folder."""
    records, warnings = [], []
    try:
        files = sorted((p for p in folder.iterdir() if p.is_file()), key=lambda p: p.name.lower())
    except OSError as error:
        return records, [f'Could not list folder {folder}: {error}']
    for path in files:
        try:
            stat = path.stat()
            digest = sha256_file(path)
            records.append({
                'filename': path.name,
                'extension': path.suffix.lower() or '(none)',
                'size_bytes': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec='seconds'),
                'sha256': digest,
                'status': 'KNOWN' if digest in references else 'UNKNOWN',
                'reference_label': references.get(digest, ''),
            })
        except (OSError, PermissionError) as error:
            warnings.append(f'Unable to analyse {path.name}: {error}')
    return records, warnings


def find_duplicates(records):
    """Group files with identical content hashes (not merely matching names)."""
    grouped = defaultdict(list)
    for record in records:
        grouped[record['sha256']].append(record['filename'])
    return [{'sha256': digest, 'files': names} for digest, names in grouped.items() if len(names) > 1]


def make_summary(records, duplicates, warnings):
    known = sum(r['status'] == 'KNOWN' for r in records)
    return {
        'total_files': len(records), 'known_files': known,
        'unknown_files': len(records) - known,
        'duplicate_groups': len(duplicates), 'warnings': len(warnings),
    }


def format_report(records, duplicates, warnings):
    summary = make_summary(records, duplicates, warnings)
    lines = ['FILE TRIAGE & SHA-256 INVESTIGATION', '=' * 44,
             f"Files analysed: {summary['total_files']}",
             f"KNOWN: {summary['known_files']} | UNKNOWN: {summary['unknown_files']}",
             f"Duplicate groups: {summary['duplicate_groups']}", '']
    for r in records:
        lines += [f"File: {r['filename']}",
                  f"  Extension: {r['extension']} | Size: {r['size_bytes']} bytes",
                  f"  Modified: {r['modified']}",
                  f"  SHA-256: {r['sha256']}",
                  f"  Status: {r['status']}" + (f" ({r['reference_label']})" if r['reference_label'] else ''), '']
    lines.append('DUPLICATE CONTENT GROUPS')
    lines += [f"- {', '.join(d['files'])} (SHA-256 {d['sha256']})" for d in duplicates] or ['None found']
    lines += ['', 'SECURITY INTERPRETATION',
              'KNOWN means the hash matched the supplied reference list; it is not a safety guarantee.',
              'UNKNOWN means no reference match; it does not prove a file is malicious.',
              'Duplicate hashes indicate identical file content even when names differ.',
              'A hash alone does not explain file behaviour or detect every threat.', '', 'WARNINGS']
    lines += warnings or ['None']
    return '\n'.join(lines) + '\n'


def save_reports(output_folder, records, duplicates, warnings):
    """Save a readable TXT and machine-readable CSV/JSON report."""
    output_folder.mkdir(parents=True, exist_ok=True)
    (output_folder / 'triage_report.txt').write_text(format_report(records, duplicates, warnings), encoding='utf-8')
    with (output_folder / 'triage_results.csv').open('w', newline='', encoding='utf-8') as handle:
        columns = ['filename', 'extension', 'size_bytes', 'modified', 'sha256', 'status', 'reference_label']
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)
    payload = {'summary': make_summary(records, duplicates, warnings),
               'files': records, 'duplicate_groups': duplicates, 'warnings': warnings}
    (output_folder / 'triage_results.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')


def main():
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='Safely triage files using SHA-256 and a local reference CSV.')
    parser.add_argument('folder', nargs='?', type=Path, default=base / 'samples', help='Folder containing safe sample files')
    parser.add_argument('--references', type=Path, default=base / 'hashes_reference.csv', help='Reference CSV')
    parser.add_argument('--output', type=Path, default=base / 'output', help='Output report folder')
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error(f'Sample folder does not exist: {args.folder}')
    references, reference_warnings = load_references(args.references)
    records, file_warnings = analyse_folder(args.folder, references)
    warnings = reference_warnings + file_warnings
    duplicates = find_duplicates(records)
    print(format_report(records, duplicates, warnings))
    try:
        save_reports(args.output, records, duplicates, warnings)
        print(f'Reports saved to: {args.output.resolve()}')
    except OSError as error:
        print(f'ERROR: Could not save reports: {error}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
