"""GhostTrace phase 1: deterministic source inspection and identity resolution.

Run: python code/main.py --inspect
This deliberately does not generate a guessed submission.
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from collections import defaultdict, Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / 'dataset'
TABLES = ('deletion_requests', 'user_identities', 'user_audit_log', 'system_activity', 'deletion_rules', 'evidence_files')


def read_csv(name: str) -> list[dict[str, str]]:
    with (DATASET / f'{name}.csv').open('r', encoding='utf-8-sig', newline='') as handle:
        return list(csv.DictReader(handle))


def clean(text: str) -> str:
    return (text or '').strip().casefold()


def normalize_email(text: str) -> str:
    return clean(text)


def is_deletion_request(text: str) -> bool:
    """Conservative baseline. Borderline requests go to manual/LLM adjudication."""
    text = clean(text)
    negative = [r'\bdo not delete\b', r"\bdon't delete\b", r'\bnot requesting deletion\b',
                r'\bkeep my account\b', r'\bdo not close my account\b']
    if any(re.search(p, text) for p in negative):
        return False
    affirmative = [r'\bdelete\b', r'\berase\b', r'\bremove (?:all )?(?:my|personal) data\b',
                   r'\bclose (?:my|the) account\b', r'\bforget me\b', r'\bdata deletion\b']
    return any(re.search(p, text) for p in affirmative)


class IdentityResolver:
    """Joins users through exact current and historical values; no fuzzy PII matches."""
    def __init__(self, identities: list[dict], audit_log: list[dict]):
        self.identities = {row['user_id']: row for row in identities}
        self.history = defaultdict(list)
        self.by_email = defaultdict(set)
        self.by_identifier = defaultdict(set)
        for row in identities:
            uid = row['user_id']
            self.by_identifier[('user_id', clean(uid))].add(uid)
            for field in ('email', 'email_hash', 'phone', 'name'):
                value = clean(row.get(field, ''))
                if value:
                    self.by_identifier[(field, value)].add(uid)
                    if field == 'email':
                        self.by_email[value].add(uid)
        for event in audit_log:
            uid = event.get('user_id', '')
            if not uid:
                continue
            self.history[uid].append(event)
            field = event.get('field_name', '')
            for key in ('old_value', 'new_value'):
                value = clean(event.get(key, ''))
                if value:
                    self.by_identifier[(field, value)].add(uid)
                    if field == 'email':
                        self.by_email[value].add(uid)

    def resolve(self, email: str) -> dict:
        ids = sorted(self.by_email.get(normalize_email(email), set()))
        if len(ids) != 1:
            return {'resolution': 'UNRESOLVED' if not ids else 'AMBIGUOUS', 'candidate_user_ids': ids}
        uid = ids[0]
        identifiers = defaultdict(set)
        identifiers['user_id'].add(uid)
        row = self.identities.get(uid, {})
        for field in ('name', 'email', 'phone', 'email_hash'):
            if row.get(field):
                identifiers[field].add(row[field])
        for event in self.history.get(uid, []):
            field = event.get('field_name', '')
            for value in (event.get('old_value', ''), event.get('new_value', '')):
                if value:
                    identifiers[field].add(value)
        return {'resolution': 'EXACT', 'user_id': uid,
                'identifiers': {key: sorted(values) for key, values in identifiers.items()},
                'audit_evidence_ids': sorted({e.get('audit_id', '') for e in self.history.get(uid, []) if e.get('audit_id')})}


def validate_manifest(rows: list[dict]) -> dict:
    missing = []
    unsupported = Counter()
    for row in rows:
        path = DATASET / row['file_path']
        if not path.is_file():
            missing.append(row['file_id'])
        unsupported[path.suffix.lower()] += 1
    return {'manifest_count': len(rows), 'missing_files': missing, 'extensions': dict(unsupported)}


def inspect() -> None:
    tables = {name: read_csv(name) for name in TABLES}
    resolver = IdentityResolver(tables['user_identities'], tables['user_audit_log'])
    report = {'dataset_rows': {name: len(rows) for name, rows in tables.items()},
              'manifest': validate_manifest(tables['evidence_files']),
              'classification': Counter(), 'identity_resolution': Counter(),
              'unresolved_cases': [], 'ambiguous_request_cases': [], 'rules': tables['deletion_rules']}
    for case in tables['deletion_requests']:
        possible = is_deletion_request(case.get('request_text', ''))
        report['classification']['deletion_intent_heuristic' if possible else 'non_deletion_heuristic'] += 1
        result = resolver.resolve(case.get('email', ''))
        report['identity_resolution'][result['resolution']] += 1
        if result['resolution'] != 'EXACT':
            report['unresolved_cases'].append(case['case_id'])
        if not possible:
            report['ambiguous_request_cases'].append(case['case_id'])
    report['classification'] = dict(report['classification'])
    report['identity_resolution'] = dict(report['identity_resolution'])
    path = ROOT / 'inspection_report.json'
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'Inspection saved: {path}')
    print(f'Requests: {len(tables["deletion_requests"])}; identities: {len(tables["user_identities"])}')
    print(f'Identity resolution: {report["identity_resolution"]}')
    print('This is an inspection baseline, NOT a final deletion verdict or output.csv generator.')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--inspect', action='store_true', help='Inspect participant data and identity mappings')
    args = parser.parse_args()
    if not DATASET.exists():
        parser.error(f'Dataset not found at {DATASET}. Copy code/main.py into the challenge repository.')
    if args.inspect:
        inspect()
    else:
        print('Run: python code/main.py --inspect')
        print('No output.csv is generated until evidence adjudication and evaluation are implemented.')


if __name__ == '__main__':
    main()
