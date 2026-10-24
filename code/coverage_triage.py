"""Leakage-safe sample/full coverage triage. Prints aggregate statistics only.
Run from repository root: python code/coverage_triage.py
Does not read sample_output.csv and never assigns compliance verdicts.
"""
from collections import Counter, defaultdict
from pathlib import Path
import json
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import EvidenceStore, read_csv, matches_identity, parse_time, deletion_intent
from inspector import IdentityResolver

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'dataset'

def norm(value):
    return str(value or '').strip().casefold()

def main():
    identities = read_csv(DATA / 'user_identities.csv')
    audits = read_csv(DATA / 'user_audit_log.csv')
    resolver = IdentityResolver(identities, audits)
    store = EvidenceStore(DATA)
    samples = read_csv(DATA / 'sample_deletion_requests.csv')
    full = read_csv(DATA / 'deletion_requests.csv')
    full_ids = {row['case_id'] for row in full}
    full_emails = {norm(row['email']) for row in full}
    manifest = store.manifest
    activities = store.activities
    observations = store.observations

    # Strict exact resource match is only a linkage clue; activity reports aren't proof.
    by_resource = defaultdict(list)
    for evt in activities:
        if evt.get('resource_id'):
            by_resource[norm(evt['resource_id'])].append(evt)

    def summarize(rows):
        stats = Counter()
        reasons = Counter()
        for case in rows:
            stats['cases'] += 1
            identity = resolver.resolve(case.get('email', ''))
            stats['identity_' + identity.get('resolution', 'UNDEFINED')] += 1
            intent = deletion_intent(case.get('request_text', ''))
            stats['intent_' + ('TRUE' if intent is True else 'FALSE' if intent is False else 'UNKNOWN')] += 1
            cutoff = parse_time(case.get('audit_at'))
            if cutoff is None:
                stats['missing_or_bad_audit_time'] += 1
            if identity.get('resolution') != 'EXACT':
                continue
            matched = [obs for obs in observations if matches_identity(obs, identity)]
            timely = [obs for obs in matched if cutoff and (t := parse_time(obs.captured_at)) and t <= cutoff]
            if matched: stats['matched_any_observation'] += 1
            if timely: stats['matched_timely_observation'] += 1
            if any(obs.state for obs in timely): stats['matched_timely_known_state'] += 1
            related_activities = [evt for obs in matched for evt in by_resource.get(norm(obs.resource_id), [])]
            if related_activities: stats['activities_by_matched_resource'] += 1
            if matched and not timely: reasons['matched_but_not_at_audit'] += 1
            if not matched: reasons['no_exact_evidence_identifier_match'] += 1
        return {'counts':dict(stats), 'missing_evidence_reasons':dict(reasons)}

    report = {
        'sample': summarize(samples),
        'full': summarize(full),
        'sample_overlap': {
            'sample_case_ids_in_full_requests': sum(row['case_id'] in full_ids for row in samples),
            'sample_emails_in_full_requests': sum(norm(row['email']) in full_emails for row in samples),
        },
        'evidence': {
            'observations': len(observations),
            'file_formats':dict(Counter(Path(row.get('file_path','')).suffix.lower() for row in manifest)),
            'observations_with_subject_reference': sum(bool(o.fields.get('subject_reference')) for o in observations),
            'observations_with_lookup_value':sum(bool(o.fields.get('lookup_value')) for o in observations),
            'observations_with_known_state':sum(bool(o.state) for o in observations),
            'activities': len(activities),
            'activity_types':dict(Counter(evt.get('event_type','') for evt in activities)),
        },
        'warnings':list(store.warnings),
        'note':'Activity events were counted for coverage only; they are not evidence of success. No ground-truth sample answers were read.'
    }
    target = ROOT / 'ghosttrace_coverage_triage.json'
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Saved', target)
    print(json.dumps({key:report[key] for key in ('sample','full','sample_overlap')}, indent=2))

if __name__ == '__main__':
    main()
