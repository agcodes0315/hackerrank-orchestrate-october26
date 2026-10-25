"""GhostTrace resource-identity linkage diagnostic (no verdicts, no PII output).
Run from repository root: python code/resource_graph_probe.py
Uses actual activity and evidence schemas. Activity reports are not deletion proof.
"""
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'dataset'
OUT = ROOT / 'ghosttrace_resource_graph_probe.json'


def rows(name):
    with (DATA / (name + '.csv')).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def norm(v):
    return str(v or '').strip().casefold()


def json_or_none(value):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def leaves(obj, label=''):
    """Field-labelled scalar tokens only; never fuzzy-match free text or substrings."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, str(k).lower())
    elif isinstance(obj, list):
        for v in obj:
            yield from leaves(v, label)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield label, norm(obj)


def build_index(users, history):
    idx = defaultdict(set)
    allowed = {'user_id', 'email', 'email_hash', 'phone', 'name', 'old_email', 'new_email', 'recipient_email', 'customer_email', 'account_email', 'subject_email'}
    for u in users:
        uid = u.get('user_id', '')
        for key in ('user_id', 'email', 'email_hash', 'phone', 'name'):
            if norm(u.get(key)): idx[(key, norm(u[key]))].add(uid)
    for e in history:
        uid = e.get('user_id', '')
        field = norm(e.get('field_name'))
        if not uid or field not in allowed: continue
        for key in ('old_value', 'new_value'):
            if norm(e.get(key)): idx[(field, norm(e[key]))].add(uid)
    return idx


def linked_users(detail, idx):
    data = json_or_none(detail)
    if data is None: return set(), 'non_json'
    result = set()
    for key, value in leaves(data):
        if key in {'user_id','email','email_hash','phone','name','old_email','new_email','recipient_email','customer_email','account_email','subject_email'}:
            result.update(idx.get((key, value), set()))
        elif key in {'subject_reference','lookup_value'}:
            # Exact match to any declared identifier type, not a text search.
            for typ in ('user_id','email','email_hash','phone','name'):
                result.update(idx.get((typ, value), set()))
    return result, 'json'


def main():
    users, history, events = rows('user_identities'), rows('user_audit_log'), rows('system_activity')
    idx = build_index(users, history)
    users_to_resources = defaultdict(set)
    resources_to_events = defaultdict(list)
    parsed = Counter()
    ambiguous = 0
    direct = 0
    examples_of_keys = Counter()
    for ev in events:
        resource = norm(ev.get('resource_id'))
        system = norm(ev.get('target_system') or ev.get('source_system'))
        resource_key = (system, resource)
        resources_to_events[resource_key].append(ev)
        detail = ev.get('details', '')
        data = json_or_none(detail)
        if isinstance(data, dict): examples_of_keys.update(data.keys())
        users_found, kind = linked_users(detail, idx)
        parsed[kind] += 1
        if len(users_found) == 1 and resource:
            direct += 1
            users_to_resources[next(iter(users_found))].add(resource_key)
        elif len(users_found) > 1:
            ambiguous += 1

    # Validate candidate resource relationships by consistency, not by taking any event success as proof.
    cases = rows('deletion_requests')
    sample = rows('sample_deletion_requests')
    email_user = defaultdict(set)
    for (kind, value), user_ids in idx.items():
        if kind == 'email': email_user[value].update(user_ids)

    def cover(requests):
        out = Counter()
        for case in requests:
            ids = email_user.get(norm(case.get('email')), set())
            if len(ids) != 1:
                out['not_unique_identity'] += 1
                continue
            uid = next(iter(ids))
            if users_to_resources.get(uid): out['direct_activity_resource_link'] += 1
            else: out['no_direct_activity_resource_link'] += 1
        return dict(out)

    output = {
        'purpose': 'diagnostics_only_no_deletion_verdict',
        'activity_total': len(events),
        'activity_detail_encoding': dict(parsed),
        'most_common_activity_details_keys': dict(examples_of_keys.most_common(25)),
        'activity_events_with_unique_typed_identity_link': direct,
        'activity_events_with_ambiguous_identity_link': ambiguous,
        'users_with_direct_activity_resource_links': len(users_to_resources),
        'unique_system_resource_pairs': len(resources_to_events),
        'full_request_coverage': cover(cases),
        'sample_request_coverage': cover(sample),
        'event_types': dict(Counter(e.get('event_type','') for e in events)),
        'next': 'Inspect details keys and expand links only when supported by explicit LINK_RESOURCE_IDENTITY or equivalent verified events.'
    }
    OUT.write_text(json.dumps(output, indent=2), encoding='utf-8')
    print(f'Saved {OUT}')
    print('Full coverage:', output['full_request_coverage'])
    print('Sample coverage:', output['sample_request_coverage'])
    print('Details encoding:', output['activity_detail_encoding'])
    print('PII excluded from report. Activity operation claims are NOT treated as proven record state.')

if __name__ == '__main__':
    main()
