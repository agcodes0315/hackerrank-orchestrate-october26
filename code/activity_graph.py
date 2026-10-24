"""Phase 6: parse text activity details into explicit identity/resource edges.
No activity claim is treated as proof of a record's actual state.
"""
from __future__ import annotations
import csv
import json
import re
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'dataset'

ID_FIELDS = {'user_id','email','email_hash','phone','name','old_email','new_email','recipient_email','customer_email','account_email','subject_email'}
REFERENCE_FIELDS = {'subject_reference','lookup_value','identity','identifier'}
LINK_FIELDS = ID_FIELDS | REFERENCE_FIELDS
# Explicitly delimited fields; avoid extracting arbitrary words from prose.
PAIR = re.compile(r'''(?<![\w])(?P<key>user_id|email_hash|old_email|new_email|recipient_email|customer_email|account_email|subject_email|subject_reference|lookup_value|email|phone|name|identity|identifier)\s*[:=]\s*(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;|}\]]+)''',re.I)
EMAIL = re.compile(r'(?<![\w.+-])([\w.%+-]+@[\w.-]+\.[A-Za-z]{2,})(?![\w.+-])')


def norm(value):
    return str(value or '').strip().strip('"\'').casefold()


def csvrows(filename):
    with (DATA / filename).open(encoding='utf-8-sig', newline='') as stream:
        return list(csv.DictReader(stream))


def iter_scalar_pairs(value):
    if isinstance(value,dict):
        for key, val in value.items():
            if isinstance(val,(dict,list)):
                yield from iter_scalar_pairs(val)
            elif val is not None:
                yield str(key).casefold(), norm(val)
    elif isinstance(value,list):
        for val in value:
            yield from iter_scalar_pairs(val)


def parse_details(details):
    """Return (explicit typed pairs, encoding); no fuzzy whole-text matching."""
    raw = str(details or '').strip()
    if not raw:
        return [], 'empty'
    try:
        obj=json.loads(raw)
        if isinstance(obj,(list,dict)):
            return [(k,v) for k,v in iter_scalar_pairs(obj) if k in LINK_FIELDS and v], 'json'
    except (ValueError,TypeError):
        pass
    # Support Python dict repr from exported logs, without evaluating arbitrary code.
    if raw.startswith('{') and raw.endswith('}'):
        try:
            import ast
            obj=ast.literal_eval(raw)
            if isinstance(obj,dict):
                return [(k,v) for k,v in iter_scalar_pairs(obj) if k in LINK_FIELDS and v], 'python_literal'
        except (ValueError, SyntaxError, TypeError, RecursionError):
            pass
    pairs=[]
    for match in PAIR.finditer(raw):
        key=norm(match.group('key'))
        val=norm(match.group('value')).rstrip('.,')
        if key in LINK_FIELDS and val:
            pairs.append((key,val))
    return pairs, 'key_value_text' if pairs else 'unstructured_text'


def identity_index(users, history):
    index=defaultdict(set)
    for u in users:
        uid=norm(u.get('user_id'))
        if not uid: continue
        for key in ('user_id','email','email_hash','phone','name'):
            val=norm(u.get(key))
            if val: index[(key,val)].add(uid)
    for ev in history:
        uid=norm(ev.get('user_id'))
        field=norm(ev.get('field_name'))
        if field not in ID_FIELDS or not uid: continue
        for k in ('old_value','new_value'):
            val=norm(ev.get(k))
            if val: index[(field,val)].add(uid)
    return index


def linked_users(pairs, index):
    matches=set()
    for key, value in pairs:
        key=norm(key); value=norm(value)
        if key in ID_FIELDS:
            matches.update(index.get((key,value),()))
        elif key in REFERENCE_FIELDS:
            for kind in ('user_id','email','email_hash','phone'):
                matches.update(index.get((kind,value),()))
            # Support reference field that itself contains a typed value.
            match=PAIR.fullmatch(value)
            if match and norm(match.group('key')) in ID_FIELDS:
                matches.update(index.get((norm(match.group('key')),norm(match.group('value'))),()))
    return matches


def analyze(users, history, events, requests):
    index=identity_index(users,history)
    encoding=Counter(); event_links=0; ambiguous=0
    uid_resources=defaultdict(set)
    user_events=defaultdict(list)
    link_event_types=Counter()
    unparsed_examples=[]
    for ev in events:
        pairs, kind=parse_details(ev.get('details',''))
        encoding[kind]+=1
        found=linked_users(pairs,index)
        if len(found)!=1:
            if len(found)>1: ambiguous+=1
            elif len(unparsed_examples)<8:
                # format exemplar only: redact potential emails and IDs
                raw=re.sub(EMAIL,'<EMAIL>',str(ev.get('details','')))
                raw=re.sub(r'(?i)(user_id|email_hash|phone|name)\s*[:=]\s*[^\s,;|]+',r'\1=<VALUE>',raw)
                unparsed_examples.append({'event_type':ev.get('event_type',''),'details_shape':raw[:160]})
            continue
        uid=next(iter(found))
        resource=norm(ev.get('resource_id'))
        if not resource: continue
        # Resource_id is not necessarily in target_system. Keep both separately.
        systems={norm(ev.get('source_system')),norm(ev.get('target_system'))} - {''}
        for sys in systems: uid_resources[uid].add((sys,resource))
        event_links+=1; link_event_types[ev.get('event_type','')]+=1
        user_events[uid].append(ev)

    def coverage(cases):
        out=Counter()
        for case in cases:
            email=norm(case.get('email'))
            matched=index.get(('email',email),set())
            if len(matched)!=1: out['ambiguous_identity']+=1
            elif next(iter(matched)) in uid_resources: out['linked_user']+=1
            else: out['no_explicit_activity_link']+=1
        return dict(out)

    report={
        'activity_count':len(events),
        'activity_detail_encoding':dict(encoding),
        'events_with_unique_explicit_identity_link':event_links,
        'events_with_ambiguous_links':ambiguous,
        'users_with_explicit_resource_links':len(uid_resources),
        'system_resource_links':sum(map(len,uid_resources.values())),
        'linked_event_types':dict(link_event_types),
        'full_request_coverage':coverage(requests),
        'sample_request_coverage':coverage(csvrows('sample_deletion_requests.csv')),
        'unmatched_detail_shapes_redacted':unparsed_examples,
        'important':'An activity event is a claim, not verification of deletion or current state. Resource edges are provisional until corroborated.'
    }
    return report


def main():
    report=analyze(csvrows('user_identities.csv'),csvrows('user_audit_log.csv'),csvrows('system_activity.csv'),csvrows('deletion_requests.csv'))
    target=ROOT/'ghosttrace_activity_graph.json'
    target.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Saved:',target)
    for k in ('activity_detail_encoding','events_with_unique_explicit_identity_link','users_with_explicit_resource_links','full_request_coverage','sample_request_coverage'):
        print(k,report[k])

if __name__=='__main__': main()
