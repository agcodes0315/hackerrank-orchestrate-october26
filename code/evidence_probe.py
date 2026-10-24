"""Diagnose ingestion/join coverage without printing personal identifiers or raw content."""
from __future__ import annotations
import json, csv
from collections import Counter
from pathlib import Path
from engine import EvidenceStore, read_csv, matches_identity, parse_time
from inspector import IdentityResolver

ROOT=Path(__file__).resolve().parents[1]
DATASET=ROOT/'dataset'

def main():
    requests=read_csv(DATASET/'deletion_requests.csv')
    samples=read_csv(DATASET/'sample_deletion_requests.csv')
    ids=read_csv(DATASET/'user_identities.csv')
    history=read_csv(DATASET/'user_audit_log.csv')
    activities=read_csv(DATASET/'system_activity.csv')
    manifest=read_csv(DATASET/'evidence_files.csv')
    store=EvidenceStore(DATASET)
    resolver=IdentityResolver(ids,history)
    report={'csv_headers':{},'manifest_extensions':dict(Counter(Path(r.get('file_path','')).suffix.lower() for r in manifest)),
            'evidence_manifest_columns':sorted({k for r in manifest for k in r}),
            'observations':len(store.observations),'evidence_schema':{},'activity_schema':{},'case_join_coverage':{},
            'warnings':store.warnings}
    for name,rows in [('deletion_requests',requests),('sample_deletion_requests',samples),('user_identities',ids),
                      ('user_audit_log',history),('system_activity',activities),('deletion_rules',read_csv(DATASET/'deletion_rules.csv'))]:
        report['csv_headers'][name]=list(rows[0]) if rows else []
    schema=Counter(); states=Counter(); src=Counter(); empty=Counter()
    for obs in store.observations:
        schema.update(obs.fields.keys()); states.update([obs.state or '<MISSING>']); src.update([obs.source_type]);
        if not parse_time(obs.captured_at): empty['unparseable_timestamp']+=1
        if not obs.category: empty['missing_category']+=1
    report['evidence_schema']={'field_counts':dict(schema.most_common(70)),'state_counts':dict(states),
                               'source_counts':dict(src),'quality_flags':dict(empty)}
    act_keys=Counter(); types=Counter()
    for row in activities:
        act_keys.update(k for k,v in row.items() if v not in (None,''))
        for k in ('operation','event_type','action','status'):
            if row.get(k):types.update([k+':'+str(row[k])[:50]])
    report['activity_schema']={'populated_columns':dict(act_keys),'most_common_event_labels':dict(types.most_common(35))}
    for label,rows in [('full',requests),('sample',samples)]:
        matched=at_audit=missing_cutoff=0
        for request in rows:
            ident=resolver.resolve(request.get('email',''))
            cutoff=parse_time(request.get('audit_at'))
            if cutoff is None:missing_cutoff+=1
            found=[o for o in store.observations if matches_identity(o,ident)]
            if found:matched+=1
            if cutoff and any(parse_time(o.captured_at) and parse_time(o.captured_at)<=cutoff for o in found):at_audit+=1
        report['case_join_coverage'][label]={'total':len(rows),'identity_matched_observation':matched,
                                            'matched_before_audit_at':at_audit,'missing_audit_time':missing_cutoff}
    dest=ROOT/'ghosttrace_evidence_diagnostic.json'
    dest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Diagnostic saved:',dest)
    print('Observations:',len(store.observations),'Warnings:',len(store.warnings))
    print('Join coverage:',json.dumps(report['case_join_coverage']))
    print('Evidence field names:',', '.join(list(schema)[:35]))
    print('No raw PII or record contents are included in this diagnostic.')

if __name__=='__main__':main()
