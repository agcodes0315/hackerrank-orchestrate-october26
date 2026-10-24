"""Evidence-first resource lifecycle analysis (diagnostic, not a deletion verdict).

Links users to observations, then groups activity events by EXACT resource_id.
Activity records are claims; only file observations report checked state.
"""
from __future__ import annotations
import csv
import json
from collections import defaultdict, Counter
from datetime import timezone
from pathlib import Path

from engine import EvidenceStore, matches_identity, parse_time, read_csv, norm

ROOT = Path(__file__).resolve().parents[1]

RISK_TYPES = {'SYNC_RECORD','INDEX_RECORD','REFRESH_CACHE','RESTORE_BACKUP','CREATE_EXPORT','UPDATE_RECORD'}
CONTROL_TYPES = {'DISABLE_DATA_FLOW','BLOCK_RESTORE'}
DELETE_TYPES = {'DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD'}


def timeline_for_resource(events, resource_id, audit_at, system_id=None):
    """Chronological activity claims for an exact resource, no substring matching.

    Limit to audit_at and retain claimed operations; no result is treated as proof.
    """
    cutoff=parse_time(audit_at)
    if cutoff is None: return []
    out=[]
    for e in events:
        if norm(e.get('resource_id')) != norm(resource_id): continue
        stamp=parse_time(e.get('event_time'))
        if stamp is None or stamp>cutoff: continue
        # source and target system may both touch the same resource
        if system_id and norm(system_id) not in {norm(e.get('source_system')),norm(e.get('target_system'))}:
            continue
        out.append(e)
    return sorted(out,key=lambda e:(parse_time(e['event_time']),e.get('activity_id','')))


def classify_timeline(events):
    """Flag POTENTIAL resurrection only when risk happens AFTER a deletion claim.

    All results require subsequent independent verification.
    """
    deletions=[e for e in events if e.get('event_type','').upper()=='DELETE_RECORD']
    if not deletions: return {'risk':'NO_DELETE_CLAIM','risk_event_ids':[], 'deletion_claim_ids':[]}
    last_delete=max(parse_time(e['event_time']) for e in deletions)
    after=[e for e in events if parse_time(e['event_time'])>last_delete]
    risky=[e for e in after if e.get('event_type','').upper() in RISK_TYPES]
    return {
        'risk':'POSSIBLE_RESURRECTION_REQUIRES_VERIFICATION' if risky else 'NO_LATER_RECREATION_EVENT_SEEN',
        'risk_event_ids':[e.get('activity_id','') for e in risky],
        'deletion_claim_ids':[e.get('activity_id','') for e in deletions],
    }


def latest_observations(rows,audit_at):
    cutoff=parse_time(audit_at)
    if not cutoff:return []
    by_key={}
    for o in rows:
        moment=parse_time(o.captured_at)
        if moment is None or moment>cutoff:continue
        key=(o.system_id,o.resource_id)
        if key not in by_key or moment>parse_time(by_key[key].captured_at):by_key[key]=o
    return sorted(by_key.values(),key=lambda o:(o.system_id,o.resource_id))


def analyze_case(case, identity, observations, activities):
    matching=[o for o in observations if matches_identity(o,identity)]
    snapshots=latest_observations(matching,case.get('audit_at'))
    resources=[]
    for o in snapshots:
        # Join by exact resource_id. Resource identifiers may be unique across all systems;
        # cross-system activity is context only, never authoritative state proof.
        related=timeline_for_resource(activities,o.resource_id,case.get('audit_at'))
        own=[e for e in related if norm(o.system_id) in {norm(e.get('source_system')),norm(e.get('target_system'))}]
        lifecycle=classify_timeline(related)
        resources.append({
            'system_id':o.system_id,'resource_id':o.resource_id,'category':o.category,
            'verified_snapshot_state':o.state or 'UNKNOWN','evidence_id':o.evidence_id,
            'captured_at':o.captured_at,'activity_count_same_resource':len(related),
            'activity_count_same_system':len(own),**lifecycle,
        })
    return {'case_id':case['case_id'],'matched_evidence_records':len(matching),
            'timely_resource_snapshots':len(snapshots), 'resources':resources}


def analyze(data, full=True):
    from inspector import IdentityResolver
    dataset=Path(data)
    req=read_csv(dataset/('deletion_requests.csv' if full else 'sample_deletion_requests.csv'))
    users=read_csv(dataset/'user_identities.csv')
    history=read_csv(dataset/'user_audit_log.csv')
    resolver=IdentityResolver(users,history)
    store=EvidenceStore(dataset)
    counts=Counter(); samples=[]; matched=0
    for case in req:
        identity=resolver.resolve(case['email'])
        result=analyze_case(case,identity,store.observations,store.activities)
        if result['timely_resource_snapshots']:matched+=1
        for r in result['resources']:
            counts[r['risk']]+=1
            if r['risk']=='POSSIBLE_RESURRECTION_REQUIRES_VERIFICATION' and len(samples)<20:
                samples.append({'case_id':result['case_id'],**r})
    return {'requests':len(req),'requests_with_timely_resource_snapshot':matched,
            'resource_timeline_flags':dict(counts),
            'potential_resurrection_examples':samples,
            'warnings':store.warnings,
            'limitations':['Activity events are claims; no successful deletion is inferred from reported_result.',
                           'Only resources already connected to a user by authoritative evidence are replayed.',
                           'Events after audit_at are ignored.',
                           'No user status or output.csv is generated by this diagnostic.']}


def main():
    report={'full':analyze(ROOT/'dataset',True),'sample':analyze(ROOT/'dataset',False)}
    target=ROOT/'ghosttrace_lifecycle_report.json'
    target.write_text(json.dumps(report,indent=2),encoding='utf-8')
    for k,v in report.items():
        print(k,':',v['requests_with_timely_resource_snapshot'],'of',v['requests'],'cases have timely snapshots')
        print('resource flags:',v['resource_timeline_flags'])
    print('Saved:',target)


if __name__=='__main__':main()
