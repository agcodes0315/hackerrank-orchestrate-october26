"""GhostTrace consolidated CLI: one entry point for the existing deterministic modules.

All proposed statuses are blocked unless individual case evidence is sufficient.
This code does not convert diagnostic risk flags into proof of a deletion violation.
"""
from __future__ import annotations
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'dataset'


def write_json(name, value):
    path = ROOT / name
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    return path


def audit(dataset='full'):
    from inspector import IdentityResolver
    from engine import EvidenceStore, audit_case, read_csv
    from lifecycle import analyze_case
    filename = 'sample_deletion_requests.csv' if dataset == 'sample' else 'deletion_requests.csv'
    cases = read_csv(DATA / filename)
    ids = IdentityResolver(read_csv(DATA / 'user_identities.csv'), read_csv(DATA / 'user_audit_log.csv'))
    store = EvidenceStore(DATA)
    rules = read_csv(DATA / 'deletion_rules.csv')
    predictions = []
    reviews = {}
    lifecycle = []
    for case in cases:
        identity = ids.resolve(case.get('email',''))
        result, warnings = audit_case(case, identity, store, rules)
        if result is not None: predictions.append(result)
        if warnings: reviews[case['case_id']] = warnings
        analyzed = analyze_case(case, identity, store.observations, store.activities)
        flagged = [r for r in analyzed['resources'] if r['risk']=='POSSIBLE_RESURRECTION_REQUIRES_VERIFICATION']
        for r in flagged:
            lifecycle.append({'case_id':case['case_id'], 'system_id':r['system_id'],
                'resource_id':r['resource_id'], 'risk':r['risk'],
                'snapshot_evidence_id':r['evidence_id'], 'snapshot_state':r['verified_snapshot_state'],
                'event_ids':r['risk_event_ids'], 'deletion_claim_ids':r['deletion_claim_ids']})
    tag = 'sample' if dataset == 'sample' else 'full'
    write_json('ghosttrace_'+tag+'_predictions.json', predictions)
    summary = {'dataset':tag,'requests':len(cases),'predicted':len(predictions),
               'review_required':len(reviews), 'statuses':dict(Counter(x['deletion_status'] for x in predictions)),
               'evidence_observations':len(store.observations),'extraction_warnings':store.warnings,
               'potential_resurrection_count':len(lifecycle), 'potential_resurrections':lifecycle,
               'reviews': reviews,
               'note':'Provisional investigation only; no assumption that absence of evidence proves deletion.'}
    write_json('ghosttrace_'+tag+'_report.json', summary)
    print(f'{tag}: {len(predictions)}/{len(cases)} classified, {len(reviews)} require review; {len(lifecycle)} potential resurrection signals')
    return summary


def evaluate():
    import evaluate as sample_eval
    sample_eval.main()


def validate(csv_path):
    """Check submission shape, key names, unique IDs, ordering and grounded evidence ID syntax.

    Structural checks do not establish factual correctness.
    """
    from engine import PHASES, OPERATIONS, STATES, read_csv
    source=read_csv(DATA/'deletion_requests.csv')
    expected={r['case_id'] for r in source}
    errors=[]
    target=Path(csv_path)
    if not target.is_file():
        print('No output.csv yet. Audit coverage must be complete before final submission.')
        return False
    with target.open(newline='',encoding='utf-8-sig') as f:
        r=csv.DictReader(f)
        if r.fieldnames != ['case_id','deletion_status','steps_json']:
            errors.append('CSV columns do not match the required header')
        rows=list(r)
    ids=[r.get('case_id') for r in rows]
    if set(ids)!=expected or len(ids)!=len(expected) or len(ids)!=len(set(ids)):
        errors.append('Incorrect, duplicate or missing case IDs')
    if ids!=sorted(ids):errors.append('Case rows must be lexicographically sorted by case_id')
    needed={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}
    for row in rows:
        cid=row.get('case_id','?')
        status=row.get('deletion_status')
        if status not in {'COMPLETE','INCOMPLETE','NOT_APPLICABLE'}:
            errors.append(f'{cid}: unsupported deletion status')
        try: steps=json.loads(row.get('steps_json',''))
        except json.JSONDecodeError:
            errors.append(f'{cid}: invalid steps JSON');continue
        if not isinstance(steps,list):errors.append(f'{cid}: steps_json must be a list');continue
        if status=='NOT_APPLICABLE' and steps:errors.append(f'{cid}: NOT_APPLICABLE needs []')
        sortable=[]
        for i,step in enumerate(steps,1):
            if not isinstance(step,dict) or set(step)!=needed:
                errors.append(f'{cid}: incorrect step fields');continue
            phase=step.get('phase');op=step.get('operation')
            if phase not in PHASES or op not in OPERATIONS.get(phase,[]):
                errors.append(f'{cid}: unknown phase or operation');continue
            if step.get('step_no')!=i:errors.append(f'{cid}: nonconsecutive step_no')
            if step.get('state')!=STATES.get(op):errors.append(f'{cid}: operation/state mismatch')
            if phase in ('FINDING','VERIFICATION') and not step.get('evidence_id') and status=='COMPLETE':
                errors.append(f'{cid}: verified step missing evidence_id')
            if phase=='FINDING' and not step.get('evidence_id'):
                errors.append(f'{cid}: finding missing evidence_id')
            if phase=='REMEDIATION' and step.get('evidence_id'):
                errors.append(f'{cid}: proposed remediation must have empty evidence_id')
            sortable.append((PHASES[phase],OPERATIONS[phase].index(op),step['system_id'],step['resource_id']))
        if sortable != sorted(sortable):errors.append(f'{cid}: incorrect step order')
    report={'valid_structure':not errors,'rows':len(rows),'errors':errors[:100]}
    write_json('ghosttrace_submission_validation.json',report)
    print('Structural validation:', 'PASS' if not errors else f'FAIL ({len(errors)} issues)')
    return not errors


def run_all():
    from inspector import inspect
    inspect()
    audit('full')
    audit('sample')
    evaluate()
    from lifecycle import analyze
    write_json('ghosttrace_lifecycle_report.json',{'full':analyze(DATA,True),'sample':analyze(DATA,False)})
    print('Reports created. No submission CSV is written when investigations remain unresolved.')
    print('Next: inspect ghosttrace_full_report.json and ghosttrace_sample_evaluation.json')


def main():
    p=argparse.ArgumentParser(description='GhostTrace consolidated evidence-first auditing workflow')
    p.add_argument('command',nargs='?',default='all', choices=['all','inspect','audit','sample','evaluate','validate','tests','gemma'])
    p.add_argument('--file',default=str(ROOT/'output.csv'))
    p.add_argument('--rule-id',default='rule_05')
    p.add_argument('--facts',default='{}',help='JSON dictionary of non-sensitive factual flags')
    p.add_argument('--model',default='gemma3:4b')
    args=p.parse_args()
    if not DATA.exists():p.error(f'Dataset missing at {DATA}')
    if args.command=='all': run_all()
    elif args.command=='inspect':
        from inspector import inspect
        inspect()
    elif args.command=='audit':audit('full')
    elif args.command=='sample':audit('sample')
    elif args.command=='evaluate':evaluate()
    elif args.command=='validate':sys.exit(0 if validate(args.file) else 1)
    elif args.command=='tests':sys.exit(subprocess.call([sys.executable,'-m','unittest','discover','-s',str(ROOT/'code/tests'),'-v']))
    elif args.command=='gemma':
        from gemma_agent import interpret
        from engine import read_csv
        rule=next((r for r in read_csv(DATA/'deletion_rules.csv') if r['rule_id']==args.rule_id),None)
        if not rule:p.error(f'Unknown rule {args.rule_id}')
        facts=json.loads(args.facts)
        print(json.dumps(interpret(rule,facts,model=args.model),indent=2))

if __name__=='__main__':main()
