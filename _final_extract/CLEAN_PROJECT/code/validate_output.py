"""Validate challenge CSV shape, steps, order, and source IDs, not semantic truth."""
import csv,json,sys
from pathlib import Path
from engine import PHASES,OPERATIONS,STATES,read_csv
root=Path(__file__).resolve().parents[1]
cases=read_csv(root/'dataset/deletion_requests.csv')
rows=read_csv(root/'output.csv')
errors=[]
expected=sorted(x['case_id'] for x in cases)
if len(rows)!=len(cases):errors.append(f'expected {len(cases)} rows, got {len(rows)}')
if not rows or list(rows[0])!=['case_id','deletion_status','steps_json']:errors.append('wrong columns')
if [r.get('case_id') for r in rows]!=expected:errors.append('incorrect case IDs/order/duplicates')
for r in rows:
    cid=r.get('case_id','?');status=r.get('deletion_status')
    if status not in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE'):errors.append(f'{cid}: bad status')
    try: steps=json.loads(r.get('steps_json',''))
    except Exception: errors.append(f'{cid}: invalid JSON');continue
    if not isinstance(steps,list):errors.append(f'{cid}: steps not list');continue
    if status=='NOT_APPLICABLE' and steps:errors.append(f'{cid}: nonempty N/A steps')
    if status=='COMPLETE' and any(s.get('phase')!='VERIFICATION' for s in steps):errors.append(f'{cid}: COMPLETE with nonverification steps')
    if [s.get('step_no') for s in steps]!=list(range(1,len(steps)+1)):errors.append(f'{cid}: step numbers')
    key=[]
    for s in steps:
        if set(s)!={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}:errors.append(f'{cid}: wrong fields');continue
        phase=s['phase'];op=s['operation']
        if phase not in PHASES or op not in OPERATIONS.get(phase,[]):errors.append(f'{cid}: bad operation');continue
        if s['state']!=STATES[op]:errors.append(f'{cid}: bad state')
        if phase=='FINDING' or (status=='COMPLETE' and phase=='VERIFICATION'):
            if not s['evidence_id']:errors.append(f'{cid}: uncited finding/verification')
        if phase=='REMEDIATION' or (status=='INCOMPLETE' and phase=='VERIFICATION'):
            if s['evidence_id']:errors.append(f'{cid}: unexpected future evidence ID')
        key.append((PHASES[phase],OPERATIONS[phase].index(op),s['system_id'],s['resource_id']))
    if key!=sorted(key):errors.append(f'{cid}: wrong step order')
if errors:
    print('FAILED:',len(errors),'errors'); print('\n'.join(errors[:30]));sys.exit(1)
print(f'STRUCTURAL VALIDATION PASSED: {len(rows)} rows. This does not establish evidence correctness.')
