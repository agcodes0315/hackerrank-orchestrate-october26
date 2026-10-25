"""Emergency STRUCTURAL fallback only; unverified rows are NOT evidence-backed answers.
Strict `main.py --audit` remains authoritative and refuses unsupported predictions.
"""
from __future__ import annotations
import csv,json,sys
from pathlib import Path
from engine import EvidenceStore,audit_case,read_csv
from inspector import IdentityResolver

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'dataset'

def make_predictions(requests):
    resolver=IdentityResolver(read_csv(DATA/'user_identities.csv'), read_csv(DATA/'user_audit_log.csv'))
    rules=read_csv(DATA/'deletion_rules.csv')
    store=EvidenceStore(DATA)
    results=[]; unresolved=[]
    for case in requests:
        pred,reasons=audit_case(case,resolver.resolve(case['email']),store,rules)
        if pred is None:
            unresolved.append({'case_id':case['case_id'],'reasons':reasons})
            # Conservative fallback is not a real finding. Never invent evidence or a COMPLETE verdict.
            pred={'case_id':case['case_id'],'deletion_status':'INCOMPLETE','steps_json':[]}
        results.append(pred)
    return sorted(results,key=lambda row:row['case_id']),unresolved

def write_csv(rows,path):
    with open(path,'w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['case_id','deletion_status','steps_json'])
        for r in rows:w.writerow((r['case_id'],r['deletion_status'],json.dumps(r['steps_json'],separators=(',',':'))))

def main():
    cases=read_csv(DATA/'deletion_requests.csv')
    rows,unresolved=make_predictions(cases)
    write_csv(rows,ROOT/'output.csv')
    (ROOT/'emergency_unverified.json').write_text(json.dumps({'warning':'These rows have not been independently verified and use a structurally valid fallback, not a proven deletion verdict.','unresolved_cases':unresolved},indent=2),encoding='utf-8')
    print('WROTE',ROOT/'output.csv','rows',len(rows),'unverified',len(unresolved))
    if len(unresolved): print('WARNING: unverified INCOMPLETE rows have no supported steps; challenge accuracy will be limited. Do not present as audited.')

if __name__=='__main__':main()
