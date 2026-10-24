"""Leakage-safe evaluation: run the same auditor on the separate labeled sample requests."""
from __future__ import annotations
import csv, json
from collections import Counter
from pathlib import Path
from engine import EvidenceStore, audit_case, read_csv
from inspector import IdentityResolver

ROOT=Path(__file__).resolve().parents[1]
DATASET=ROOT/'dataset'

def main():
    sample=read_csv(DATASET/'sample_deletion_requests.csv')
    gold=read_csv(DATASET/'sample_output.csv')
    resolver=IdentityResolver(read_csv(DATASET/'user_identities.csv'),read_csv(DATASET/'user_audit_log.csv'))
    store=EvidenceStore(DATASET)
    rules=read_csv(DATASET/'deletion_rules.csv')
    predictions={}; reviews={}
    for row in sample:
        result,issues=audit_case(row,resolver.resolve(row.get('email','')),store,rules)
        if result is not None: predictions[row['case_id']]=result
        if issues: reviews[row['case_id']]=issues
    counted=correct_status=correct_steps=correct_sequences=0
    failure=[]
    for expected in gold:
        cid=expected['case_id']
        actual=predictions.get(cid)
        if actual is None:
            failure.append({'case_id':cid,'issue':'REVIEW','reasons':reviews.get(cid,['unknown'])})
            continue
        counted+=1
        expected_steps=json.loads(expected['steps_json'])
        status_ok=actual['deletion_status']==expected['deletion_status']
        steps_ok=actual['steps_json']==expected_steps
        sequence_ok=[s['operation'] for s in actual['steps_json']]==[s['operation'] for s in expected_steps]
        correct_status+=status_ok
        correct_steps+=steps_ok
        correct_sequences+=sequence_ok
        if not (status_ok and steps_ok):
            failure.append({'case_id':cid,'issue':'mismatch','status_expected':expected['deletion_status'],
                            'status_predicted':actual['deletion_status'], 'steps_expected':len(expected_steps),
                            'steps_predicted':len(actual['steps_json'])})
    result={'sample_rows':len(gold),'evaluated':counted,'coverage':counted/len(gold) if gold else None,
            'status_accuracy_on_evaluated':correct_status/counted if counted else None,
            'status_accuracy_on_all_samples':correct_status/len(gold) if gold else None,
            'exact_step_array_rate':correct_steps/counted if counted else None,
            'sequence_accuracy':correct_sequences/counted if counted else None,
            'prediction_statuses':dict(Counter(row['deletion_status'] for row in predictions.values())),
            'reviews':len(reviews),'failures':failure}
    (ROOT/'ghosttrace_sample_evaluation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='failures'},indent=2))
    print('Saved ghosttrace_sample_evaluation.json; sample labels were used for evaluation only.')

if __name__=='__main__':main()
