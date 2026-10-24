"""Evaluate provisional predictions using ONLY the 32 public sample-output rows.
Never use sample labels as features or shortcuts in the prediction pipeline.
"""
from __future__ import annotations
import csv,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def rows(path):
    with path.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def normalize_step(step):return {k:v for k,v in step.items() if k!='step_no'}
def main():
    gold=rows(ROOT/'dataset'/'sample_output.csv')
    path=ROOT/'ghosttrace_predictions.json'
    if not path.exists():raise SystemExit('Run python code/main.py --audit before evaluation')
    pred={r['case_id']:r for r in json.loads(path.read_text(encoding='utf-8'))}
    n=0; exact_status=0; exact_steps=0; sequence_exact=0; correct_fields=0; total_fields=0
    failures=[]
    for g in gold:
        p=pred.get(g['case_id'])
        if p is None: failures.append({'case_id':g['case_id'],'issue':'no grounded prediction'});continue
        n+=1
        ps=p['deletion_status']; gs=g['deletion_status']
        exact_status+=ps==gs
        desired=json.loads(g['steps_json']); actual=p['steps_json']
        exact_steps+=desired==actual
        sequence_exact += [s.get('operation') for s in desired]==[s.get('operation') for s in actual]
        for s1,s2 in zip(desired,actual):
            for key in ('phase','operation','state','system_id','resource_id','evidence_id'):
                total_fields+=1;correct_fields+=s1.get(key)==s2.get(key)
        if gs!=ps or desired!=actual: failures.append({'case_id':g['case_id'],'expected_status':gs,'predicted_status':ps,'expected_steps':len(desired),'predicted_steps':len(actual)})
    result={'sample_rows':len(gold),'evaluated':n,'coverage':n/len(gold) if gold else None,
            'status_accuracy_on_evaluated':exact_status/n if n else None,
            'exact_step_array_rate':exact_steps/n if n else None,
            'sequence_accuracy':sequence_exact/n if n else None,
            'aligned_field_accuracy':correct_fields/total_fields if total_fields else None,'failures':failures}
    (ROOT/'ghosttrace_evaluation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='failures'},indent=2))
    print('Per-case failure details: ghosttrace_evaluation.json')
if __name__=='__main__':main()
