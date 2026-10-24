"""GhostTrace phase 2 entry point. All results are provisional until coverage is reviewed."""
from __future__ import annotations
import argparse,csv,json,sys
from collections import Counter
from pathlib import Path
from engine import EvidenceStore,audit_case,read_csv,canonicalize
from inspector import inspect,IdentityResolver

ROOT=Path(__file__).resolve().parents[1]
DATASET=ROOT/'dataset'

def run(output,allow_partial=False):
    identities=read_csv(DATASET/'user_identities.csv')
    audit=read_csv(DATASET/'user_audit_log.csv')
    resolver=IdentityResolver(identities,audit)
    cases=read_csv(DATASET/'deletion_requests.csv')
    rules=read_csv(DATASET/'deletion_rules.csv')
    store=EvidenceStore(DATASET)
    predictions=[]; reviews={}
    for c in cases:
        prediction,flags=audit_case(c,resolver.resolve(c['email']),store,rules)
        if flags: reviews[c['case_id']]=flags
        if prediction is not None: predictions.append(prediction)
    report={'total_requests':len(cases),'predicted':len(predictions),'review_required':len(reviews),
            'status_counts':dict(Counter(p['deletion_status'] for p in predictions)),
            'structured_observations':len(store.observations),'warnings':store.warnings,'review_cases':reviews}
    (ROOT/'ghosttrace_review.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    (ROOT/'ghosttrace_predictions.json').write_text(json.dumps(predictions,indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'Cases: {len(cases)}; provisional predictions: {len(predictions)}; NEED REVIEW: {len(reviews)}')
    print(f'Structured evidence observations: {len(store.observations)}; parsing warnings: {len(store.warnings)}')
    print('Details: ghosttrace_review.json and ghosttrace_predictions.json')
    if reviews or len(predictions)!=len(cases):
        print('STOP: refusing to create a misleading submission CSV. Resolve evidence/review gaps first.',file=sys.stderr)
        return 2
    with open(output,'w',newline='',encoding='utf-8') as f:
        writer=csv.writer(f); writer.writerow(['case_id','deletion_status','steps_json'])
        for row in sorted(predictions,key=lambda r:r['case_id']):
            writer.writerow([row['case_id'],row['deletion_status'],json.dumps(row['steps_json'],separators=(',',':'))])
    print('Written:',output)
    return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--inspect',action='store_true')
    parser.add_argument('--audit',action='store_true')
    parser.add_argument('--output',default=str(ROOT/'output.csv'))
    args=parser.parse_args()
    if not DATASET.is_dir(): parser.error(f'Expected challenge dataset folder: {DATASET}')
    if args.inspect: inspect()
    elif args.audit: sys.exit(run(args.output))
    else: parser.print_help()
