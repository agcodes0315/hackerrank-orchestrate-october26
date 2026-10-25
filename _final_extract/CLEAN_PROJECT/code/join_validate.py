"""Post-patch join coverage + extracted evidence state checks; does not use gold labels."""
from pathlib import Path
from collections import Counter
import json
from engine import EvidenceStore, read_csv, matches_identity, parse_time
from inspector import IdentityResolver
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'dataset'

def main():
    store=EvidenceStore(DATA)
    resolver=IdentityResolver(read_csv(DATA/'user_identities.csv'),read_csv(DATA/'user_audit_log.csv'))
    cases=read_csv(DATA/'deletion_requests.csv')
    sample=read_csv(DATA/'sample_deletion_requests.csv')
    stats={}
    for name,rows in [('sample',sample),('full',cases)]:
        identity_matches=timely=known_states=0
        for row in rows:
            ids=resolver.resolve(row['email']); cutoff=parse_time(row.get('audit_at'))
            found=[o for o in store.observations if matches_identity(o,ids)]
            eligible=[o for o in found if cutoff and parse_time(o.captured_at) and parse_time(o.captured_at)<=cutoff]
            identity_matches+=bool(found)
            timely+=bool(eligible)
            known_states+=bool([o for o in eligible if o.state])
        stats[name]={'cases':len(rows),'identity_joined':identity_matches,'before_audit_at':timely,'known_state':known_states}
    states=dict(Counter(o.state or '<UNKNOWN>' for o in store.observations))
    report={'case_coverage':stats,'observation_states':states,'extraction_warnings':store.warnings}
    (ROOT/'ghosttrace_join_validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'case_coverage':stats,'observation_states':states,'warnings':len(store.warnings)},indent=2))
if __name__=='__main__': main()
