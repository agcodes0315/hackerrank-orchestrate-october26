"""Evidence-oriented deletion policy engine. No LLM is allowed to create evidence.

This engine errs on the side of REVIEW for data it cannot establish. It does not
convert unsupported speculation into positive findings or verification proofs.
"""
from __future__ import annotations
import csv
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PHASES = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
OPERATIONS = {
 'FINDING': ['REPORT_REMAINING_RECORD','REPORT_EXPOSED_PII','REPORT_ACTIVE_DATA_FLOW','REPORT_RESTORE_RISK'],
 'REMEDIATION': ['DISABLE_DATA_FLOW','BLOCK_RESTORE','DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD'],
 'VERIFICATION': ['VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT','VERIFY_RECORD_REDACTED','VERIFY_RECORD_ANONYMIZED','VERIFY_DATA_FLOW_DISABLED','VERIFY_RESTORE_BLOCKED']
}
STATES = {'REPORT_REMAINING_RECORD':'PRESENT','REPORT_EXPOSED_PII':'PRESENT','REPORT_ACTIVE_DATA_FLOW':'ACTIVE','REPORT_RESTORE_RISK':'ACTIVE',
          'DISABLE_DATA_FLOW':'DISABLED','BLOCK_RESTORE':'BLOCKED','DELETE_RECORD':'ABSENT','REDACT_RECORD':'REDACTED','ANONYMIZE_RECORD':'ANONYMIZED',
          'VERIFY_RECORD_ABSENT':'ABSENT','VERIFY_RECORD_PRESENT':'PRESENT','VERIFY_RECORD_REDACTED':'REDACTED',
          'VERIFY_RECORD_ANONYMIZED':'ANONYMIZED','VERIFY_DATA_FLOW_DISABLED':'DISABLED','VERIFY_RESTORE_BLOCKED':'BLOCKED'}
CATEGORIES = {'USER_PROFILE','SECONDARY_IDENTIFIER','SEARCH_INDEX_ENTRY','CACHE_ENTRY','SUPPORT_MESSAGE','SUPPORT_ATTACHMENT','ANALYTICS_PROFILE',
              'PRODUCT_TELEMETRY','USER_EXPORT','MARKETING_PROFILE','EMAIL_DELIVERY_LOG','SECURITY_AUDIT_LOG','LEGAL_HOLD_RECORD','BACKUP_ARCHIVE','ACCOUNT_TOMBSTONE'}
ID_KEYS = {'user_id','email','email_hash','phone','name','old_email','new_email','recipient_email','customer_email','account_email','subject_email','subject_reference','lookup_value'}
META_KEYS = {'system_id','resource_id','data_category','category','record_type','state','status','snapshot_at','captured_at','timestamp','observed_at',
             'event_time','event_at','occurred_at','recorded_at','updated_at','file_id','activity_id','audit_id','id','table','table_name'}
PII_FIELDS = {'name','email','email_hash','phone','first_name','last_name','full_name','customer_email','recipient_email','address'}


def parse_time(s):
    if not s: return None
    try: return datetime.fromisoformat(str(s).strip().replace('Z','+00:00')).replace(tzinfo=timezone.utc) if datetime.fromisoformat(str(s).strip().replace('Z','+00:00')).tzinfo is None else datetime.fromisoformat(str(s).strip().replace('Z','+00:00')).astimezone(timezone.utc)
    except (ValueError, TypeError): return None


def norm(x): return str(x or '').strip().casefold()


def read_csv(path):
    with open(path,encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))


def tokens(text):
    return set(re.findall(r'[a-z_]+', norm(text)))


def deletion_intent(text):
    """Tri-state (True, False, None); never treat uncertain messages as authorized."""
    t = norm(text)
    negatives = [r'\b(?:do not|don\'t|never|without)\s+(?:delete|erase|remove|close)\b',
                 r'\b(?:not|no)\s+(?:requesting|asking for)\s+(?:deletion|erasure)\b',
                 r'\b(?:instead of|rather than)\s+(?:deleting|erasing)\b',
                 r'\b(?:keep|retain)\s+my\s+(?:account|data)\b']
    if any(re.search(p,t) for p in negatives): return False
    if any(re.search(p,t) for p in [r'\b(?:delete|erase|erasure|deletion|forget me|right to be forgotten)\b',
                                     r'\b(?:close|terminate)\s+(?:my|the)\s+account\b',
                                     r'\bremove\s+(?:all\s+)?(?:my|personal|account)\s+(?:data|information|details)\b']): return True
    if any(re.search(p,t) for p in [r'\b(?:export|download|correct|update|access|unsubscribe|opt out|opt-out)\b']): return False
    return None


def flatten(obj,prefix='',depth=0):
    """Flatten JSON objects while retaining containing record boundaries."""
    if depth > 12: return {}
    if not isinstance(obj,dict): return {}
    out={}
    for key,val in obj.items():
        name=str(key)
        if isinstance(val,(str,int,float,bool)) or val is None: out[name]=val
        elif isinstance(val,dict):
            for k,v in flatten(val,depth=depth+1).items(): out.setdefault(k,v)
    return out


def json_records(obj):
    if isinstance(obj,list):
        for item in obj: yield from json_records(item)
    elif isinstance(obj,dict):
        if set(obj).intersection(ID_KEYS | META_KEYS) and len(obj)>=2:
            yield flatten(obj)
        for v in obj.values():
            if isinstance(v,(dict,list)): yield from json_records(v)


@dataclass(frozen=True)
class Observation:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    captured_at: str
    fields: dict
    source_type: str = 'file'


class EvidenceStore:
    def __init__(self, dataset):
        self.dataset=Path(dataset)
        self.observations=[]
        self.warnings=[]
        self.manifest=read_csv(self.dataset/'evidence_files.csv')
        self._load_files()
        self._load_activities()

    def _add(self,record,file_id,when,source='file',fallback_system='',fallback_category=''):
        row={norm(k):v for k,v in record.items()}
        system=str(row.get('system_id') or row.get('system') or row.get('service') or fallback_system or '').strip()
        resource=str(row.get('resource_id') or row.get('record_id') or row.get('entity_id') or row.get('id') or '').strip()
        category=str(row.get('data_category') or row.get('category') or row.get('record_type') or fallback_category or '').upper()
        state=normalized_state(row.get('state') or row.get('status') or row.get('record_state') or row.get('result') or '')
        observed=str(row.get('snapshot_at') or row.get('captured_at') or row.get('observed_at') or row.get('timestamp') or row.get('recorded_at') or when or '')
        if not (system and resource): return
        self.observations.append(Observation(system,resource,category,state,file_id,observed,row,source))

    def _load_files(self):
        for manifest in self.manifest:
            fid=manifest.get('file_id','')
            path=self.dataset / manifest.get('file_path','')
            if not path.is_file():
                self.warnings.append(f'Missing evidence: {fid}'); continue
            when=next((manifest[k] for k in ('captured_at','capture_time','created_at','timestamp') if manifest.get(k)), '')
            suffix=path.suffix.lower()
            try:
                if suffix=='.json':
                    obj=json.loads(path.read_text(encoding='utf-8-sig'))
                    for row in json_records(obj): self._add(row,fid,when)
                elif suffix=='.sql':
                    db=sqlite3.connect(':memory:')
                    try:
                        db.executescript(path.read_text(encoding='utf-8-sig'))
                        tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                        for table in tables:
                            safe='"'+table.replace('"','""')+'"'
                            cur=db.execute(f'SELECT * FROM {safe} LIMIT 200000')
                            names=[x[0] for x in cur.description]
                            for values in cur.fetchall():
                                row=dict(zip(names, values)); row.setdefault('system_id',manifest.get('system_id',''))
                                row.setdefault('data_category',manifest.get('data_category',''))
                                self._add(row,fid,when,fallback_system=manifest.get('system_id',''))
                    finally: db.close()
                elif suffix in ('.log','.txt'):
                    for line in path.read_text(encoding='utf-8-sig',errors='replace').splitlines():
                        if line.lstrip().startswith('{'):
                            try:
                                value=json.loads(line)
                                for row in json_records(value): self._add(row,fid,when)
                            except ValueError: pass
                else:
                    self.warnings.append(f'{fid}: {suffix} requires independent extraction; no claims inferred')
            except Exception as e:
                self.warnings.append(f'Could not parse {fid}: {type(e).__name__}: {str(e)[:140]}')

    def _load_activities(self):
        # Activity rows are indexed only as weak contextual observations, never as authoritative snapshots.
        self.activities=read_csv(self.dataset/'system_activity.csv')


def identity_terms(identity):
    fields=identity.get('identifiers',{})
    return {k:set(map(norm,values)) for k,values in fields.items()}


def _reference_match(value, identity):
    """Exact identifier in a typed reference, not substring PII guessing.

    Supports scalar values, key=value / key:value references, and JSON dictionaries.
    Does not equate two different users based on a shared partial substring.
    """
    if value is None or isinstance(value, bool):
        return False
    ids=identity_terms(identity)
    identifiers={v for vals in ids.values() for v in vals if v}
    if not identifiers: return False
    if isinstance(value,dict):
        return any(_reference_match(v,identity) for v in value.values())
    if isinstance(value,list):
        return any(_reference_match(v,identity) for v in value)
    raw=norm(value)
    if raw in identifiers: return True
    if raw.startswith(('{','[')):
        try: return _reference_match(json.loads(str(value)),identity)
        except (ValueError,TypeError): pass
    # Strong equality only: we do not match emails appearing inside unrelated prose.
    typed=re.fullmatch(r'[a-z_][a-z_0-9]*\s*[:=]\s*[\"\']?([^\"\']+?)[\"\']?',raw)
    if typed and norm(typed.group(1)) in identifiers: return True
    return False


def matches_identity(obs,identity):
    ids=identity_terms(identity)
    for key, value in obs.fields.items():
        k=norm(key)
        if k in ID_KEYS and _reference_match(value,identity): return True
        if k in ('old_value','new_value') and _reference_match(value,identity): return True
    return False


def normalized_state(raw):
    """Translate only unambiguous evidence results; other values remain unknown."""
    x=norm(raw).replace(' ','_')
    known={
      'present':'PRESENT','exists':'PRESENT','found':'PRESENT',
      'absent':'ABSENT','not_found':'ABSENT','missing':'ABSENT',
      'deleted':'ABSENT','removed':'ABSENT',
      'redacted':'REDACTED','sanitized':'REDACTED',
      'anonymized':'ANONYMIZED','anonymous':'ANONYMIZED',
      'active':'ACTIVE','enabled':'ACTIVE','disabled':'DISABLED',
      'blocked':'BLOCKED',
    }
    return known.get(x,'')


def policy_action(category,fields,rules):
    category=category.upper()
    matching=[r for r in rules if r.get('data_category','').upper()==category]
    if not matching: return None
    action=matching[0]['required_action'].upper()
    if category=='ACCOUNT_TOMBSTONE': return 'REDACT'
    if category=='BACKUP_ARCHIVE': return 'RETAIN'
    if category=='LEGAL_HOLD_RECORD': return 'RETAIN'
    if category=='SECURITY_AUDIT_LOG': return 'RETAIN'
    if category in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY'):
        return 'ANONYMIZE' if any(norm(fields.get(k,'')) for k in ID_KEYS) else 'RETAIN'
    return action


def needs_action(obs,action):
    state=obs.state
    if action=='DELETE': return state not in ('ABSENT','DELETED','REMOVED')
    if action=='REDACT':
        return state not in ('REDACTED','SANITIZED') or any(norm(obs.fields.get(k,'')) for k in PII_FIELDS)
    if action=='ANONYMIZE': return state not in ('ANONYMIZED','ANONYMOUS')
    if action=='RETAIN': return state in ('ABSENT','DELETED','REMOVED')
    return False


def issue_ops(action,obs):
    if action=='DELETE': return ('REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT')
    if action=='REDACT': return ('REPORT_EXPOSED_PII','REDACT_RECORD','VERIFY_RECORD_REDACTED')
    if action=='ANONYMIZE': return ('REPORT_EXPOSED_PII','ANONYMIZE_RECORD','VERIFY_RECORD_ANONYMIZED')
    return (None,None,'VERIFY_RECORD_PRESENT')


def make_step(phase,system,resource,operation,evidence_id=''):
    return {'step_no':0,'phase':phase,'system_id':system,'resource_id':resource,'operation':operation,
            'state':STATES[operation],'evidence_id':evidence_id}


def canonicalize(steps):
    seen=set(); unique=[]
    for step in steps:
        key=tuple(step[k] for k in ('phase','system_id','resource_id','operation'))
        if key in seen: continue
        seen.add(key); unique.append(step)
    unique.sort(key=lambda s:(PHASES[s['phase']],OPERATIONS[s['phase']].index(s['operation']),s['system_id'],s['resource_id']))
    for i,s in enumerate(unique,1): s['step_no']=i
    return unique


def audit_case(case,identity,store,rules):
    intent=deletion_intent(case.get('request_text',''))
    if intent is False: return {'case_id':case['case_id'],'deletion_status':'NOT_APPLICABLE','steps_json':[]}, []
    issues=[]; steps=[]; review=[]
    if intent is None: review.append('request-intent ambiguous, cannot authorize deletion automatically')
    if identity.get('resolution')!='EXACT': review.append('identity unresolved or shared')
    cutoff=parse_time(case.get('audit_at'))
    if cutoff is None: review.append('missing valid audit_at')
    if review: return None,review
    matches=[]
    for obs in store.observations:
        seen=parse_time(obs.captured_at)
        if seen is None or seen > cutoff: continue
        if matches_identity(obs,identity): matches.append(obs)
    latest={}
    for obs in matches:
        key=(obs.system_id,obs.resource_id)
        if key not in latest or parse_time(obs.captured_at)>parse_time(latest[key].captured_at): latest[key]=obs
    for obs in latest.values():
        if not obs.state:
            review.append(f'unknown evidence result for {obs.system_id}/{obs.resource_id}; cannot infer state')
            continue
        action=policy_action(obs.category,obs.fields,rules)
        if action is None:
            review.append(f'Unknown policy category on {obs.system_id}/{obs.resource_id}: {obs.category or "missing"}'); continue
        finding,remedy,verify=issue_ops(action,obs)
        if needs_action(obs,action):
            if finding:
                steps.append(make_step('FINDING',obs.system_id,obs.resource_id,finding,obs.evidence_id))
            if remedy:
                steps.append(make_step('REMEDIATION',obs.system_id,obs.resource_id,remedy))
            steps.append(make_step('VERIFICATION',obs.system_id,obs.resource_id,verify))
            issues.append((obs.system_id,obs.resource_id))
        elif obs.state or action=='RETAIN':
            steps.append(make_step('VERIFICATION',obs.system_id,obs.resource_id,verify,obs.evidence_id))
    if not latest: review.append('no attributable structured evidence at audit time')
    if review: return None,review
    status='INCOMPLETE' if issues else 'COMPLETE'
    if status=='INCOMPLETE':
        steps=[s for s in steps if s['phase']!='VERIFICATION' or (s['system_id'],s['resource_id']) in issues]
    else:
        steps=[s for s in steps if s['phase']=='VERIFICATION']
    return {'case_id':case['case_id'],'deletion_status':status,'steps_json':canonicalize(steps)},[]
