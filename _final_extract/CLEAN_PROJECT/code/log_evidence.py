"""Strictly extract observations from completed log readbacks with trace-correlated identity.
Do not treat successful workflow operations as proof of state.
"""
import json,re,shlex

TS=re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)')
PAIR=re.compile(r'([a-zA-Z_][a-zA-Z_0-9]*)=(?:"([^"]*)"|([^\s|]+))')
TRACE=re.compile(r'\b(?:tr-\d+|rb-\d+-\d+)\b')
ALLOWED={
 'profile_lookup_completed':('USER_PROFILE','account_service'),
 'index_query_completed':('SEARCH_INDEX_ENTRY','search_service'),
 'support_ticket_read_completed':('SUPPORT_MESSAGE','support_platform'),
 'attachment_read_completed':('SUPPORT_ATTACHMENT','support_platform'),
 'analytics_profile_read_completed':('ANALYTICS_PROFILE','analytics_platform'),
 'audit_record_read_completed':('SECURITY_AUDIT_LOG','security_service'),
 'restore_policy_read_completed':('BACKUP_ARCHIVE','backup_service'),
 'connector_config_read_completed':('DATA_FLOW','integration_service'),
}
START_ID_FIELDS=('lookup_key','match_key','subject_key','scan_key','correlation_key','customer_email','customer_reference','subject_reference')

def extract(path):
    traces={}
    for line in path.read_text(encoding='utf-8-sig',errors='replace').splitlines():
        ts=TS.match(line)
        if not ts: continue
        when=ts.group(1)
        obj=None
        start=line.find('{')
        if start!=-1:
            try: obj=json.loads(line[start:])
            except (ValueError,TypeError): pass
        raw={k:(a if a!='' else b) for k,a,b in PAIR.findall(line)}
        data={**raw,**obj} if isinstance(obj,dict) else raw
        m=TRACE.search(line)
        trace=str(data.get('trace_id') or (m.group(0) if m else ''))
        event=str(data.get('event',''))
        if not event:
            for name in ALLOWED:
                if re.search(r'\b'+name+r'\b',line): event=name; break
        if not event:
            m2=re.search(r'\b([a-z_]+_(?:started|completed|read|hit)):',line)
            if m2: event=m2.group(1)
        if trace:
            stored=traces.setdefault(trace,{})
            for key in START_ID_FIELDS:
                v=data.get(key)
                if v and str(v).casefold() not in ('null','none','unknown'):
                    stored[key]=v
        if event not in ALLOWED: continue
        if not data.get('resource_id'): continue
        # Don't turn a mere "completed" operation into proof of deletion.
        category,system=ALLOWED[event]
        state=''
        if event=='profile_lookup_completed':
            if str(data.get('rows','')).strip()=='0' or str(data.get('http_status',''))=='404': state='ABSENT'
            elif str(data.get('rows','')).strip()=='1' or str(data.get('http_status',''))=='200': state='PRESENT'
        elif event=='index_query_completed':
            if data.get('result')=='hit' or data.get('total_hits') not in (None,'0',0): state='PRESENT'
            elif data.get('result') in ('miss','not_found') or str(data.get('total_hits',''))=='0': state='ABSENT'
        elif event=='support_ticket_read_completed':
            state='PRESENT' # record exists; may require redaction depending on fields
        elif event=='analytics_profile_read_completed':
            state='PRESENT'
        elif event=='audit_record_read_completed':
            if str(data.get('rows',''))=='1': state='PRESENT'
        elif event=='restore_policy_read_completed':
            state='PRESENT' if str(data.get('archive_present','')).lower()=='true' else ('ABSENT' if str(data.get('archive_present','')).lower()=='false' else '')
        elif event=='connector_config_read_completed':
            state='ACTIVE' if str(data.get('enabled','')).lower()=='true' else ('DISABLED' if str(data.get('enabled','')).lower()=='false' else '')
        if not state: continue
        result=dict(data)
        for k,v in traces.get(trace,{}).items(): result.setdefault(k,v)
        # An identity on an earlier started line is only used if a single correlated trace identifier exists.
        result['system_id']=system
        result['data_category']=category
        result['state']=state
        result['captured_at']=when
        # drop unreliable null-valued lookup identifiers
        for k in list(result):
            if str(result[k]).casefold() in ('null','none','unknown'): result.pop(k)
        yield result
