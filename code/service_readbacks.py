"""Participant-facing service readbacks: explicit state and typed identity only.

No inferred deletion statuses from workflow reports; no ownership assigned from resource IDs.
"""
from __future__ import annotations

SOURCES = {
    ('account_service','profile_lookups'): ('USER_PROFILE','account_service'),
    ('analytics_platform','profiles'): ('ANALYTICS_PROFILE','analytics_platform'),
    ('backup_service','restore_entries'): ('BACKUP_ARCHIVE','backup_service'),
    ('export_service','exports'): ('USER_EXPORT','export_service'),
    ('integration_service','connectors'): ('DATA_FLOW','integration_service'),
    ('search_service','index_queries'): ('SEARCH_INDEX_ENTRY','search_service'),
    ('security_service','audit_records'): ('SECURITY_AUDIT_LOG','security_service'),
    ('support_platform','tickets'): ('SUPPORT_MESSAGE','support_platform'),
}

def extract_service_exports(document):
    for service, group in document.get('service_exports',{}).items():
        if not isinstance(group,dict): continue
        for collection, values in group.items():
            if not isinstance(values,list) or (service,collection) not in SOURCES: continue
            category,system=SOURCES[(service,collection)]
            for source in values:
                if not isinstance(source,dict) or not source.get('resource_id'): continue
                row=dict(source)
                row['system_id']=system
                row['data_category']=category
                if category=='USER_PROFILE':
                    code=str(source.get('status_code',''))
                    if code=='404' and source.get('profile') is None: state='ABSENT'
                    elif code=='200' and isinstance(source.get('profile'),dict): state='PRESENT'
                    else: continue
                    if isinstance(source.get('profile'),dict):
                        row.update(source['profile'])
                elif category=='SEARCH_INDEX_ENTRY':
                    hits=source.get('hits')
                    if not isinstance(hits,dict): continue
                    count=hits.get('total')
                    if not isinstance(count,int) or count<0: continue
                    state='PRESENT' if count else 'ABSENT'
                    documents=hits.get('documents',[])
                    if count>0 and isinstance(documents,list) and len(documents)==1 and isinstance(documents[0],dict):
                        row.update(documents[0])
                    if source.get('query'): row['lookup_key']=source['query']
                elif category=='DATA_FLOW':
                    enabled=source.get('enabled')
                    if not isinstance(enabled,bool): continue
                    state='ACTIVE' if enabled else 'DISABLED'
                elif category=='BACKUP_ARCHIVE':
                    permitted=source.get('restore_allowed')
                    if not isinstance(permitted,bool): continue
                    state='ACTIVE' if permitted else 'BLOCKED'
                elif category=='SECURITY_AUDIT_LOG': state='PRESENT'
                elif category in ('USER_EXPORT','SUPPORT_MESSAGE','ANALYTICS_PROFILE'): state='PRESENT'
                else: continue
                row['state']=state
                yield row
