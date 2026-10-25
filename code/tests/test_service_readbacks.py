import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from service_readbacks import extract_service_exports
from engine import audit_case,Observation

class ServiceReadbacksTests(unittest.TestCase):
    def test_status_404_with_null_profile_is_absent(self):
        src={'service_exports':{'account_service':{'profile_lookups':[{'resource_id':'acct_1','status_code':404,'profile':None,'observed_at':'2026-01-01T00:00:00Z'}]}}}
        self.assertEqual(next(extract_service_exports(src))['state'],'ABSENT')
    def test_200_requires_actual_profile(self):
        src={'service_exports':{'account_service':{'profile_lookups':[{'resource_id':'acct_1','status_code':200,'profile':None}]}}}
        self.assertEqual(list(extract_service_exports(src)),[])
    def test_enabled_connector_is_active(self):
        src={'service_exports':{'integration_service':{'connectors':[{'resource_id':'flow1','enabled':True,'customer_reference':'user_7'}]}}}
        self.assertEqual(next(extract_service_exports(src))['state'],'ACTIVE')
    def test_backup_restore_is_risk_when_allowed(self):
        src={'service_exports':{'backup_service':{'restore_entries':[{'resource_id':'b1','restore_allowed':True,'customer_reference':'user_7'}]}}}
        self.assertEqual(next(extract_service_exports(src))['state'],'ACTIVE')
    def test_unknown_search_count_not_assumed_absent(self):
        src={'service_exports':{'search_service':{'index_queries':[{'resource_id':'idx1','hits':{'total':None}}]}}}
        self.assertEqual(list(extract_service_exports(src)),[])

if __name__=='__main__':unittest.main()
