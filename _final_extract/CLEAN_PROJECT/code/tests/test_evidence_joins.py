import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import Observation, matches_identity, normalized_state, EvidenceStore

IDENTITY={'resolution':'EXACT','user_id':'u17','identifiers': {'user_id':['u17'],'email':['new@example.com','old@example.com'],'email_hash':['hash123']}}

class JoinTests(unittest.TestCase):
    def test_typed_subject_reference(self):
        o=Observation('crm','r1','USER_PROFILE','PRESENT','e1','2026-01-01',{'subject_reference':'user_id=u17'})
        self.assertTrue(matches_identity(o,IDENTITY))
    def test_lookup_historical_email(self):
        o=Observation('crm','r1','USER_PROFILE','PRESENT','e1','2026-01-01',{'lookup_value':'old@example.com'})
        self.assertTrue(matches_identity(o,IDENTITY))
    def test_no_substring_mismatch(self):
        o=Observation('crm','r1','USER_PROFILE','PRESENT','e1','2026-01-01',{'lookup_value':'old@example.com.attacker'})
        self.assertFalse(matches_identity(o,IDENTITY))
    def test_result_mapping(self):
        self.assertEqual(normalized_state('not_found'),'ABSENT')
        self.assertEqual(normalized_state('redacted'),'REDACTED')
        self.assertEqual(normalized_state('success'),'')
    def test_recorded_at_and_result_loaded(self):
        store=object.__new__(EvidenceStore)
        store.observations=[]
        store._add({'recorded_at':'2026-08-01T00:00:00Z','system':'CRM','resource_id':'r1','record_type':'USER_PROFILE','result':'present','subject_reference':'user_id:u17'},'evidence_01','2026-08-03T00:00:00Z')
        self.assertEqual(len(store.observations),1)
        self.assertEqual(store.observations[0].captured_at,'2026-08-01T00:00:00Z')
        self.assertEqual(store.observations[0].state,'PRESENT')

if __name__=='__main__': unittest.main()
