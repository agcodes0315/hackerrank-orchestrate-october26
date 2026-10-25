import unittest
from datetime import timezone
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from engine import deletion_intent,canonicalize,make_step,Observation,needs_action,parse_time,policy_action

class EngineTests(unittest.TestCase):
    def test_negation_is_not_deletion(self):
        self.assertFalse(deletion_intent('Please do not delete my account.'))
    def test_deletion_is_authorized(self):
        self.assertTrue(deletion_intent('Erase my personal data under the right to be forgotten.'))
    def test_unclassified_request_requires_review(self):
        self.assertIsNone(deletion_intent('Help me with a question.'))
    def test_phase_and_operation_order(self):
        values=[make_step('VERIFICATION','z','a','VERIFY_RECORD_ABSENT'),make_step('REMEDIATION','b','a','DELETE_RECORD'),make_step('FINDING','a','z','REPORT_EXPOSED_PII'),make_step('FINDING','z','a','REPORT_REMAINING_RECORD')]
        sorted_values=canonicalize(values)
        self.assertEqual([x['operation'] for x in sorted_values],['REPORT_REMAINING_RECORD','REPORT_EXPOSED_PII','DELETE_RECORD','VERIFY_RECORD_ABSENT'])
        self.assertEqual([x['step_no'] for x in sorted_values],[1,2,3,4])
    def test_tombstone_requires_redaction(self):
        obs=Observation('accounts','acct1','ACCOUNT_TOMBSTONE','PRESENT','e1','2026-10-01T00:00:00Z',{'user_id':'u1','email':'old@example.com'})
        self.assertEqual(policy_action('ACCOUNT_TOMBSTONE',obs.fields,[{'data_category':'ACCOUNT_TOMBSTONE','required_action':'REDACT'}]),'REDACT')
        self.assertTrue(needs_action(obs,'REDACT'))
    def test_utc_dates(self):
        self.assertEqual(parse_time('2026-10-01T02:00:00+02:00'),parse_time('2026-10-01T00:00:00Z'))
if __name__=='__main__':unittest.main()
