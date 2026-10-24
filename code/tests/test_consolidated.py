import sys,unittest,tempfile,csv,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from policy_agent import validate_advice
from engine import canonicalize,make_step
from gemma_agent import interpret

class ConsolidationTests(unittest.TestCase):
    def test_sorting(self):
        steps=[make_step('REMEDIATION','b','x','DELETE_RECORD'), make_step('FINDING','a','x','REPORT_REMAINING_RECORD','evidence_1')]
        result=canonicalize(steps)
        self.assertEqual([r['phase'] for r in result],['FINDING','REMEDIATION'])
    def test_policy_advice_rejects_status_injection(self):
        rule={'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE'}
        with self.assertRaises(ValueError):validate_advice({'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE','interpretation':'APPLIES','supporting_fact_keys':['shared'],'reason':'yes','deletion_status':'COMPLETE'},rule,{'shared':True})
    def test_model_rejects_raw_pii_before_network_call(self):
        with self.assertRaises(ValueError):interpret({'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE','condition':'x','required_action':'REDACT'}, {'email':'person@example.com'})
if __name__=='__main__':unittest.main()
