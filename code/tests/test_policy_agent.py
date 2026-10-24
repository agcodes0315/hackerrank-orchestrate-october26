import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from policy_agent import validate_advice
RULE={'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE'}
class PolicyContractTests(unittest.TestCase):
    def test_accepts_bounded_interpretation(self):
        value={'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE','interpretation':'UNCERTAIN','supporting_fact_keys':[],'reason':'Cannot prove shared context'}
        self.assertEqual(validate_advice(value,RULE,{}),value)
    def test_rejects_invented_evidence(self):
        value={'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE','interpretation':'APPLIES','supporting_fact_keys':['invented'],'reason':'X'}
        with self.assertRaises(ValueError): validate_advice(value,RULE,{})
    def test_rejects_status_override(self):
        value={'rule_id':'rule_05','data_category':'SUPPORT_MESSAGE','interpretation':'UNCERTAIN','supporting_fact_keys':[],'reason':'X','deletion_status':'COMPLETE'}
        with self.assertRaises(ValueError): validate_advice(value,RULE,{})
if __name__=='__main__':unittest.main()
