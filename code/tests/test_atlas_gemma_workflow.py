import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlas_gemma_workflow import sanitized_facts, select_authoritative_rule, run

RULE = {'rule_id': 'rule_05', 'data_category': 'SUPPORT_MESSAGE',
        'condition': 'Shared context', 'required_action': 'REDACT', 'score': 0.873}
OTHER = {'rule_id': 'rule_06', 'data_category': 'SUPPORT_ATTACHMENT',
         'condition': 'Private attachment', 'required_action': 'DELETE', 'score': 0.9}

class AtlasGemmaTests(unittest.TestCase):
    def test_exact_category_beats_score(self):
        assert select_authoritative_rule([OTHER, RULE], 'SUPPORT_MESSAGE')['rule_id'] == 'rule_05'

    def test_missing_category_fails_closed(self):
        with self.assertRaises(ValueError):
            select_authoritative_rule([RULE], 'USER_PROFILE')

    def test_ambiguous_category_fails_closed(self):
        with self.assertRaises(ValueError):
            select_authoritative_rule([RULE, dict(RULE)], 'SUPPORT_MESSAGE')

    def test_sensitive_raw_fact_rejected(self):
        with self.assertRaises(ValueError):
            sanitized_facts({'email': 'user@example.com'})

    @patch('atlas_gemma_workflow.interpret')
    @patch('atlas_gemma_workflow.retrieve_policies')
    def test_agent_only_runs_after_exact_match(self, retrieve, interpret):
        retrieve.return_value = [OTHER, RULE]
        interpret.return_value = {'validated_policy_advice': {'interpretation': 'APPLIES'}}
        report = run('shared customer support conversation', 'SUPPORT_MESSAGE', {'shared_context': True})
        self.assertEqual(report['retrieval']['matched_rule_id'], 'rule_05')
        self.assertIn('NONE', report['audit_impact'])
        interpret.assert_called_once()
        with self.assertRaises(ValueError):
            run('wrong', 'LEGAL_HOLD_RECORD', {'shared_context': True})
        interpret.assert_called_once()

if __name__ == '__main__':
    unittest.main()
