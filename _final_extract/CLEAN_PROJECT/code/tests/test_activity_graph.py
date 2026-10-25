import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from activity_graph import parse_details, linked_users, identity_index

class ActivityGraphTests(unittest.TestCase):
    def setUp(self):
        self.idx=identity_index([{'user_id':'u-1','email':'old@example.com','name':'User One'}, {'user_id':'u-2','email':'other@example.com','name':'User Two'}],[])
    def test_kv_text(self):
        self.assertEqual(parse_details('SYNC_RECORD user_id=u-1 source=crm')[0],[('user_id','u-1')])
    def test_colon_text(self):
        self.assertEqual(parse_details('subject_reference: old@example.com; status: success')[0],[('subject_reference','old@example.com')])
    def test_json(self):
        self.assertEqual(parse_details('{"meta":{"user_id":"u-1"}}')[0],[('user_id','u-1')])
    def test_python_literal(self):
        self.assertEqual(parse_details("{'lookup_value': 'old@example.com'}")[0],[('lookup_value','old@example.com')])
    def test_explicit_link(self):
        self.assertEqual(linked_users(parse_details('email=old@example.com')[0],self.idx),{'u-1'})
    def test_does_not_fuzzy_match(self):
        self.assertEqual(linked_users(parse_details('I spoke to old@example.com yesterday')[0],self.idx),set())
    def test_ambiguous(self):
        pairs=parse_details('email=old@example.com; email=other@example.com')[0]
        self.assertEqual(len(linked_users(pairs,self.idx)),2)

if __name__=='__main__': unittest.main()
