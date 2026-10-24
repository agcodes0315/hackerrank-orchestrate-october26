import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from lifecycle import timeline_for_resource, classify_timeline, latest_observations
from engine import Observation

class LifecycleTests(unittest.TestCase):
    def event(self,aid,typ,resource,date,src='search'):
        return {'activity_id':aid,'event_type':typ,'resource_id':resource,'event_time':date,
                'source_system':src,'target_system':'archive','reported_result':'SUCCESS'}

    def test_exact_resource_and_audit_cutoff(self):
        events=[self.event('a','DELETE_RECORD','r1','2026-01-01T00:00:00Z'),
                self.event('b','SYNC_RECORD','r10','2026-01-02T00:00:00Z'),
                self.event('c','SYNC_RECORD','r1','2026-01-04T00:00:00Z')]
        result=timeline_for_resource(events,'r1','2026-01-03T00:00:00Z')
        self.assertEqual([e['activity_id'] for e in result],['a'])

    def test_resurrection_after_delete_flagged_not_proven(self):
        events=[self.event('a','DELETE_RECORD','r1','2026-01-01T00:00:00Z'),
                self.event('b','SYNC_RECORD','r1','2026-01-02T00:00:00Z')]
        self.assertEqual(classify_timeline(events)['risk'],'POSSIBLE_RESURRECTION_REQUIRES_VERIFICATION')

    def test_no_resurrection_if_sync_before_delete(self):
        events=[self.event('a','SYNC_RECORD','r1','2026-01-01T00:00:00Z'),
                self.event('b','DELETE_RECORD','r1','2026-01-02T00:00:00Z')]
        self.assertEqual(classify_timeline(events)['risk'],'NO_LATER_RECREATION_EVENT_SEEN')

    def test_snapshot_prefers_latest_before_audit(self):
        def o(state,when):
            return Observation('search','r1','SEARCH_INDEX_ENTRY',state,'evidence_1',when,{})
        observations=[o('PRESENT','2026-01-01T00:00:00Z'),o('ABSENT','2026-01-02T00:00:00Z'),o('PRESENT','2026-01-04T00:00:00Z')]
        self.assertEqual(latest_observations(observations,'2026-01-03T00:00:00Z')[0].state,'ABSENT')

if __name__=='__main__':unittest.main()
