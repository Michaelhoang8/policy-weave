import concurrent.futures
import tempfile
import unittest
from pathlib import Path
from policy import sample_policy,sample_requests
from store import Store,Conflict,Integrity,Missing,digest,encoded


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'policy.sqlite3';self.store=Store(self.path)

    def tearDown(self):self.temp.cleanup()

    def publish(self,policy=None,expected=1):
        return self.store.publish({'expected':expected,'policy':policy or sample_policy(),'note':'Reviewed change'})

    def test_revision_roundtrip_reopen_and_stale_publication(self):
        old=self.store.get(1);p=sample_policy();p['rules'][1]['conditions'][1]['value']=3
        new=self.publish(p)
        self.assertEqual(new['id'],2);self.assertEqual(self.store.get(1),old)
        self.assertEqual(Store(self.path).state()['head']['id'],2)
        with self.assertRaises(Conflict):self.publish()
        self.assertEqual(self.store.state()['total'],2)

    def test_concurrent_publish_has_exactly_one_winner(self):
        def attempt(n):
            try:return self.store.publish({'expected':1,'policy':sample_policy(),'note':f'Writer {n}'})['id']
            except Conflict:return 'conflict'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(attempt,range(8)))
        self.assertEqual(results.count(2),1);self.assertEqual(results.count('conflict'),7)
        self.assertEqual(self.store.state()['total'],2)

    def test_injected_head_failure_rolls_back_revision(self):
        with self.store.connect() as db:
            db.execute("CREATE TRIGGER fail_head BEFORE UPDATE ON head BEGIN SELECT RAISE(ABORT,'injected'); END")
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):self.publish()
        self.assertEqual(self.store.state()['total'],1)
        self.assertEqual(self.store.state()['head']['id'],1)

    def test_batch_comparison_finds_changed_decisions_and_restoration(self):
        p=sample_policy();p['rules'][1]['conditions'][1]['value']=3;self.publish(p)
        result=self.store.compare({'before':1,'after':2,'requests':sample_requests()})
        self.assertEqual(result['changed'],1);self.assertTrue(result['rows'][1]['changed'])
        self.assertEqual(result['rows'][1]['before']['decision'],'allow')
        self.assertEqual(result['rows'][1]['after']['reason'],'default-deny')
        restored=self.publish(self.store.get(1)['policy'],2)
        self.assertEqual(restored['id'],3);self.assertEqual(restored['digest'],self.store.get(1)['digest'])
        self.assertEqual(self.store.compare({'before':1,'after':3,'requests':sample_requests()})['changed'],0)

    def test_digest_detects_payload_corruption_and_canonical_order(self):
        self.assertEqual(digest(encoded({'name':'x','rules':[]})),digest(encoded({'rules':[],'name':'x'})))
        with self.store.connect() as db:db.execute("UPDATE revisions SET payload='{}' WHERE id=1")
        with self.assertRaises(Integrity):self.store.get(1)
        with self.assertRaises(Integrity):self.publish()

    def test_invalid_requests_do_not_create_revisions(self):
        for value in [{'expected':True,'policy':sample_policy(),'note':'x'},{'expected':1,'policy':{},'note':'x'},{'expected':1,'policy':sample_policy(),'note':''}]:
            with self.assertRaises(ValueError):self.store.publish(value)
        with self.assertRaises(Missing):self.store.get(99)
        with self.assertRaises(ValueError):self.store.compare({'before':1,'after':1,'requests':[]})
        self.assertEqual(self.store.state()['total'],1)


if __name__=='__main__':unittest.main()
