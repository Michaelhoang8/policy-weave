"""Immutable policy revisions with optimistic, transactional publication."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from policy import validate_policy, validate_request, evaluate, exact, sample_policy


class Conflict(Exception):
    pass


class Missing(Exception):
    pass


class Integrity(Exception):
    pass


def encoded(policy):
    return json.dumps(policy, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def digest(payload):
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def revision_id(value):
    if type(value) is not int or value < 1:
        raise ValueError('Revision IDs must be positive integers.')
    return value


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS revisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT NOT NULL, digest TEXT NOT NULL,
                    note TEXT NOT NULL, created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL REFERENCES revisions(id));
            ''')
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT revision FROM head WHERE singleton=1').fetchone() is None:
                payload = encoded(sample_policy())
                rid = db.execute('INSERT INTO revisions(payload,digest,note) VALUES(?,?,?)', (payload,digest(payload),'Initial fictional example')).lastrowid
                db.execute('INSERT INTO head(singleton,revision) VALUES(1,?)',(rid,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def load(db, rid):
        row = db.execute('SELECT * FROM revisions WHERE id=?',(rid,)).fetchone()
        if row is None:
            raise Missing('Policy revision not found.')
        if digest(row['payload']) != row['digest']:
            raise Integrity('Stored policy digest mismatch. Restore the database from a trusted backup.')
        try:
            policy = validate_policy(json.loads(row['payload']))
        except (ValueError, RecursionError) as error:
            raise Integrity('Stored policy is invalid.') from error
        return {'id': row['id'], 'policy': policy, 'digest': row['digest'], 'note': row['note'], 'created': row['created']}

    def get(self, rid):
        with self.connect() as db:
            return self.load(db, revision_id(rid))

    def state(self):
        with self.connect() as db:
            db.execute('BEGIN')
            rid = db.execute('SELECT revision FROM head WHERE singleton=1').fetchone()[0]
            history = [dict(r) for r in db.execute('SELECT id,digest,note,created FROM revisions ORDER BY id DESC LIMIT 100')]
            return {'head': self.load(db,rid), 'history': history, 'total': db.execute('SELECT count(*) FROM revisions').fetchone()[0]}

    def publish(self, value):
        exact(value, ['expected', 'policy', 'note'], 'Publication')
        expected = revision_id(value['expected'])
        policy = validate_policy(value['policy'])
        if not isinstance(value['note'], str) or not 1 <= len(value['note'].strip()) <= 240:
            raise ValueError('A revision note needs 1–240 characters.')
        payload = encoded(policy)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT revision FROM head WHERE singleton=1').fetchone()[0]
            if current != expected:
                raise Conflict(f'Head changed from revision {expected} to {current}. Refresh before publishing.')
            self.load(db,current)
            if db.execute('SELECT count(*) FROM revisions').fetchone()[0] >= 2000:
                raise ValueError('This local database has reached its 2,000-revision limit.')
            rid = db.execute('INSERT INTO revisions(payload,digest,note) VALUES(?,?,?)', (payload,digest(payload),value['note'].strip())).lastrowid
            db.execute('UPDATE head SET revision=? WHERE singleton=1',(rid,))
            return self.load(db,rid)

    def decide(self, value):
        exact(value, ['revision', 'request'], 'Decision')
        revision = self.get(value['revision'])
        return {'revision': revision['id'], 'digest': revision['digest'], **evaluate(revision['policy'],value['request'])}

    def compare(self, value):
        exact(value, ['before', 'after', 'requests'], 'Comparison')
        before, after = self.get(value['before']), self.get(value['after'])
        if not isinstance(value['requests'], list) or not 1 <= len(value['requests']) <= 100:
            raise ValueError('Compare 1–100 requests.')
        requests = [validate_request(r) for r in value['requests']]
        rows = []
        for i, request in enumerate(requests):
            a, b = evaluate(before['policy'],request), evaluate(after['policy'],request)
            rows.append({'index': i, 'request': request, 'changed': a['decision'] != b['decision'], 'before': {k:v for k,v in a.items() if k != 'rules'}, 'after': {k:v for k,v in b.items() if k != 'rules'}})
        return {'before': before['id'], 'after': after['id'], 'beforeDigest': before['digest'], 'afterDigest': after['digest'], 'changed': sum(r['changed'] for r in rows), 'total': len(rows), 'rows': rows}
