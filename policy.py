"""Small deterministic deny-overrides policy language; no expression execution."""
import copy
import math
import re


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f'{label} needs exactly: {", ".join(keys)}.')


def name(value, label):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,47}', value):
        raise ValueError(f'{label} must be a simple 1–48 character name.')
    return value


def scalar(value):
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str) and len(value) <= 120:
        return
    if type(value) in (int, float) and abs(value) <= 1e9 and math.isfinite(value):
        return
    raise ValueError('Attribute values must be null, booleans, strings up to 120 characters, or finite numbers within ±1e9.')


def names(values, label, wildcard=False):
    if not isinstance(values, list) or not 1 <= len(values) <= 20 or len(set(v for v in values if isinstance(v, str))) != len(values):
        raise ValueError(f'{label} needs 1–20 distinct names.')
    for value in values:
        if value != '*' or not wildcard:
            name(value, label)


def validate_policy(value):
    exact(value, ['name', 'rules'], 'Policy')
    if not isinstance(value['name'], str) or not value['name'].strip() or not 1 <= len(value['name']) <= 80:
        raise ValueError('Policy name must contain 1–80 characters.')
    if not isinstance(value['rules'], list) or len(value['rules']) > 50:
        raise ValueError('A policy may contain at most 50 rules.')
    ids = set()
    for rule in value['rules']:
        exact(rule, ['id', 'effect', 'actions', 'roles', 'conditions'], 'Rule')
        name(rule['id'], 'Rule ID')
        if rule['id'] in ids:
            raise ValueError('Rule IDs must be unique.')
        ids.add(rule['id'])
        if rule['effect'] not in ('allow', 'deny'):
            raise ValueError('Effect must be allow or deny.')
        names(rule['actions'], 'Actions', True)
        names(rule['roles'], 'Roles', True)
        if not isinstance(rule['conditions'], list) or len(rule['conditions']) > 8:
            raise ValueError('Each rule may contain at most eight conditions.')
        for condition in rule['conditions']:
            exact(condition, ['path', 'op', 'value'], 'Condition')
            if not isinstance(condition['path'], str) or not re.fullmatch(r'(subject|resource)\.[A-Za-z][A-Za-z0-9_]{0,31}', condition['path']):
                raise ValueError('Condition paths use subject.attribute or resource.attribute.')
            op = condition['op']
            if op not in ('eq', 'neq', 'in', 'gte', 'lte'):
                raise ValueError('Condition operators: eq, neq, in, gte, lte.')
            if op == 'in':
                if not isinstance(condition['value'], list) or not 1 <= len(condition['value']) <= 20:
                    raise ValueError('The in operator needs 1–20 scalar values.')
                for item in condition['value']:
                    scalar(item)
            else:
                scalar(condition['value'])
            if op in ('gte', 'lte') and type(condition['value']) not in (int, float):
                raise ValueError('Numeric comparisons need a numeric policy value.')
    return copy.deepcopy(value)


def validate_request(value):
    exact(value, ['action', 'roles', 'subject', 'resource'], 'Request')
    name(value['action'], 'Action')
    if value['roles'] != []:
        names(value['roles'], 'Request roles')
    for section in ('subject', 'resource'):
        attrs = value[section]
        if not isinstance(attrs, dict) or len(attrs) > 20:
            raise ValueError('Each attribute section needs an object with at most 20 entries.')
        for key, val in attrs.items():
            if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,31}', key):
                raise ValueError('Attribute names use 1–32 letters, digits, or underscores, starting with a letter.')
            scalar(val)
    return copy.deepcopy(value)


def equal(a, b):
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    return type(a) is type(b) and a == b


def evaluate(policy, request):
    policy, request = validate_policy(policy), validate_request(request)
    rows, allows, denies = [], [], []
    for rule in policy['rules']:
        checks = [
            {'check': 'action', 'matched': '*' in rule['actions'] or request['action'] in rule['actions'], 'actual': request['action'], 'expected': rule['actions']},
            {'check': 'roles', 'matched': '*' in rule['roles'] or bool(set(request['roles']) & set(rule['roles'])), 'actual': request['roles'], 'expected': rule['roles']},
        ]
        for condition in rule['conditions']:
            section, key = condition['path'].split('.')
            present = key in request[section]
            actual = request[section].get(key)
            wanted, op = condition['value'], condition['op']
            matched = False
            if present:
                if op == 'eq':
                    matched = equal(actual, wanted)
                elif op == 'neq':
                    matched = not equal(actual, wanted)
                elif op == 'in':
                    matched = any(equal(actual, item) for item in wanted)
                elif type(actual) in (int, float):
                    matched = actual >= wanted if op == 'gte' else actual <= wanted
            checks.append({'check': condition['path'], 'op': op, 'present': present, 'actual': actual, 'expected': wanted, 'matched': matched})
        matched = all(c['matched'] for c in checks)
        rows.append({'id': rule['id'], 'effect': rule['effect'], 'matched': matched, 'checks': checks})
        if matched:
            (allows if rule['effect'] == 'allow' else denies).append(rule['id'])
    decision = 'deny' if denies or not allows else 'allow'
    return {'decision': decision, 'reason': 'explicit-deny' if denies else 'matching-allow' if allows else 'default-deny', 'allows': allows, 'denies': denies, 'rules': rows}


def sample_policy():
    return {'name': 'Research workspace', 'rules': [
        {'id': 'read-public', 'effect': 'allow', 'actions': ['read'], 'roles': ['*'], 'conditions': [{'path': 'resource.classification', 'op': 'eq', 'value': 'public'}]},
        {'id': 'analyst-internal', 'effect': 'allow', 'actions': ['read'], 'roles': ['analyst'], 'conditions': [{'path': 'resource.classification', 'op': 'in', 'value': ['public', 'internal']}, {'path': 'subject.clearance', 'op': 'gte', 'value': 2}]},
        {'id': 'suspended-subject', 'effect': 'deny', 'actions': ['*'], 'roles': ['*'], 'conditions': [{'path': 'subject.suspended', 'op': 'eq', 'value': True}]},
    ]}


def sample_requests():
    return [
        {'action': 'read', 'roles': [], 'subject': {}, 'resource': {'classification': 'public'}},
        {'action': 'read', 'roles': ['analyst'], 'subject': {'clearance': 2, 'suspended': False}, 'resource': {'classification': 'internal'}},
        {'action': 'read', 'roles': ['analyst'], 'subject': {'clearance': 1}, 'resource': {'classification': 'internal'}},
        {'action': 'read', 'roles': ['analyst'], 'subject': {'clearance': 3, 'suspended': True}, 'resource': {'classification': 'public'}},
        {'action': 'write', 'roles': ['analyst'], 'subject': {'clearance': 3}, 'resource': {'classification': 'internal'}},
    ]
