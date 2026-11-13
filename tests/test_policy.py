import copy
import itertools
import unittest
from policy import evaluate, validate_policy, validate_request, sample_policy, sample_requests


class PolicyTests(unittest.TestCase):
    def test_example_decisions_and_deny_precedence(self):
        result=[evaluate(sample_policy(),r) for r in sample_requests()]
        self.assertEqual([r['decision'] for r in result],['allow','allow','deny','deny','deny'])
        self.assertEqual(result[3]['reason'],'explicit-deny')
        self.assertIn('read-public',result[3]['allows'])
        self.assertEqual(result[3]['denies'],['suspended-subject'])

    def test_rule_order_does_not_change_decision(self):
        policy=sample_policy()
        for rules in itertools.permutations(policy['rules']):
            candidate={**policy,'rules':list(rules)}
            for request in sample_requests():
                self.assertEqual(evaluate(candidate,request)['decision'],evaluate(policy,request)['decision'])

    def test_missing_attributes_never_match_even_neq_or_null(self):
        p={'name':'Missing','rules':[{'id':'r','effect':'allow','roles':['*'],'actions':['*'],'conditions':[{'path':'subject.a','op':'neq','value':1}]}]}
        r=sample_requests()[0]
        self.assertEqual(evaluate(p,r)['decision'],'deny')
        self.assertFalse(evaluate(p,r)['rules'][0]['checks'][2]['present'])
        p['rules'][0]['conditions'][0]={'path':'subject.a','op':'eq','value':None}
        self.assertEqual(evaluate(p,r)['decision'],'deny')
        r['subject']['a']=None
        self.assertEqual(evaluate(p,r)['decision'],'allow')

    def test_strict_scalar_types_and_numeric_boundaries(self):
        p={'name':'Types','rules':[{'id':'r','effect':'allow','roles':['*'],'actions':['*'],'conditions':[{'path':'subject.a','op':'eq','value':1}]}]}
        for actual,expected in [(True,'deny'),('1','deny'),(1.0,'allow'),(None,'deny')]:
            r=sample_requests()[0];r['subject']['a']=actual
            self.assertEqual(evaluate(p,r)['decision'],expected)
        p['rules'][0]['conditions'][0]['op']='gte'
        for actual,expected in [(False,'deny'),('3','deny'),(1,'allow'),(0.99,'deny')]:
            r['subject']['a']=actual;self.assertEqual(evaluate(p,r)['decision'],expected)
        p['rules'][0]['conditions'][0]['op']='lte'
        r['subject']['a']=1;self.assertEqual(evaluate(p,r)['decision'],'allow')

    def test_all_conditions_roles_actions_and_default_deny(self):
        p=sample_policy();r=sample_requests()[1]
        self.assertEqual(evaluate(p,r)['decision'],'allow')
        for change in [{'roles':[]},{'action':'Read'},{'subject':{}}]:
            self.assertEqual(evaluate(p,{**r,**change})['decision'],'deny')
        self.assertEqual(evaluate({'name':'Empty','rules':[]},r)['reason'],'default-deny')

    def test_validation_rejects_ambiguous_values_and_bounds(self):
        for v in [True,float('nan'),float('inf'),10**1000,{},[]]:
            p=sample_policy();p['rules'][1]['conditions'][1]['value']=v
            with self.assertRaises(ValueError):validate_policy(p)
        for change in [{'roles':['*']},{'roles':['a','a']},{'roles':[{}]},{'subject':{'bad.key':1}},{'resource':{'a':[]}}]:
            with self.assertRaises(ValueError):validate_request({**sample_requests()[0],**change})
        p=sample_policy();p['rules'].append(p['rules'][0])
        with self.assertRaises(ValueError):validate_policy(p)
        with self.assertRaises(ValueError):validate_policy({'name':'x','rules':sample_policy()['rules']*20})

    def test_inputs_are_not_mutated_and_numeric_membership_is_strict(self):
        p=sample_policy();r=sample_requests()[1];before=copy.deepcopy((p,r));evaluate(p,r)
        self.assertEqual((p,r),before)
        p['rules'][1]['conditions']=[{'path':'subject.clearance','op':'in','value':[1,2]}]
        r['subject']['clearance']=True;self.assertEqual(evaluate(p,r)['decision'],'deny')

    def test_generated_requests_match_independent_boolean_oracle(self):
        p=sample_policy()
        for action,roles,clearance,classification,suspended in itertools.product(['read','write'],[[],['analyst'],['guest']],[None,1,2,4],['public','internal','secret'],[None,False,True]):
            subject={}
            if clearance is not None:subject['clearance']=clearance
            if suspended is not None:subject['suspended']=suspended
            request={'action':action,'roles':roles,'subject':subject,'resource':{'classification':classification}}
            allow=action=='read' and (classification=='public' or ('analyst' in roles and classification=='internal' and clearance is not None and clearance>=2))
            expected='allow' if allow and suspended is not True else 'deny'
            self.assertEqual(evaluate(p,request)['decision'],expected)


if __name__=='__main__':unittest.main()
