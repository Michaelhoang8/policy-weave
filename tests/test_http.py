import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from run import make_server
from policy import sample_policy,sample_requests


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.server=make_server(Path(self.temp.name)/'db.sqlite3')
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()

    def request(self,method,path,value=None,headers=None,raw=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        body=raw if raw is not None else json.dumps(value).encode() if value is not None else None
        hs={'Content-Type':'application/json',**(headers or {})}
        conn.request(method,path,body,hs);response=conn.getresponse();data=response.read();status=response.status;conn.close()
        return status,json.loads(data) if data and response.getheader('Content-Type','').startswith('application/json') else data

    def test_revision_decision_preview_and_comparison(self):
        status,state=self.request('GET','/api/state');self.assertEqual(status,200)
        self.assertEqual(state['head']['id'],1)
        p=sample_policy();p['rules'][1]['conditions'][1]['value']=3
        status,result=self.request('POST','/api/preview',{'policy':p,'request':sample_requests()[1]})
        self.assertEqual(status,200);self.assertEqual(result['decision'],'deny')
        self.assertEqual(self.request('GET','/api/state')[1]['total'],1)
        publication={'expected':1,'policy':p,'note':'Raise clearance'}
        self.assertEqual(self.request('POST','/api/revisions',publication)[0],201)
        self.assertEqual(self.request('POST','/api/revisions',publication)[0],409)
        self.assertEqual(self.request('POST','/api/decide',{'revision':1,'request':sample_requests()[1]})[1]['decision'],'allow')
        result=self.request('POST','/api/compare',{'before':1,'after':2,'requests':sample_requests()})[1]
        self.assertEqual(result['changed'],1)
        self.assertEqual(self.request('GET','/api/revisions/999')[0],404)

    def test_transport_validation_and_hidden_files(self):
        for path in ['/.git/config','/data/policies.sqlite3','/../store.py']:
            self.assertEqual(self.request('GET',path)[0],404)
        self.assertEqual(self.request('GET','/api/state',headers={'Host':'evil.invalid'})[0],400)
        self.assertEqual(self.request('POST','/api/preview',{},headers={'Origin':'https://evil.invalid'})[0],403)
        self.assertEqual(self.request('POST','/api/preview',{},headers={'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request('POST','/api/preview',raw=b'{"policy":{},"policy":{}}')[0],400)
        self.assertEqual(self.request('POST','/api/preview',raw=b'{"value":NaN}')[0],400)
        self.assertEqual(self.request('POST','/api/preview',raw=b'\xff')[0],400)
        self.assertEqual(self.request('POST','/api/preview',raw=b' '*250001)[0],413)
        self.assertEqual(self.request('HEAD','/api/state')[1],b'')
        self.assertEqual(self.request('DELETE','/api/state')[0],405)


if __name__=='__main__':unittest.main()
