import tempfile
import unittest
from pathlib import Path
from starlette.testclient import TestClient
from app import create_app


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app(self.temp.name)
        self.client=TestClient(self.app)

    def tearDown(self):
        self.client.close();self.temp.cleanup()

    def run_data(self,text='{"a": 1}',fmt='json',**kwargs):
        response=self.client.post('/api/analyze',json={'text':text,'format':fmt,**kwargs})
        self.assertEqual(response.status_code,201,response.text)
        return response.json()

    def test_health_and_static(self):
        self.assertEqual(self.client.get('/api/health').json()['status'],'ok')
        self.assertIn('CBOR Workbench',self.client.get('/').text)
        self.assertEqual(self.client.get('/static/app.js').status_code,200)
        self.assertIn("frame-ancestors 'none'",self.client.get('/').headers['content-security-policy'])

    def test_history_saved_repeatedly_and_persistent(self):
        a,b=self.run_data(),self.run_data()
        self.assertNotEqual(a['id'],b['id'])
        other=TestClient(create_app(self.temp.name))
        self.assertEqual(len(other.get('/api/history').json()),2)
        self.assertEqual(other.get('/api/history/'+a['id']).json()['hex'],a['hex'])
        other.close()

    def test_failed_scan_is_saved(self):
        a=self.run_data('ffff','hex')
        self.assertIsNone(a['result']['best'])
        self.assertEqual(len(self.client.get('/api/history').json()),1)

    def test_rename_pin_delete(self):
        a=self.run_data()
        url='/api/history/'+a['id']
        result=self.client.patch(url,json={'title':'名前','pinned':True}).json()
        self.assertEqual(result['title'],'名前')
        self.assertEqual(self.client.get('/api/history').json()[0]['pinned'],1)
        self.assertEqual(self.client.delete(url).status_code,204)
        self.assertEqual(self.client.get(url).status_code,404)

    def test_candidate_selection_persists(self):
        a=self.run_data('01ff820203','hex')
        self.assertEqual(a['result']['selected']['offset'],2)
        url='/api/history/'+a['id']
        r=self.client.post(url+'/candidate',json={'offset':0})
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.client.get(url).json()['result']['selected']['offset'],0)
        self.assertEqual(self.client.get('/api/history').json()[0]['offset'],0)
        self.assertEqual(self.client.post(url+'/candidate',json={'offset':99}).status_code,400)

    def test_exports_and_node_payload(self):
        a=self.run_data('a16162420102','hex')
        url='/api/history/'+a['id']
        r=self.client.get(url+'/export?format=cbor')
        self.assertEqual(r.content,bytes.fromhex(a['hex']))
        self.assertIn('attachment',r.headers['content-disposition'])
        self.assertEqual(self.client.get(url+'/node?offset=3').json()['payload'],'0102')
        self.assertEqual(self.client.get(url+'/export?format=json').json()['id'],a['id'])

    def test_compare_semantic_paths_ignore_map_order(self):
        a=self.run_data('{"a":1,"b":2}')
        b=self.run_data('{"b":3,"a":1,"c":4}')
        r=self.client.post('/api/compare',json={'left':a['id'],'right':b['id']}).json()
        self.assertEqual(r['counts']['changed'],2) # map pair count and b value
        self.assertEqual(r['counts']['added'],2)   # c key/value
        self.assertEqual(r['counts']['removed'],0)

    def test_encoding_only_difference(self):
        a=self.run_data('01','hex',mode='exact')
        b=self.run_data('1801','hex',mode='exact')
        r=self.client.post('/api/compare',json={'left':a['id'],'right':b['id']}).json()
        self.assertEqual(r['counts']['changed'],0)
        self.assertEqual(r['counts']['encoding'],1)

    def test_cross_origin_denied_same_origin_allowed(self):
        for method,path in [('POST','/api/analyze'),('PATCH','/api/history/no'),('DELETE','/api/history/no')]:
            r=self.client.request(method,path,json={},headers={'Origin':'https://outside.invalid'})
            self.assertEqual(r.status_code,403)
        r=self.client.post('/api/analyze',json={'text':'00','format':'hex'},headers={'Origin':'http://testserver'})
        self.assertEqual(r.status_code,201)

    def test_bad_requests(self):
        for value in [[],None,{'text':'xyz'},{'text':'00','offset':-1},{'text':'00','mode':'bad'},{'text':'00','sequence':'false'},{'text':'00','mode':'exact','offset':2}]:
            r=self.client.post('/api/analyze',json=value)
            self.assertEqual(r.status_code,400,r.text)
        self.assertEqual(len(self.client.get('/api/history').json()),0)
        self.assertEqual(self.client.post('/api/compare',json={}).status_code,400)


if __name__=='__main__':unittest.main()
