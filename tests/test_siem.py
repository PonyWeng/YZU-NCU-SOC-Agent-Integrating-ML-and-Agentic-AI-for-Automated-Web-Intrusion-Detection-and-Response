"""Offline integration tests. No network, model calls, or production data writes."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from siem import store
from siem.collector import normalize,collect_once,import_legacy
from siem.parsers import parse
from siem.geo import enrich


def sample(event_id='e1', ip='192.0.2.1', code=1):
    stamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
    return normalize({'id':event_id,'attack_prediction':code,'return_code':200,
        'log_record':f'{ip} - - [{stamp}] "GET /search?q=test HTTP/1.1" 200 42 "-" "test"'})


class SIEMTests(unittest.TestCase):
    def test_documentation_ip_gets_stable_external_demo_location(self):
        location=enrich('198.51.100.121')
        self.assertEqual(location['status'],'demo')
        self.assertNotEqual(location['country_code'],'LAN')
        self.assertIsInstance(location['latitude'],float)

    def test_modsecurity_rule_family_selects_primary_attack_class(self):
        base={'transaction':{'time':'15/Sep/2026:12:00:00 +0000','remote_address':'192.0.2.1'},
              'request':{'request_line':'GET /search?q=test HTTP/1.1'},'response':{'status':200}}
        xss={**base,'audit_data':{'messages':[{'details':{'ruleId':'941100','tags':['attack-xss']},'message':'XSS Attack Detected'}]}}
        traversal={**base,'audit_data':{'messages':[{'details':{'ruleId':'930100','tags':['attack-lfi']},'message':'Path Traversal Attack'}]}}
        self.assertEqual(parse(json.dumps(xss),'modsecurity_json')['attack'],2)
        self.assertEqual(parse(json.dumps(traversal),'modsecurity_json')['attack'],3)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'SIEM_DB_PATH':str(self.root/'test.sqlite3')})
        self.env.start()
        store.init_db()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_import_is_idempotent_and_does_not_alert(self):
        path=self.root/'legacy.json'
        path.write_text(json.dumps([{'id':'old','attack_prediction':1,'return_code':200,'log_record':sample()['raw']}]),encoding='utf-8')
        self.assertEqual(import_legacy(path),1)
        self.assertEqual(import_legacy(path),0)
        with store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM incidents').fetchone()[0],0)

    def test_modsecurity_json_is_normalized(self):
        raw=json.dumps({'transaction':{'time':'10/Sep/2026:01:02:03.123456 +0000','remote_address':'172.19.0.1',
            'remote_port':54321,'local_address':'172.20.0.2','local_port':8080},
            'request':{'request_line':'GET /search?q=%27+or+1%3D1 HTTP/1.1',
                       'headers':{'User-Agent':'scanner','X-Real-IP':'203.0.113.9'}},
            'response':{'status':200,'headers':{'Content-Length':'42'}},
            'audit_data':{'messages':['Warning. detected SQLi [id "942100"] [msg "SQL Injection Attack Detected"] [tag "attack-sqli"]']}})
        row=parse(raw,'modsecurity_json','Apache WAF','127.0.0.1',80)
        self.assertEqual(row['src_ip'],'203.0.113.9')
        self.assertEqual(row['attack'],1)
        self.assertIn('942100',row['description'])

    def test_modsecurity_transaction_without_rule_match_is_skipped(self):
        from siem.collector import Classifier
        raw=json.dumps({'transaction':{'time':'10/Sep/2026:01:02:03 +0000','remote_address':'172.19.0.1'},
            'request':{'request_line':'GET /demo-error HTTP/1.1','headers':{'X-Real-IP':'198.51.100.8'}},
            'response':{'status':500},'audit_data':{'messages':[]}})
        classifier=Classifier.__new__(Classifier)
        self.assertIsNone(classifier.event(raw,'waf-no-match','modsecurity_json','demo','127.0.0.1',8081))

    def test_rule_groups_by_source_and_cooldown(self):
        with store.connection() as db:
            db.execute('UPDATE rules SET enabled=1,threshold=2 WHERE id=1')
        with patch('config.LINE_USER_IDS',['recipient']):
            store.insert_events([sample('1','192.0.2.1'),sample('2','192.0.2.2')],evaluate=True)
            store.insert_events([sample('3','192.0.2.1'),sample('4','192.0.2.1')],evaluate=True)
            store.insert_events([sample('3','192.0.2.1')],evaluate=True)
        with store.connection() as db:
            rows=db.execute('SELECT * FROM incidents').fetchall()
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['src_ip'],'192.0.2.1')
            self.assertEqual(rows[0]['count'],3)
            self.assertEqual(db.execute('SELECT count(*) FROM notifications').fetchone()[0],1)
        self.assertEqual(store.overview(0)['counts']['total'],4)

    def test_old_event_does_not_trigger_rule(self):
        with store.connection() as db:
            db.execute('UPDATE rules SET enabled=1,threshold=1')
        row=sample();row['timestamp']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat(timespec='seconds')
        store.insert_events([row],evaluate=True)
        with store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM incidents').fetchone()[0],0)

    def test_behavior_rule_alerts_without_attack_payload(self):
        rows=[sample(f'normal-{i}',ip='198.51.100.8',code=0) for i in range(50)]
        for row in rows:
            row['service_name']='flask-target'
        with patch('config.LINE_USER_IDS',[]):
            store.insert_events(rows,evaluate=True)
        with store.connection() as db:
            incident=db.execute("SELECT * FROM incidents WHERE rule_name LIKE '短時間大量連線%'").fetchone()
            self.assertIsNotNone(incident)
            self.assertEqual(incident['severity'],'high')
            self.assertEqual(incident['count'],50)

    def test_ml_high_risk_alert_bundles_during_cooldown(self):
        rows=[sample(f'sqli-{i}',ip='198.51.100.9',code=1) for i in range(4)]
        with patch('config.LINE_USER_IDS',['recipient']):
            store.insert_events(rows,evaluate=True)
        with store.connection() as db:
            incident=db.execute('SELECT * FROM incidents WHERE rule_id=1').fetchone()
            self.assertEqual(incident['rule_name'],'SQL injection attempt（1 分鐘 1 次）')
            self.assertEqual(incident['count'],4)
            self.assertEqual(db.execute('SELECT count(*) FROM notifications').fetchone()[0],1)

    def test_literal_search_pagination_and_filters(self):
        rows=[sample(str(i),code=i%4) for i in range(8)]
        rows[0]['url']='/100%_test'
        store.insert_events(rows)
        self.assertEqual(store.list_events(hours=0,q='%_')['total'],1)
        self.assertEqual(store.list_events(hours=0,attack=1)['total'],2)
        self.assertEqual(len(store.list_events(hours=0,page=2,page_size=3)['items']),3)

    def test_ai_context_is_grounded_and_suggests_current_risk(self):
        from siem.security_context import snapshot, suggestions, followup_suggestions
        store.insert_events([sample('context-1',ip='198.51.100.20',code=1)])
        with store.connection() as db:
            db.execute('''INSERT INTO incidents(rule_id,rule_name,src_ip,attack,severity,count,
                created_at,first_seen,last_seen,status,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (1,'Critical demo','198.51.100.20',1,'critical',1,store.now(),store.now(),store.now(),'new','["context-1"]'))
        data=snapshot(1,refresh=True)
        self.assertEqual(data['counts']['attack_traffic'],1)
        self.assertEqual(data['open_by_severity']['critical'],1)
        result=suggestions(1)
        self.assertEqual(len(result['items']),3)
        self.assertIn('Critical',result['items'][0]['question'])
        self.assertTrue(result['snapshot']['context_version'])
        followups=followup_suggestions('這次 SQL injection 是怎麼發生的？','來源是 198.51.100.20',1)
        self.assertTrue(followups['focus_detected'])
        self.assertTrue(any('如何防禦' in item['question'] for item in followups['items']))
        self.assertTrue(any('198.51.100.20' in item['question'] for item in followups['items']))
        later=followup_suggestions('繼續分析 SQL injection','',1,[
            {'role':'user','content':'SQL injection 是什麼？'},
            {'role':'assistant','content':'這是一種注入攻擊。'},
            {'role':'user','content':'如何防禦 SQL injection？'}])
        self.assertEqual(later['investigation_turn'],2)
        self.assertTrue(any('影響' in item['title'] or '比較' in item['title'] for item in later['items']))
        from ai_gateway import _question_context, _prompt
        entity=_question_context('調查 198.51.100.20 的活動')
        self.assertEqual(entity['queried_ip'],'198.51.100.20')
        self.assertIn('Apache Web Server',entity['events'][0]['service_name'])
        self.assertIn('不要問候',_prompt('目前狀況？',[]))

    def test_collector_retry_partial_line_and_rotation(self):
        path=self.root/'access.log'
        path.write_bytes((sample()['raw']+'\n').encode())
        class Fake:
            def event(self,raw,event_id,*service_metadata):
                row=sample(event_id);row['raw']=raw;return row
        with patch('siem.store.insert_events',side_effect=RuntimeError('db unavailable')):
            with self.assertRaises(RuntimeError):
                collect_once(path,Fake())
        self.assertIsNone(store.get_state('cursor:'+str(path.resolve())))
        self.assertEqual(collect_once(path,Fake()),1)
        self.assertEqual(collect_once(path,Fake()),0)
        with path.open('ab') as f:
            f.write(b'partial')
        self.assertEqual(collect_once(path,Fake()),0)
        with path.open('ab') as f:
            f.write(b' line\n')
        self.assertEqual(collect_once(path,Fake()),1)
        path.write_bytes(b'rotated\n')
        self.assertEqual(collect_once(path,Fake()),1)

    def test_api_auth_validation_export_and_incident_state(self):
        from fastapi.testclient import TestClient
        from api import app,webhook_app
        row=sample();row['url']='=HYPERLINK("malicious")'
        store.insert_events([row])
        with TestClient(app) as client:
            self.assertEqual(client.get('/').status_code,200)
            self.assertEqual(client.get('/api/events?hours=1').status_code,401)
            login=client.post('/api/auth/login',json={'username':'admin','password':'Admin@12345'},headers={'X-SIEM-Request':'dashboard'})
            self.assertEqual(login.status_code,200)
            self.assertEqual(login.json()['role'],'admin')
            self.assertEqual(client.get('/api/events?hours=1').json()['total'],1)
            context=client.get('/api/ai/context?hours=1').json()
            self.assertEqual(len(context['items']),3)
            self.assertIn('context_version',context['snapshot'])
            followups=client.post('/api/ai/suggestions',json={'message':'SQL injection 如何處理？','answer':'','hours':1},headers={'X-SIEM-Request':'dashboard'}).json()
            self.assertTrue(followups['focus_detected'])
            session=client.post('/api/chat/sessions',headers={'X-SIEM-Request':'dashboard'}).json()['id']
            self.assertEqual(client.delete('/api/chat/sessions/'+session,headers={'X-SIEM-Request':'dashboard'}).status_code,200)
            self.assertEqual(client.get('/api/chat/sessions/'+session).status_code,404)
            self.assertEqual(client.get('/api/events?page=0').status_code,422)
            self.assertEqual(client.get('/api/events?since=2026-01-01').status_code,422)
            self.assertEqual(client.get('/api/events/missing').status_code,404)
            self.assertEqual(client.post('/api/blacklist',json={'ip':'192.0.2.1'}).status_code,403)
            self.assertEqual(client.get('/api/events',headers={'X-Forwarded-For':'192.0.2.1'}).status_code,403)
            self.assertEqual(client.get('/api/events',headers={'Host':'evil.example'}).status_code,400)
            self.assertEqual(client.put('/api/rules/1',json={},headers={'X-SIEM-Request':'dashboard','Origin':'https://evil.example'}).status_code,403)
            self.assertIn("'=HYPERLINK",client.get('/api/events/export?hours=1').text)
            rule={'enabled':True,'threshold':1,'window_sec':120,'cooldown_sec':300,'severity':'high'}
            headers={'X-SIEM-Request':'dashboard'}
            self.assertEqual(client.put('/api/rules/1',json=rule,headers=headers).status_code,200)
            store.insert_events([sample('e2')],evaluate=True)
            self.assertEqual(client.patch('/api/incidents/1',json={'status':'resolved','note':'Reviewed'},headers=headers).status_code,200)
            self.assertEqual(client.get('/api/incidents/1').json()['status'],'resolved')
            self.assertTrue(client.get('/api/audit').json())
            created=client.post('/api/users',json={'username':'analyst1','display_name':'Analyst One','password':'Analyst@123','role':'analyst'},headers=headers)
            self.assertEqual(created.status_code,200)
            self.assertEqual(client.post('/api/auth/logout',headers=headers).status_code,200)
            self.assertEqual(client.post('/api/auth/login',json={'username':'analyst1','password':'Analyst@123'},headers=headers).status_code,200)
            self.assertEqual(client.get('/api/events').status_code,200)
            self.assertEqual(client.get('/api/audit').status_code,403)
            self.assertEqual(client.put('/api/rules/1',json=rule,headers=headers).status_code,403)
            self.assertEqual(client.patch('/api/incidents/1',json={'status':'investigating','note':'Analyst review'},headers=headers).status_code,200)
            profile=client.put('/api/auth/account',json={'display_name':'Pony Analyst','current_password':'','new_password':''},headers=headers)
            self.assertEqual(profile.status_code,200)
            self.assertEqual(client.get('/api/auth/me').json()['display_name'],'Pony Analyst')
        with TestClient(webhook_app) as client:
            self.assertEqual(client.get('/api/events').status_code,404)
            self.assertEqual(client.post('/webhook',json={'events':[]}).status_code,400)

    def test_enforcement_validation_and_rollback(self):
        from assistant import enforcer
        blacklist=self.root/'blacklist.json'; htaccess=self.root/'.htaccess'
        htaccess.write_text('original',encoding='utf-8')
        with patch.object(enforcer,'BLACKLIST_FILE',blacklist),patch.object(enforcer,'HTACCESS_PATH',htaccess):
            with self.assertRaises(ValueError):
                enforcer.change_ban('999.1.1.1',True,'test')
            with self.assertRaises(ValueError):
                enforcer.change_ban('127.0.0.1',True,'test')
            enforcer.change_ban('192.0.2.1',True,'test')
            self.assertIn('Require not ip 192.0.2.1',htaccess.read_text())
            enforcer.change_ban('192.0.2.1',False,'test')
            self.assertNotIn('Require not ip',htaccess.read_text())
            original=htaccess.read_text()
            atomic=enforcer._atomic
            def broken(path,text):
                if path==blacklist:
                    raise OSError('disk error')
                atomic(path,text)
            with patch.object(enforcer,'_atomic',side_effect=broken):
                with self.assertRaises(OSError):
                    enforcer.change_ban('192.0.2.2',True,'test')
            self.assertEqual(htaccess.read_text(),original)


if __name__=='__main__':
    unittest.main()
