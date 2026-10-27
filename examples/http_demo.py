"""Run against a real local HTTP listener; demonstrate delivery/withholding."""
from dataclasses import replace
from threading import Thread
from http.client import HTTPConnection
import json
from alf_reference.gateway import RecommendationService,create_server

def send(addr):
    conn=HTTPConnection(*addr,timeout=3)
    try:
        body=json.dumps({'recipient':'reader-42','item':'civic-story-7'}).encode()
        conn.request('POST','/recommend',body,{'Content-Type':'application/json'})
        result=conn.getresponse()
        return result.status,json.loads(result.read())
    finally:
        conn.close()

if __name__=='__main__':
    service=RecommendationService()
    server=create_server(service)
    thread=Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        print('Scenario A: approved recommendation')
        print(send(server.server_address))
        print('\nScenario B: unauthorized ranker configuration')
        service.controller.hot_swap('ranker','unauthorized-ranker-v2')
        print(send(server.server_address))
        print('\nScenario C: output substituted between validation and sink')
        service.controller.hot_swap('ranker','rank-v1')
        service.before_release=lambda op:replace(op,output='ranked:substituted-civic-story')
        print(send(server.server_address))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
