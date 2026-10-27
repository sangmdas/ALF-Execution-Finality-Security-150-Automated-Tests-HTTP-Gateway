"""12 integration tests using an actual localhost TCP listener and HTTP client."""
from dataclasses import replace
from http.client import HTTPConnection
from threading import Thread
import json
import pytest
from alf_reference.gateway import RecommendationService,create_server

@pytest.fixture
def http_lab():
    service=RecommendationService()
    server=create_server(service)
    t=Thread(target=server.serve_forever,daemon=True)
    t.start()
    yield service,server.server_address
    server.shutdown()
    server.server_close()
    t.join(timeout=2)

def query(address,path='/recommend',body=None,method='POST'):
    c=HTTPConnection(*address,timeout=5)
    try:
        data=json.dumps(body if body is not None else {'recipient':'user-7','item':'story-a'}) if method=='POST' else None
        c.request(method,path,body=data,headers={'Content-Type':'application/json'} if data else {})
        response=c.getresponse()
        status=response.status
        payload=json.loads(response.read())
        return status,payload
    finally:
        c.close()

def test_http_01_authorized_recommendation_delivered(http_lab):
    _,address=http_lab
    status,data=query(address)
    assert status==200 and data['status']=='delivered'
    assert data['content']=='ranked:story-a'

def test_http_02_changed_model_withheld(http_lab):
    service,address=http_lab
    service.controller.hot_swap('ranker','rank-v2')
    status,data=query(address)
    assert status==403 and data['status']=='WITHHELD'

def test_http_03_changed_features_withheld(http_lab):
    service,address=http_lab
    service.controller.hot_swap('features','feat-v2')
    status,data=query(address)
    assert status==403 and data['status']=='WITHHELD'

def test_http_04_same_config_new_generation_withheld(http_lab):
    service,address=http_lab
    service.before_release=lambda op:(service.controller.hot_swap('ranker','rank-v1') or op)
    status,data=query(address)
    assert status==403 and 'generation mismatch' in data['reason']

def test_http_05_output_mutation_before_wire_withheld(http_lab):
    service,address=http_lab
    service.before_release=lambda op:replace(op,output='ranked:unapproved-story')
    status,data=query(address)
    assert status==403 and 'actual operation' in data['reason']
    assert 'unapproved-story' not in json.dumps(data)

def test_http_06_destination_swap_withheld(http_lab):
    service,address=http_lab
    service.before_release=lambda op:replace(op,destination='feed:other-user')
    status,data=query(address)
    assert status==403 and data['status']=='WITHHELD'

def test_http_07_revoked_policy_withheld(http_lab):
    service,address=http_lab
    service.registry.revoke()
    status,data=query(address)
    assert status==403 and data['status']=='WITHHELD'

def test_http_08_same_config_hot_swap_prevalidation_withheld(http_lab):
    service,address=http_lab
    service.controller.hot_swap('ranker','rank-v1')
    service.before_release=lambda op:(service.controller.hot_swap('ranker','rank-v1') or op)
    status,data=query(address)
    assert status==403 and data['status']=='WITHHELD'

def test_http_09_organic_direct_publication_separate(http_lab):
    service,address=http_lab
    service.registry.revoke()
    status,data=query(address,'/direct')
    assert status==200 and data['status']=='direct-publication'

def test_http_10_bad_input_rejected(http_lab):
    _,address=http_lab
    status,data=query(address,body={'recipient':'','item':'story-a'})
    assert status==400 and 'error' in data

def test_http_11_unknown_endpoint_does_not_deliver(http_lab):
    _,address=http_lab
    status,data=query(address,'/unprotected-path')
    assert status==404 and 'content' not in data

def test_http_12_health_endpoint_is_not_delivery(http_lab):
    _,address=http_lab
    status,data=query(address,'/health',method='GET')
    assert status==200 and data['mode']=='laboratory-only'
    assert 'content' not in data
