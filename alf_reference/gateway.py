"""Real loopback HTTP delivery boundary, backed by the educational ALF sink.

Not a hardened production service. Trust boundaries and evidence acquisition are
simulated; production requires isolated observer, trusted keys and path coverage.
"""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import replace
import json
import threading
from typing import Callable
from .core import ActivationController, ApprovalRegistry, Validator, FinalitySink, Operation, Denied

class RecommendationService:
    def __init__(self):
        self.controller = ActivationController({'ranker':'rank-v1','features':'feat-v1'})
        self.registry = ApprovalRegistry({'ranker':'rank-v1','features':'feat-v1'})
        self.validator = Validator(self.controller, self.registry, b'LAB-receipt-key', b'LAB-enable-key')
        self.sink = FinalitySink(self.controller, self.registry, b'LAB-receipt-key', b'LAB-enable-key')
        self._counter = 0
        self._lock = threading.Lock()
        # This hook is deliberately NOT exposed over the HTTP interface.
        # It simulates a compromised/changed upstream stage between validation and delivery.
        self.before_release: Callable[[Operation], Operation] | None = None
    def process(self, recipient: str, item: str):
        if not isinstance(recipient,str) or not recipient or not isinstance(item,str) or not item:
            raise ValueError('recipient and item must be nonempty strings')
        with self._lock:
            self._counter += 1
            identifier = f'http-recommendation-{self._counter}'
            op = Operation(identifier, f'ranked:{item}', f'feed:{recipient}')
            receipt, enablement = self.validator.validate(op)
            actual = self.before_release(op) if self.before_release is not None else op
            # The byte-level response is formed from *actual*, and sink checks *actual*.
            result = self.sink.release(actual, receipt, enablement)
            return {'status':'delivered', 'operation_id':actual.operation_id,
                    'recipient':actual.destination, 'content':actual.output,
                    'evidence':'simulated', 'release':result}

def make_handler(service: RecommendationService):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def respond(self, status:int, payload:dict):
            body=json.dumps(payload,sort_keys=True).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if self.path=='/health':
                self.respond(200,{'service':'ALF reference gateway','mode':'laboratory-only'})
            else:
                self.respond(404,{'error':'not found'})
        def do_POST(self):
            if self.path not in ('/recommend','/direct'):
                return self.respond(404, {'error':'not found'})
            try:
                length=int(self.headers.get('Content-Length','-1'))
                if length<0 or length>16384:
                    return self.respond(413,{'error':'invalid request size'})
                data=json.loads(self.rfile.read(length))
                if not isinstance(data,dict):
                    raise ValueError('expected object')
                recipient=data.get('recipient')
                item=data.get('item')
                if not isinstance(recipient,str) or not recipient or not isinstance(item,str) or not item:
                    raise ValueError('recipient and item must be nonempty strings')
                if self.path=='/direct':
                    # illustrative separate publication class; this does NOT prove legal entitlement.
                    return self.respond(200,{'status':'direct-publication', 'recipient':recipient,'content':item})
                self.respond(200,service.process(recipient,item))
            except Denied as exc:
                self.respond(403,{'status':'WITHHELD','reason':str(exc)})
            except (ValueError,TypeError,UnicodeError,json.JSONDecodeError):
                self.respond(400,{'error':'invalid request'})
    return Handler

def create_server(service=None,host='127.0.0.1',port=0):
    service = service or RecommendationService()
    return ThreadingHTTPServer((host,port),make_handler(service))
