"""Run Policy Weave's local policy laboratory and revision API."""
import argparse
import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from policy import evaluate, exact, sample_requests
from store import Store, Conflict, Missing, Integrity

ROOT = Path(__file__).resolve().parent
ASSETS = {'/': ('index.html','text/html'), '/app.js': ('app.js','text/javascript'), '/style.css': ('style.css','text/css')}


def object_pairs(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON field: {key}')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('JSON numbers must be finite.')


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, status, value, mime='application/json'):
        body = value if isinstance(value,bytes) else json.dumps(value,allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',mime+'; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def handle_request(self):
        try:
            hosts = self.headers.get_all('Host',[])
            if len(hosts) != 1 or not re.fullmatch(r'(localhost|127\.0\.0\.1)(:[0-9]{1,5})?',hosts[0],re.I):
                return self.reply(400,{'error':'Use a loopback Host header.'})
            path = urlsplit(self.path).path
            if self.command in ('GET','HEAD'):
                if path in ASSETS:
                    name,mime = ASSETS[path]
                    return self.reply(200,(ROOT/name).read_bytes(),mime)
                if path == '/api/state':
                    return self.reply(200,self.server.store.state())
                if path == '/api/examples':
                    return self.reply(200,{'requests':sample_requests()})
                match = re.fullmatch(r'/api/revisions/([1-9][0-9]{0,8})',path)
                if match:
                    return self.reply(200,self.server.store.get(int(match[1])))
                return self.reply(404,{'error':'Not found.'})
            if self.command != 'POST':
                return self.reply(405,{'error':'Method not supported.'})
            origin = self.headers.get_all('Origin',[])
            allowed = (f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}')
            if len(origin)>1 or (origin and origin[0] not in allowed):
                return self.reply(403,{'error':'Cross-origin requests are rejected.'})
            lengths = self.headers.get_all('Content-Length',[])
            if self.headers.get('Transfer-Encoding') or len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=250000:
                return self.reply(413,{'error':'Provide a JSON body of at most 250 KB.'})
            if self.headers.get('Content-Type','').split(';')[0].strip() != 'application/json':
                return self.reply(415,{'error':'Use application/json.'})
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError('Incomplete request body.')
            value = json.loads(raw.decode('utf-8'),object_pairs_hook=object_pairs,parse_constant=reject_constant)
            if path == '/api/revisions':
                return self.reply(201,self.server.store.publish(value))
            if path == '/api/decide':
                return self.reply(200,self.server.store.decide(value))
            if path == '/api/compare':
                return self.reply(200,self.server.store.compare(value))
            if path == '/api/preview':
                exact(value,['policy','request'],'Preview')
                return self.reply(200,{'draft':True,**evaluate(value['policy'],value['request'])})
            return self.reply(404,{'error':'Not found.'})
        except Missing as error:
            self.reply(404,{'error':str(error)})
        except Conflict as error:
            self.reply(409,{'error':str(error)})
        except Integrity as error:
            self.reply(500,{'error':str(error)})
        except (ValueError,UnicodeDecodeError,RecursionError) as error:
            self.reply(400,{'error':str(error)})
        except (sqlite3.OperationalError,TimeoutError):
            self.reply(503,{'error':'Local service temporarily unavailable. Retry shortly.'})

    do_GET=handle_request
    do_HEAD=handle_request
    do_POST=handle_request
    do_PUT=handle_request
    do_DELETE=handle_request


def make_server(path,port=0):
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.store=Store(path)
    return server


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--db',default=str(ROOT/'data/policies.sqlite3'))
    args=parser.parse_args()
    server=make_server(args.db,args.port)
    print(f'Policy Weave: http://127.0.0.1:{server.server_port}',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=='__main__':
    main()
