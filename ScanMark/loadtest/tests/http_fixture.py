"""Disposable loopback fixture; NOT ScanMark and NOT capacity evidence."""
from gevent import monkey
monkey.patch_all()
import json
import sqlite3
import sys
from urllib.parse import parse_qs
from gevent.pywsgi import WSGIServer

path, mode, port_file = sys.argv[1:]


def app(environ, start_response):
    path_info = environ['PATH_INFO']
    status, headers = '200 OK', [('Content-Type', 'text/html')]
    body = ''
    if path_info == '/login' and environ['REQUEST_METHOD'] == 'GET':
        body = '<input name="csrf_token" value="fixture">'
        if mode == 'redirect':
            status = '302 Found'
            headers += [('Location', 'http://127.0.0.1:1/never-contact-this')] 
    elif path_info == '/login':
        form = parse_qs(environ['wsgi.input'].read(int(environ['CONTENT_LENGTH'])).decode())
        email = form['email'][0]
        student = email.split('@')[0].removeprefix('st')
        if mode == 'partial-login' and student == '1':
            status = '403 Forbidden'
        else:
            status = '302 Found'
            headers += [('Location', '/scan_page'), ('Set-Cookie', f'student={student}; Path=/')]
    elif path_info == '/scan_page':
        student = environ.get('HTTP_COOKIE', '').removeprefix('student=')
        body = f'csrfToken: "fixture", userMarker: "{student}"'
    elif path_info == '/mark_attendance':
        data = json.loads(environ['wsgi.input'].read(int(environ['CONTENT_LENGTH'])))
        student = int(data['user_marker'])
        session = int(data['qr_data'].split('|')[0][1:])
        with sqlite3.connect(path) as conn:
            if not (mode == 'missing-write' and student == 1):
                conn.execute('INSERT INTO attendance VALUES (?,?)', (student, session))
            if mode == 'duplicate-write' and student == 1:
                conn.execute('INSERT INTO attendance VALUES (?,?)', (student, session))
        body = json.dumps({'outcome': 'success'})
        headers = [('Content-Type', 'application/json')]
    elif path_info.startswith('/api/session/'):
        body = 'invalid json' if mode == 'bad-projector' else '{"last_id": 0}'
    else:
        status = '404 Not Found'
    start_response(status, headers)
    return [body.encode()]


server = WSGIServer(('127.0.0.1', 0), app, log=None)
server.start()
with open(port_file, 'w') as handle:
    handle.write(str(server.server_port))
server.serve_forever()
