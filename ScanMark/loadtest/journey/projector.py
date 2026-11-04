"""
The lecturer's screen, for a harness: the current QR token as a PNG.

    python projector.py --listen 127.0.0.1:8300 --secret "$SECRET_KEY"
    GET /frame?session=12  ->  {"token": "S12|...|...", "png": "data:image/png;base64,..."}

Tokens are minted with the server's own algorithm (``S<id>|<unix>|<hmac16>``)
and rotate every ``--rotate`` seconds, exactly like the projector page, so a
scan that is slow to reach the server meets a real expiry window rather than a
code that never ages.
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import qrcode


def token_for(secret, session_id, timestamp):
    message = f'S{session_id}|{timestamp}'
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()[:16]
    return f'{message}|{signature}'


def png_for(text):
    image = qrcode.make(text, box_size=8, border=4)
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buffer.getvalue()).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default='127.0.0.1:8300')
    parser.add_argument('--secret', required=True)
    parser.add_argument('--rotate', type=int, default=12)
    args = parser.parse_args()
    cache = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            parts = urlsplit(self.path)
            session_id = int(parse_qs(parts.query).get('session', ['0'])[0])
            slot = int(time.time()) // args.rotate * args.rotate
            key = (session_id, slot)
            if key not in cache:
                cache.clear()
                token = token_for(args.secret, session_id, slot)
                cache[key] = {'token': token, 'png': png_for(token), 'issued': slot}
            body = json.dumps(cache[key]).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    host, _, port = args.listen.rpartition(':')
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == '__main__':
    main()
