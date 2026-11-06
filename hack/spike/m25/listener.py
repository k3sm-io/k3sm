#!/usr/bin/env python3
"""A loopback listener that logs every request it receives as "HIT <method> <path>".

Usage: listener.py PORT

It is the target of the remote image_url probe: an engine that fetched the URL
would leave a HIT line. No HIT line is the evidence that nothing went out.
"""
import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("HIT", self.command, self.path, flush=True)
        self.send_response(404)
        self.end_headers()

    do_HEAD = do_POST = do_GET

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("LISTEN", sys.argv[1], flush=True)
    http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
