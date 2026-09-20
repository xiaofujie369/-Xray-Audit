"""Loopback-only HTTPS reverse proxy using an explicit disposable test certificate."""

import argparse
import http.client
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def proxy(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 1048576:
            self.send_error(413)
            return
        upstream = http.client.HTTPConnection("127.0.0.1", 18080, timeout=35)
        try:
            upstream.request(
                self.command,
                self.path,
                self.rfile.read(length),
                {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")},
            )
            response = upstream.getresponse()
            data = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            upstream.close()

    do_GET = do_POST = do_PATCH = do_DELETE = proxy


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 18443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
