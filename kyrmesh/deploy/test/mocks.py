#!/usr/bin/env python3
"""Stand-ins for the services a GCE boot of the Kyrmesh VM talks to, for a disposable test VM.

HTTPS on 127.0.0.1:8443 answers as api.cloudflare.com, secretmanager.googleapis.com and
github.com (one certificate from the test CA covers the three names); HTTP on 127.0.0.1:8080
answers as the GCE metadata server. nftables sends those names' addresses here, so the scripts
under test run unchanged. DNS-01 TXT records go to pebble-challtestsrv, the resolver Pebble and
the server's propagation check both ask. Every call is appended to calls.log; no secret is logged.
"""

import base64
import json
import os
import ssl
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STATE = sys.argv[1]  # directory with config.json, the release files and calls.log
CONF = json.load(open(os.path.join(STATE, "config.json")))
LOCK = threading.Lock()  # guards RECORDS and NEXT
LOG_LOCK = threading.Lock()  # separate: log() runs inside LOCK sections, and threading.Lock is not reentrant
# The zone outlives the VM, as Cloudflare's does: records are kept on disk so the reboot phase
# finds the A record the first boot created.
ZONE_FILE = os.path.join(STATE, "zone.json")
_saved = json.load(open(ZONE_FILE)) if os.path.exists(ZONE_FILE) else {"records": {}, "next": 1}
RECORDS = _saved["records"]  # id -> record
NEXT = [_saved["next"]]


def save_zone():
    # Called under LOCK; write then rename so a crash never leaves half a file.
    tmp = ZONE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"records": RECORDS, "next": NEXT[0]}, f)
    os.replace(tmp, ZONE_FILE)


def log(line):
    with LOG_LOCK, open(os.path.join(STATE, "calls.log"), "a") as f:
        f.write(line + "\n")


def challtestsrv(path, body):
    req = urllib.request.Request("http://127.0.0.1:8055" + path, data=json.dumps(body).encode(), method="POST")
    urllib.request.urlopen(req, timeout=5).read()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, obj, raw=None):
        data = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream" if raw is not None else "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def handle_any(self, method):
        host = (self.headers.get("Host") or "").split(":")[0]
        url = urlparse(self.path)
        log(f"{host} {method} {url.path}")
        if host == "metadata.google.internal":
            return self.metadata(url)
        if host == "secretmanager.googleapis.com":
            return self.secret(url)
        if host == "github.com":
            return self.release(url)
        if host == "api.cloudflare.com":
            return self.cloudflare(method, url)
        self.reply(404, {"error": "unknown host " + host})

    def metadata(self, url):
        if self.headers.get("Metadata-Flavor") != "Google":
            return self.reply(403, {"error": "missing Metadata-Flavor"})
        prefix = "/computeMetadata/v1/instance/"
        path = url.path[len(prefix):] if url.path.startswith(prefix) else ""
        if path == "service-accounts/default/token":
            return self.reply(200, {"access_token": CONF["gce_token"], "expires_in": 3600, "token_type": "Bearer"})
        if path == "network-interfaces/0/access-configs/0/external-ip":
            return self.reply(200, None, CONF["external_ip"].encode())
        if path.startswith("attributes/"):
            key = path[len("attributes/"):]
            attrs = json.load(open(os.path.join(STATE, "attributes.json")))
            if key in attrs:
                return self.reply(200, None, attrs[key].encode())
        self.reply(404, {"error": "no such metadata " + path})

    def secret(self, url):
        if self.headers.get("Authorization") != "Bearer " + CONF["gce_token"]:
            return self.reply(401, {"error": "bad gce token"})
        if url.path != f"/v1/{CONF['secret']}/versions/latest:access":
            return self.reply(404, {"error": "no such secret"})
        data = base64.b64encode(CONF["cloudflare_token"].encode()).decode()
        self.reply(200, {"name": CONF["secret"] + "/versions/1", "payload": {"data": data}})

    def release(self, url):
        name = url.path.rsplit("/", 1)[-1]
        path = os.path.join(STATE, "release", name)
        if not url.path.startswith(f"/Kembec/kyrmesh/releases/download/{CONF['version']}/") or not os.path.isfile(path):
            return self.reply(404, {"error": "no such release asset"})
        self.reply(200, None, open(path, "rb").read())

    def cloudflare(self, method, url):
        if self.headers.get("Authorization") != "Bearer " + CONF["cloudflare_token"]:
            return self.reply(403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]})
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        parts = url.path.removeprefix("/client/v4/").split("/")
        ok = lambda result: self.reply(200, {"success": True, "errors": [], "result": result})
        if parts == ["zones"]:
            return ok([{"id": "zone1", "name": CONF["zone"]}] if q.get("name") == CONF["zone"] else [])
        if parts[:3] != ["zones", "zone1", "dns_records"]:
            return self.reply(404, {"success": False, "errors": [{"code": 7003, "message": "no route"}]})
        with LOCK:
            if method == "GET":
                return ok([r for r in RECORDS.values()
                           if r["type"] == q.get("type", r["type"]) and r["name"] == q.get("name", r["name"])])
            if method == "POST":
                rec = dict(self.body(), id=f"rec{NEXT[0]}")
                NEXT[0] += 1
            elif method == "PUT":
                rec = dict(self.body(), id=parts[3])
            elif method == "DELETE":
                rec = RECORDS.pop(parts[3], None)
            if method != "DELETE":
                RECORDS[rec["id"]] = rec
            save_zone()
        if method == "DELETE":
            # Outside LOCK: a DELETE that logged or called challtestsrv while holding it hung every
            # other request for 30 s (the core's cleanup hit its deadline, KEM-462).
            if rec is None:
                return self.reply(404, {"success": False, "errors": [{"code": 81044, "message": "record not found"}]})
            if rec["type"] == "TXT":
                challtestsrv("/clear-txt", {"host": rec["name"] + "."})
            log(f"  delete {rec['type']} {rec['name']}")
            return ok({"id": rec["id"]})
        log(f"  {method.lower()} {rec['type']} {rec['name']} {rec['content'] if rec['type'] == 'A' else '<challenge>'}")
        if rec["type"] == "TXT":
            challtestsrv("/set-txt", {"host": rec["name"] + ".", "value": rec["content"]})
        ok(rec)

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")


def serve(port, tls):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(STATE, "tls.crt"), os.path.join(STATE, "tls.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve, args=(8080, False), daemon=True).start()
    serve(8443, True)
