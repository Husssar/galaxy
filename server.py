#!/usr/bin/env python3
"""
leakscope - en lokal server som visar allt du lamnar ifran dig vid en HTTP(S)-anslutning.

Allt stannar pa den har maskinen. Inga externa anrop.

Varje anslutning sparas automatiskt som en JSON-fil i mappen visits/, sa att
du kan jamfora webblasare mot varandra - t.ex. Firefox mot Firefox i privat
lage. Omladdningar i samma webblasare uppdaterar sin rad i stallet for att
lagga till nya. --no-store stanger av all skrivning till disk.

    python3 server.py                 # http://127.0.0.1:8088
    python3 server.py --tls           # https, visar aven TLS/JA3-fingeravtryck
    python3 server.py --host 0.0.0.0  # tillganglig fran andra enheter i LAN
    python3 server.py --no-store      # spara inget till disk
    python3 server.py --store /sokvag # annan mapp for sparade besok
"""

import argparse
import hashlib
import html
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

# ---------------------------------------------------------------- state ----
# Allt i minnet, utom sparade besok (se STORE) som overlever omstart
# sa att du kan jamfora webblasare mot varandra.
LOCK = threading.Lock()
CONNECTIONS = []          # raa requestlogg, det servern passivt ser
FINGERPRINTS = {}         # klient-fingeravtryck -> {count, first, last, ips}
ETAG_IDENTITIES = {}      # etag -> {issued, hits}
TLS_INFO = {}             # (ip, port) -> parsed ClientHello
VISITS = []               # sparade besok att jamfora
TRACKER_HITS = []         # tredjepartsdemon: vad sparare.local sett
BOARD = {}                # klassrumslage: fingeravtryck -> attributvarden
NOSCRIPT = {}             # css-sonden: sid -> vad stilmallen rojde
MAX_LOG = 300
MAX_VISITS = 100
MAX_HITS = 500
MAX_PROBES = 200
MAX_FINGERPRINTS = 2000
MAX_ETAGS = 2000
MAX_TLS = 500
MAX_BOARD = 1000
MAX_BODY = 1 << 20   # 1 MiB tak pa POST-kroppen

# Tredjepartsdemon. Tre skilda vardar pa loopback ger tre skilda origins,
# och darmed skilda cookie-burkar - precis som tre riktiga doman.
SITE_A = "127.0.0.1"
SITE_B = "127.0.0.2"
TRACKER = "127.0.0.3"
SITE_NAMES = {SITE_A: "Sajt A - nyhetssidan", SITE_B: "Sajt B - webbutiken",
              TRACKER: "Sparningsnatverket"}
DEMO = False
BOARD_ON = False

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def now():
    return time.time()


def esc(x):
    """HTML-escapar varde som interpoleras in i server-renderad HTML.
    Anvands pa ALL request-harledd data (User-Agent, Referer, url, sid,
    fingeravtryck, vardnamn) innan den nar sidan."""
    return html.escape("" if x is None else str(x), quote=True)


# Headrar som ar ofarliga att frysa ner i en sparad besokspost och som UI:t
# faktiskt visar. Allt annat - sarskilt Cookie och Authorization - sparas ALDRIG.
SAVED_HEADERS = ("User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
                 "DNT", "Sec-GPC", "Connection", "Sec-Fetch-Site",
                 "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Upgrade-Insecure-Requests")


def safe_headers(headers):
    return {k: v for k, v in headers.items() if k in SAVED_HEADERS}


# Tak for i-minnet-strukturer. Vid overflow slas det ENSKILT aldsta elementet
# ut (LRU), aldrig hela strukturen - annars kan en enda besokare som postar
# massor av skrapvarden nollstalla allas insamlade data (t.ex. klassrumstavlan).
# Anropas med LOCK haller. ts = faltet som anger alder; None = insattningsordning.
def cap_dict(d, cap, ts=None):
    while len(d) > cap:
        if ts is None:
            oldest = next(iter(d))                      # insattningsordning
        else:
            oldest = min(d, key=lambda k: d[k].get(ts, 0))
        del d[oldest]


# Gissade tidigare "css eller javascript", vilket serverade statiska
# html-filer som skript.
STATIC_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}


def static_type(name):
    return STATIC_TYPES.get(os.path.splitext(name)[1].lower(),
                            "application/octet-stream")


# ------------------------------------------------------- sparade besok ----
# --------------------------------------------------------- lagring ----
# Gransssnittet ar medvetet smalt - load_all / put / delete / clear - sa att
# JsonDirStore kan bytas mot en SQLite- eller Postgres-backad store utan att
# nagot annat i filen rors. En fil per besok i stallet for en stor visits.json
# betyder att en skrivning kostar lika mycket oavsett hur manga besok som
# finns, vilket spelar roll nu nar varje sidladdning sparas automatiskt.


class MemoryStore:
    """--no-store: allt lever och dor med processen."""

    persistent = False

    def load_all(self):
        return []

    def put(self, rec):
        pass

    def delete(self, rec_id):
        pass

    def clear(self):
        pass

    def describe(self):
        return "bara i minnet"


class JsonDirStore:
    """En JSON-fil per besok i en mapp."""

    persistent = True

    def __init__(self, path):
        self.dir = path
        os.makedirs(self.dir, exist_ok=True)

    def _file(self, rec_id):
        safe = "".join(c for c in str(rec_id) if c.isalnum() or c in "-_")[:64]
        return os.path.join(self.dir, safe + ".json") if safe else None

    def load_all(self):
        out = []
        try:
            names = sorted(os.listdir(self.dir))
        except OSError as e:
            print("[!] kunde inte lasa %s: %s" % (self.dir, e))
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), encoding="utf-8") as f:
                    out.append(json.load(f))
            except (OSError, ValueError) as e:
                print("[!] hoppar over trasig %s: %s" % (name, e))
        out.sort(key=lambda r: r.get("last", r.get("t", 0)))
        return out

    def put(self, rec):
        f = self._file(rec.get("id"))
        if not f:
            return
        tmp = f + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(rec, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, f)
        except OSError as e:
            print("[!] kunde inte skriva %s: %s" % (f, e))

    def delete(self, rec_id):
        f = self._file(rec_id)
        try:
            if f and os.path.isfile(f):
                os.remove(f)
        except OSError:
            pass

    def clear(self):
        for rec in self.load_all():
            self.delete(rec.get("id"))

    def describe(self):
        return self.dir


STORE = MemoryStore()


def migrate_legacy(old_file):
    """Tidigare versioner la allt i en enda visits.json. Flytta over en gang
    och dop om originalet, sa att ingens sparade jamforelser forsvinner."""
    if not os.path.isfile(old_file):
        return
    try:
        with open(old_file, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    moved = 0
    for rec in data.get("visits", []):
        if isinstance(rec, dict) and rec.get("id"):
            rec.setdefault("first", rec.get("t", now()))
            rec.setdefault("last", rec.get("t", now()))
            rec.setdefault("hits", 1)
            STORE.put(rec)
            moved += 1
    if moved:
        os.replace(old_file, old_file + ".migrerad")
        print("[*] flyttade %d besok ur %s till mappformatet" % (moved, old_file))


def load_visits():
    VISITS.extend(STORE.load_all()[-MAX_VISITS:])


# Attribut som aldrig fallerar eller varierar mellan tva laddningar. Nyckeln
# byggs pa dem i stallet for pa hela fingeravtrycket, som kan skifta om en
# enskild avlasning rakar sla i tidsgransen.
CORE_KEYS = ("ua", "screen", "tz", "platform", "webgl")


def visit_key(auto_label, attrs):
    """Omladdningar i samma webblasare ska sla ihop. Privat lage far en egen
    rad - det har samma fingeravtryck som vanligt lage, vilket ar just den
    poang sidan vill visa, sa avtrycket ensamt duger inte som nyckel."""
    core = "|".join(str((attrs.get(k) or {}).get("v", "")) for k in CORE_KEYS)
    return hashlib.sha256(("%s|%s" % (auto_label, core)).encode()).hexdigest()[:16]


# ------------------------------------------------------- ClientHello ----
def parse_client_hello(data):
    """Plockar ut JA3-delarna ur en TLS ClientHello. None om det inte ar en."""
    try:
        if len(data) < 45 or data[0] != 0x16:
            return None
        pos = 5
        if data[pos] != 0x01:               # handshake type: client_hello
            return None
        pos += 4                            # hoppa typ + 3 byte langd
        client_version = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + 32                       # version + random
        sid_len = data[pos]
        pos += 1 + sid_len

        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        ciphers = [int.from_bytes(data[pos + i:pos + i + 2], "big")
                   for i in range(0, cs_len, 2)]
        pos += cs_len

        comp_len = data[pos]
        pos += 1 + comp_len

        extensions, curves, point_formats = [], [], []
        alpn, sni, sig_algs, versions = [], None, [], []

        if pos + 2 <= len(data):
            ext_total = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            end = min(pos + ext_total, len(data))
            while pos + 4 <= end:
                etype = int.from_bytes(data[pos:pos + 2], "big")
                elen = int.from_bytes(data[pos + 2:pos + 4], "big")
                body = data[pos + 4:pos + 4 + elen]
                pos += 4 + elen
                extensions.append(etype)

                if etype == 0x000a and len(body) >= 2:      # supported_groups
                    n = int.from_bytes(body[0:2], "big")
                    curves = [int.from_bytes(body[2 + i:4 + i], "big")
                              for i in range(0, n, 2)]
                elif etype == 0x000b and body:               # ec_point_formats
                    point_formats = list(body[1:1 + body[0]])
                elif etype == 0x0000 and len(body) >= 5:     # SNI
                    nlen = int.from_bytes(body[3:5], "big")
                    sni = body[5:5 + nlen].decode("ascii", "replace")
                elif etype == 0x0010 and len(body) >= 2:     # ALPN
                    p = 2
                    while p < len(body):
                        ln = body[p]
                        alpn.append(body[p + 1:p + 1 + ln].decode("ascii", "replace"))
                        p += 1 + ln
                elif etype == 0x000d and len(body) >= 2:     # signature_algorithms
                    n = int.from_bytes(body[0:2], "big")
                    sig_algs = [int.from_bytes(body[2 + i:4 + i], "big")
                                for i in range(0, n, 2)]
                elif etype == 0x002b and body:               # supported_versions
                    versions = [int.from_bytes(body[1 + i:3 + i], "big")
                                for i in range(0, body[0], 2)]

        def clean(xs):
            return [x for x in xs if x not in GREASE]

        ja3 = "{},{},{},{},{}".format(
            client_version,
            "-".join(str(c) for c in clean(ciphers)),
            "-".join(str(e) for e in clean(extensions)),
            "-".join(str(c) for c in clean(curves)),
            "-".join(str(p) for p in point_formats),
        )
        return {
            "ja3": ja3,
            "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(),
            "client_version": hex(client_version),
            "supported_versions": [hex(v) for v in clean(versions)],
            "cipher_count": len(clean(ciphers)),
            "ciphers": [hex(c) for c in clean(ciphers)],
            "extensions": [hex(e) for e in clean(extensions)],
            "curves": [hex(c) for c in clean(curves)],
            "sig_algs": [hex(s) for s in clean(sig_algs)],
            "alpn": alpn,
            "sni": sni,
            "grease": any(c in GREASE for c in ciphers + extensions),
        }
    except Exception:
        return None


def peek_client_hello(conn, deadline=1.5):
    """MSG_PEEK tills hela TLS-posten finns i bufferten, sen parse.

    En enda recv kan ge ett avhugget ClientHello - olika klienter delar upp
    det olika. Vi laser om tills record-langden i huvudet ar uppfylld.
    """
    end = time.time() + deadline
    buf = b""
    try:
        while True:
            left = end - time.time()
            if left <= 0:
                break
            conn.settimeout(left)
            chunk = conn.recv(16384, socket.MSG_PEEK)
            if not chunk:
                break
            buf = chunk
            if len(buf) >= 5:
                want = 5 + int.from_bytes(buf[3:5], "big")
                if len(buf) >= want or want > 16384:
                    break
            time.sleep(0.01)
    except (OSError, ValueError):
        pass
    finally:
        try:
            conn.settimeout(None)
        except OSError:
            pass
    return parse_client_hello(buf) if buf else None


class PeekingServer(ThreadingHTTPServer):
    """Tjuvkikar pa ClientHello innan TLS-handskakningen tar over."""
    daemon_threads = True
    allow_reuse_address = True
    tls_context = None

    def get_request(self):
        conn, addr = self.socket.accept()
        if self.tls_context is not None:
            parsed = peek_client_hello(conn)
            if parsed:
                with LOCK:
                    cap_dict(TLS_INFO, MAX_TLS)   # aldsta anslutningen slas ut
                    TLS_INFO[addr] = parsed
            conn = self.tls_context.wrap_socket(conn, server_side=True)
        return conn, addr


# ----------------------------------------------------------- handler ----
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "leakscope"
    sys_version = ""

    def log_message(self, *a):
        pass  # vi loggar sjalva, i minnet

    # -- helpers --------------------------------------------------------
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, indent=2).encode(),
                   "application/json; charset=utf-8", extra)

    def _record(self):
        entry = {
            "t": now(),
            "ip": self.client_address[0],
            "port": self.client_address[1],
            "line": self.requestline,
            "ua": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
        }
        with LOCK:
            CONNECTIONS.append(entry)
            del CONNECTIONS[:-MAX_LOG]

    # -- vad servern ser utan en rad JavaScript -------------------------
    def server_view(self):
        headers = [[k, v] for k, v in self.headers.items()]
        order = [k for k, _ in headers]
        hdr_fp = hashlib.sha256(
            ("|".join(order) + "||" + self.request_version).encode()
        ).hexdigest()[:16]

        raw_head = self.requestline + "\r\n" + "".join(
            "{}: {}\r\n".format(k, v) for k, v in headers) + "\r\n"

        tls = None
        with LOCK:
            tls = TLS_INFO.get(self.client_address)
        negotiated = None
        sock = self.connection
        if hasattr(sock, "cipher") and sock.cipher():
            negotiated = {
                "version": sock.version(),
                "cipher": sock.cipher()[0],
                "bits": sock.cipher()[2],
                "alpn": sock.selected_alpn_protocol(),
            }

        with LOCK:
            log = list(CONNECTIONS[-40:])

        return {
            "network": {
                "ip": self.client_address[0],
                "source_port": self.client_address[1],
                "server_port": self.server.server_address[1],
                "is_loopback": self.client_address[0] in ("0.0.0.0", "::1"),
                "reverse_dns": self._rdns(),
            },
            "http": {
                "request_line": self.requestline,
                "version": self.request_version,
                "header_count": len(headers),
                "header_order": order,
                "header_order_fingerprint": hdr_fp,
                "headers": headers,
                "raw_head": raw_head,
                "cookies_sent": self.headers.get("Cookie", ""),
                "if_none_match": self.headers.get("If-None-Match", ""),
            },
            "tls": {
                "client_hello": tls,
                "negotiated": negotiated,
            },
            "behaviour": {
                "requests_this_session": len(log),
                "log": log,
            },
            # Sidan behover veta vilka lagen som ar paslagna for att kunna
            # lanka dit - annars ar de osynliga om man inte kan flaggorna.
            "features": {
                "demo": DEMO,
                "board": BOARD_ON,
                "port": self.server.server_address[1],
                "site_a": SITE_A,
                "site_b": SITE_B,
                "tracker": TRACKER,
            },
            "server_time": now(),
        }

    def _cookies(self):
        out = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _rdns(self):
        try:
            return socket.gethostbyaddr(self.client_address[0])[0]
        except Exception:
            return None

    # -- routes ---------------------------------------------------------
    def do_GET(self):
        self._record()
        path = self.path.split("?")[0]

        if path == "/":
            return self._file("index.html", "text/html; charset=utf-8")
        if path == "/api/server-view":
            return self._json(self.server_view())
        if path == "/api/etag-pixel":
            return self._etag_pixel()
        if DEMO and (path.startswith("/demo") or path.startswith("/t/")):
            return self._demo_routes(path)
        if path == "/noscript" or path.startswith("/noscript/"):
            return self._noscript_routes(path)
        if path == "/skydd":
            return self._file("skydd.html", "text/html; charset=utf-8")
        if path == "/api/visits":
            with LOCK:
                return self._json({"visits": VISITS, "persisted": STORE.persistent})
        if path == "/api/board":
            q = parse_qs(urlparse(self.path).query)
            return self._json(board_stats(q.get("fp", [None])[0]))
        if path.startswith("/static/"):
            name = os.path.basename(path)
            return self._file(name, static_type(name))
        self._send(404, b"not found")

    def do_POST(self):
        self._record()
        path = self.path.split("?")[0]
        if path not in ("/api/client-view", "/api/visits", "/api/visits/label",
                        "/api/board"):
            return self._send(404, b"not found")
        try:
            n = int(self.headers.get("Content-Length", 0))
            # Tak pa kroppen: en enorm POST ska inte kunna binda en trad och
            # ata minne medan servern vantar in den.
            if n > MAX_BODY:
                return self._json({"error": "for stor"}, 413)
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json({"error": "bad payload"}, 400)

        if path == "/api/board":
            if not BOARD_ON:
                return self._json({"off": True})
            fp = str(payload.get("fingerprint", ""))[:64]
            attrs = payload.get("attrs")
            if not fp or not isinstance(attrs, dict):
                return self._json({"error": "bad payload"}, 400)
            board_record(fp, {str(k)[:40]: str(v)[:400] for k, v in list(attrs.items())[:60]},
                         self.client_address[0])
            return self._json(board_stats(fp))
        if path == "/api/visits":
            return self._json(self._upsert_visit(payload) or {"error": "attrs saknas"},
                              200 if isinstance(payload.get("attrs"), dict) else 400)
        if path == "/api/visits/label":
            return self._relabel(payload)

        fp = str(payload.get("fingerprint", ""))[:128]
        ip = self.client_address[0]
        with LOCK:
            rec = FINGERPRINTS.setdefault(fp, {"count": 0, "first": now(), "ips": []})
            rec["count"] += 1
            rec["last"] = now()
            if ip not in rec["ips"]:
                rec["ips"].append(ip)
            cap_dict(FINGERPRINTS, MAX_FINGERPRINTS, ts="last")
            snapshot = dict(rec)
            total = len(FINGERPRINTS)

        # Varje anslutning som nar hit sparas - ingen knapp att trycka pa.
        saved = None
        if isinstance(payload.get("attrs"), dict):
            saved = self._upsert_visit(payload, fp)

        self._json({
            "fingerprint": fp,
            "times_seen": snapshot["count"],
            "first_seen": snapshot["first"],
            "seen_from_ips": snapshot["ips"],
            "distinct_fingerprints_known": total,
            "visit": saved,
        })

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path == "/api/reset":
            with LOCK:
                CONNECTIONS.clear()
                FINGERPRINTS.clear()
                ETAG_IDENTITIES.clear()
            return self._json({"ok": True})
        if path == "/api/visits":
            with LOCK:
                VISITS.clear()
                STORE.clear()
            return self._json({"ok": True, "remaining": 0})
        if path.startswith("/api/visits/"):
            vid = path.rsplit("/", 1)[-1]
            with LOCK:
                before = len(VISITS)
                VISITS[:] = [v for v in VISITS if v.get("id") != vid]
                removed = before - len(VISITS)
                if removed:
                    STORE.delete(vid)
                left = len(VISITS)
            return self._json({"ok": bool(removed), "remaining": left},
                              200 if removed else 404)
        self._send(404, b"not found")


    # -- tredjepartsdemon -----------------------------------------------
    def _demo_routes(self, path):
        port = self.server.server_address[1]
        if path == "/demo" or path == "/demo/":
            return self._html(demo_landing(port))
        if path == "/demo/site-a":
            return self._html(demo_page(SITE_A, port))
        if path == "/demo/site-b":
            return self._html(demo_page(SITE_B, port))
        if path == "/t/tag.js":
            body = TRACKER_TAG.replace("__TRACKER__", tracker_origin(port)).encode()
            return self._send(200, body, "application/javascript; charset=utf-8",
                              {"Access-Control-Allow-Origin": "*"})
        if path == "/t/px.gif":
            return self._tracker_pixel()
        if path == "/t/reset":
            with LOCK:
                TRACKER_HITS.clear()
            return self._send(302, b"", "text/plain",
                              {"Location": tracker_origin(port) + "/t/"})
        if path == "/t/" or path == "/t":
            return self._html(tracker_dashboard(port, self._cookies().get("fp")))
        if path == "/t/data":
            return self._json(tracker_profile())
        self._send(404, b"not found")

    def _html(self, text):
        self._send(200, text.encode("utf-8"), "text/html; charset=utf-8")

    def _tracker_pixel(self):
        q = parse_qs(urlparse(self.path).query)
        fp = (q.get("fp", [""])[0] or "utan-js")[:64]
        url = q.get("u", [""])[0][:300]
        sent = self._cookies().get("tid")
        cookie_id = sent or os.urandom(8).hex()
        record_hit(self.client_address[0], cookie_id, bool(sent), fp, url,
                   self.headers.get("Referer", ""), self.headers.get("User-Agent", ""))
        # SameSite=None kravs for tredjepartscookies; Secure kravs i sin tur av
        # webblasaren, men loopback raknas som sakert ursprung.
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(GIF_1PX)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie",
                         "tid=%s; Path=/; Max-Age=31536000; SameSite=None; Secure" % cookie_id)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(GIF_1PX)

    # -- fingeravtryck utan javascript -----------------------------------
    def _noscript_routes(self, path):
        parts = [x for x in path.split("/") if x]          # ["noscript", ...]
        if len(parts) == 1:
            sid = noscript_session()
            scheme = "https" if hasattr(self.connection, "cipher") else "http"
            return self._html(noscript_page(sid, self.server.server_address[1], scheme))
        sid = parts[1]
        # Ett sid ar alltid 16 hex (os.urandom(8).hex()). Allt annat avvisas,
        # vilket omojliggor CSS-injektion via sid i noscript_css.
        if not re.fullmatch(r"[0-9a-f]{16}", sid):
            return self._send(404, b"not found")
        if len(parts) == 3 and parts[2] == "probe.css":
            noscript_record(sid, "css", None, None, self.client_address[0],
                            self.headers.get("User-Agent", ""))
            return self._send(200, noscript_css(sid).encode(),
                              "text/css; charset=utf-8")
        if len(parts) == 3 and parts[2] == "resultat":
            return self._html(noscript_result(sid))
        if len(parts) == 5 and parts[2] == "m":
            noscript_record(sid, "media", parts[3], parts[4],
                            self.client_address[0], self.headers.get("User-Agent", ""))
            return self._send(200, GIF_1PX, "image/gif", {"Cache-Control": "no-store"})
        if len(parts) == 4 and parts[2] == "f":
            # En forfragan hit betyder att local() INTE hittade typsnittet.
            noscript_record(sid, "font", parts[3], None,
                            self.client_address[0], self.headers.get("User-Agent", ""))
            return self._send(404, b"", "font/woff2", {"Cache-Control": "no-store"})
        self._send(404, b"not found")

    # -- sparade besok ---------------------------------------------------
    def _upsert_visit(self, payload, fp=None):
        """Fryser ner besoket. Samma webblasare som laddar om uppdaterar sin
        rad i stallet for att lagga till en ny."""
        attrs = payload.get("attrs")
        if not isinstance(attrs, dict):
            return None
        fp = fp if fp is not None else str(payload.get("fingerprint", ""))[:128]
        auto = str(payload.get("label", ""))[:80] or "namnlos"
        key = visit_key(auto, attrs)

        sv = self.server_view()
        ch = sv["tls"]["client_hello"]
        server = {
            "ip": sv["network"]["ip"],
            "http_version": sv["http"]["version"],
            "header_order": sv["http"]["header_order"],
            "header_order_fp": sv["http"]["header_order_fingerprint"],
            "headers": safe_headers(dict(sv["http"]["headers"])),
            "ja3_md5": ch["ja3_md5"] if ch else None,
            "ja3": ch["ja3"] if ch else None,
            "alpn": ch["alpn"] if ch else None,
            "cipher_count": ch["cipher_count"] if ch else None,
        }
        clean = {str(k)[:40]: {
            "label": str(v.get("label", k))[:120],
            "v": str(v.get("v", ""))[:4000],
            "stable": bool(v.get("stable")),
        } for k, v in list(attrs.items())[:80] if isinstance(v, dict)}

        with LOCK:
            existing = next((v for v in VISITS if v.get("id") == key), None)
            if existing:
                VISITS.remove(existing)
                rec = existing
                rec["hits"] = rec.get("hits", 1) + 1
            else:
                rec = {"id": key, "first": now(), "hits": 1,
                       "label": auto, "auto_label": auto}
            rec["auto_label"] = auto
            rec["last"] = now()
            rec["t"] = rec["last"]
            rec["fingerprint"] = fp
            # Flera skilda avtryck under samma nyckel betyder att webblasaren
            # slumpar nagot mellan besoken - det enda direkta beviset vi har
            # pa randomisering over tid, och ett starkt skydd.
            seen = rec.setdefault("fps", [])
            if fp and fp not in seen:
                seen.append(fp)
                del seen[:-20]
            rec["bits"] = payload.get("bits")
            rec["attrs"] = clean
            rec["server"] = server
            VISITS.append(rec)                 # senast aktiv hamnar sist
            for gone in VISITS[:-MAX_VISITS]:
                STORE.delete(gone.get("id"))
            del VISITS[:-MAX_VISITS]
            STORE.put(rec)
            out = {"id": rec["id"], "label": rec["label"], "hits": rec["hits"],
                   "first": rec["first"], "new": existing is None,
                   "distinct_fingerprints": len(rec.get("fps", [])),
                   "total": len(VISITS), "persisted": STORE.persistent}
        return out

    def _relabel(self, payload):
        vid = str(payload.get("id", ""))
        label = str(payload.get("label", ""))[:80] or "namnlos"
        with LOCK:
            for v in VISITS:
                if v.get("id") == vid:
                    v["label"] = label
                    STORE.put(v)
                    return self._json({"ok": True, "label": label})
        self._json({"error": "okant besok"}, 404)

    # -- etag-supercookie: spar dig utan en enda cookie ------------------
    def _etag_pixel(self):
        sent = self.headers.get("If-None-Match", "").strip('"')
        with LOCK:
            if sent and sent in ETAG_IDENTITIES:
                ETAG_IDENTITIES[sent]["hits"] += 1
                known, tag = True, sent
                hits = ETAG_IDENTITIES[sent]["hits"]
            else:
                tag = hashlib.sha256(os.urandom(16)).hexdigest()[:24]
                ETAG_IDENTITIES[tag] = {"issued": now(), "hits": 1}
                cap_dict(ETAG_IDENTITIES, MAX_ETAGS, ts="issued")
                known, hits = False, 1
        gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
               b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
               b"\x00\x00\x02\x02D\x01\x00;")
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(gif)))
        self.send_header("ETag", '"%s"' % tag)
        self.send_header("Cache-Control", "private, max-age=31536000")
        self.send_header("X-Leakscope-Recognised", "yes" if known else "no")
        self.send_header("X-Leakscope-Id", tag)
        self.send_header("X-Leakscope-Hits", str(hits))
        self.send_header("Access-Control-Expose-Headers",
                         "X-Leakscope-Recognised, X-Leakscope-Id, X-Leakscope-Hits")
        self.end_headers()
        self.wfile.write(gif)

    def _file(self, name, ctype):
        p = os.path.join(STATIC, name)
        if not os.path.isfile(p):
            return self._send(404, b"not found")
        with open(p, "rb") as f:
            self._send(200, f.read(), ctype)





# ------------------------------------------- fingeravtryck utan js ----
# Allt ovan kraver att JavaScript kor. Det har gor inte det. En stilmall
# med mediafragor som laddar var sin bild rojer skarm, lage, pekdon och
# mer - servern ser vilka forfragningar som kom in. Och @font-face med
# local() avslojar installerade typsnitt: om typsnittet FINNS anvands det
# och ingen url hamtas, saknas det hamtas reservadressen. En utebliven
# forfragan ar alltsa ocksa information.

# (nyckel, varde, css-villkor) - varje rad blir en regel som laddar sin bild
MEDIA_PROBES = [
    ("bredd", "0-480", "(max-width: 480px)"),
    ("bredd", "481-768", "(min-width: 481px) and (max-width: 768px)"),
    ("bredd", "769-1024", "(min-width: 769px) and (max-width: 1024px)"),
    ("bredd", "1025-1440", "(min-width: 1025px) and (max-width: 1440px)"),
    ("bredd", "1441-1920", "(min-width: 1441px) and (max-width: 1920px)"),
    ("bredd", "1921+", "(min-width: 1921px)"),
    ("hojd", "0-600", "(max-height: 600px)"),
    ("hojd", "601-900", "(min-height: 601px) and (max-height: 900px)"),
    ("hojd", "901+", "(min-height: 901px)"),
    ("pixeltathet", "1x", "(resolution: 1dppx)"),
    ("pixeltathet", "1.5x", "(resolution: 1.5dppx)"),
    ("pixeltathet", "2x", "(resolution: 2dppx)"),
    ("pixeltathet", "3x+", "(min-resolution: 2.5dppx)"),
    ("farglage", "morkt", "(prefers-color-scheme: dark)"),
    ("farglage", "ljust", "(prefers-color-scheme: light)"),
    ("rorelse", "reducerad", "(prefers-reduced-motion: reduce)"),
    ("kontrast", "forhojd", "(prefers-contrast: more)"),
    ("kontrast", "sankt", "(prefers-contrast: less)"),
    ("tvingade-farger", "ja", "(forced-colors: active)"),
    ("genomskinlighet", "reducerad", "(prefers-reduced-transparency: reduce)"),
    ("pekdon", "grovt", "(any-pointer: coarse)"),
    ("pekdon", "fint", "(any-pointer: fine)"),
    ("pekdon", "inget", "(any-pointer: none)"),
    ("hovring", "finns", "(any-hover: hover)"),
    ("hovring", "saknas", "(any-hover: none)"),
    ("fargomfang", "srgb", "(color-gamut: srgb)"),
    ("fargomfang", "p3", "(color-gamut: p3)"),
    ("fargomfang", "rec2020", "(color-gamut: rec2020)"),
    ("riktning", "liggande", "(orientation: landscape)"),
    ("riktning", "staende", "(orientation: portrait)"),
    ("monokrom", "ja", "(min-monochrome: 1)"),
    ("inverterat", "ja", "(inverted-colors: inverted)"),
    ("dynamiskt-omfang", "hogt", "(dynamic-range: high)"),
    ("uppdatering", "langsam", "(update: slow)"),
    ("uppdatering", "snabb", "(update: fast)"),
    ("visningslage", "fristaende", "(display-mode: standalone)"),
    ("visningslage", "flik", "(display-mode: browser)"),
    ("javascript", "avstangt", "(scripting: none)"),
    ("javascript", "pa", "(scripting: enabled)"),
]

# Typsnitt vars narvaro skvallrar om operativsystem, kontorspaket och yrke.
FONT_PROBES = [
    ("Calibri", "Windows + Office"),
    ("Cambria", "Windows + Office"),
    ("Segoe UI", "Windows"),
    ("Tahoma", "Windows"),
    ("Menlo", "macOS"),
    ("Helvetica Neue", "macOS"),
    ("SF Pro Text", "macOS"),
    ("DejaVu Sans", "Linux"),
    ("Liberation Sans", "Linux"),
    ("Ubuntu", "Linux (Ubuntu)"),
    ("Cantarell", "Linux (GNOME)"),
    ("Noto Sans", "Linux / Android"),
    ("JetBrains Mono", "utvecklare"),
    ("Fira Code", "utvecklare"),
    ("Source Code Pro", "utvecklare"),
    ("Microsoft YaHei", "kinesiskt sprakpaket"),
    ("Hiragino Sans", "japanskt sprakpaket"),
]

OS_HINTS = {"Windows": ("Calibri", "Cambria", "Segoe UI", "Tahoma"),
            "macOS": ("Menlo", "Helvetica Neue", "SF Pro Text"),
            "Linux": ("DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell")}


def font_slug(name):
    return "".join(c if c.isalnum() else "-" for c in name)


def noscript_session():
    sid = os.urandom(8).hex()
    with LOCK:
        cap_dict(NOSCRIPT, MAX_PROBES, ts="t")   # aldsta sessionen slas ut
        NOSCRIPT[sid] = {"t": now(), "media": {}, "fonts_missing": [],
                         "css_fetched": False, "ip": "", "ua": ""}
    return sid


def noscript_record(sid, kind, key, value, ip="", ua=""):
    with LOCK:
        rec = NOSCRIPT.get(sid)
        if not rec:
            return
        rec["ip"] = ip or rec["ip"]
        rec["ua"] = ua or rec["ua"]
        if kind == "css":
            rec["css_fetched"] = True
        elif kind == "media":
            rec["media"].setdefault(key, [])
            if value not in rec["media"][key]:
                rec["media"][key].append(value)
        elif kind == "font":
            if key not in rec["fonts_missing"]:
                rec["fonts_missing"].append(key)


def noscript_css(sid):
    """Stilmallen som gor jobbet. Varje mediafraga som slar till laddar sin
    egen bild; varje typsnitt som SAKNAS gor att reservadressen hamtas."""
    out = ["/* leakscope - sonderande stilmall. Ingen JavaScript inblandad. */",
           ".p{position:absolute;left:-9999px;width:1px;height:1px;opacity:.01}",
           ".f{position:absolute;left:-9999px;font-size:8px;opacity:.01}"]
    for i, (key, value, cond) in enumerate(MEDIA_PROBES):
        out.append("@media %s{#p%d{background-image:url(/noscript/%s/m/%s/%s)}}"
                   % (cond, i, sid, key, value))
    for name, _ in FONT_PROBES:
        slug = font_slug(name)
        out.append('@font-face{font-family:"pf-%s";'
                   'src:local("%s"),url(/noscript/%s/f/%s) format("woff2");'
                   'font-display:block}' % (slug, name, sid, slug))
        out.append('.f-%s{font-family:"pf-%s"}' % (slug, slug))
    return "\n".join(out)


def noscript_page(sid, port, scheme):
    probes = "".join('<div class="p" id="p%d"></div>' % i
                     for i in range(len(MEDIA_PROBES)))
    fonts = "".join('<span class="f f-%s">Aa</span>' % font_slug(n)
                    for n, _ in FONT_PROBES)
    return """<!DOCTYPE html>
<html lang="sv"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Utan JavaScript</title>
<link rel="stylesheet" href="/static/style.css">
<link rel="stylesheet" href="/noscript/%s/probe.css">
</head><body>
<header><h1>Fingeravtryck utan JavaScript</h1>
<p class="lead">Den har sidan kor inte ett enda skript. Allt som hander ar att
webblasaren hamtar en stilmall - och stilmallen ar skriven sa att den rojer dig.</p>
<p class="lead">Mediafragor som slar till laddar var sin bild, sa servern ser vilka
som gallde: skarmstorlek, pixeltathet, morkt lage, pekdon, fargomfang. Och
<code>@font-face</code> med <code>local()</code> avslojar installerade typsnitt -
finns typsnittet anvands det och ingen adress hamtas, saknas det hamtas
reservadressen. Aven en <em>utebliven</em> forfragan ar information.</p>
<div class="verdict bad">Sla av JavaScript helt och ladda om. Resultatet blir
detsamma - det ar hela poangen.</div>
<div class="actions"><a href="/noscript/%s/resultat"><button>Visa vad stilmallen rojde</button></a>
<a href="/"><button>Tillbaka till leakscope</button></a></div>
</header>
<main><section>
<p class="muted">Sonderna ligger nedan, osynliga. Lamna sidan oppen ett ogonblick
sa att webblasaren hinner hamta det den ska, och oppna sedan resultatet.</p>
%s%s
</section></main></body></html>""" % (sid, sid, probes, fonts)


def noscript_result(sid):
    with LOCK:
        rec = dict(NOSCRIPT.get(sid) or {})
    if not rec:
        return """<!DOCTYPE html><html lang="sv"><head><meta charset="utf-8">
<title>Okand session</title><link rel="stylesheet" href="/static/style.css"></head>
<body><header><h1>Okand session</h1>
<p class="lead">Sessionen finns inte kvar. <a href="/noscript">Borja om.</a></p>
</header></body></html>"""

    media = rec.get("media", {})
    missing = set(rec.get("fonts_missing", []))
    present = [(n, w) for n, w in FONT_PROBES if font_slug(n) not in missing]

    rows = "".join(
        "<div class='kv'><span>%s</span><code class='hl'>%s</code></div>"
        % (esc(k), esc(", ".join(v))) for k, v in sorted(media.items()))

    fontrows = "".join(
        "<tr><td class='k'>%s</td><td>%s</td><td><code>%s</code></td></tr>"
        % (n, w, "finns" if font_slug(n) not in missing else "saknas")
        for n, w in FONT_PROBES)

    names = {n for n, _ in present}
    guesses = [os_name for os_name, fonts in OS_HINTS.items()
               if len(names.intersection(fonts)) >= 2]
    dev = [n for n in ("JetBrains Mono", "Fira Code", "Source Code Pro") if n in names]
    locale = [w for n, w in present if "sprakpaket" in w]

    slutsats = []
    if guesses:
        slutsats.append("Operativsystem: <strong>%s</strong>" % " eller ".join(guesses))
    if media.get("bredd"):
        slutsats.append("Skarmbredd kring <strong>%s px</strong>" % esc(media["bredd"][0]))
    if media.get("pixeltathet"):
        slutsats.append("Pixeltathet <strong>%s</strong>" % esc(media["pixeltathet"][0]))
    if media.get("farglage"):
        slutsats.append("Kor <strong>%s</strong> grannsnitt" % esc(media["farglage"][0]))
    if media.get("pekdon"):
        slutsats.append("Pekdon: <strong>%s</strong>" % esc(", ".join(media["pekdon"])))
    if dev:
        slutsats.append("Troligen <strong>utvecklare</strong> - har %s" % ", ".join(dev))
    if locale:
        slutsats.append("Sprakpaket: <strong>%s</strong>" % ", ".join(locale))
    js = media.get("javascript", [])
    if js:
        slutsats.append("JavaScript var <strong>%s</strong> nar sidan laddades" % esc(js[0]))

    signals = sum(len(v) for v in media.values()) + len(present)
    status = ("<p class='verdict bad'>%d signaler, noll skript. "
              "Stilmallen ensam racker.</p>" % signals) if rec.get("css_fetched") else \
             ("<p class='verdict good'>Stilmallen har inte hamtats an. Ladda "
              "sondsidan forst, vanta ett ogonblick, och kom tillbaka hit.</p>")

    return """<!DOCTYPE html><html lang="sv"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Vad stilmallen rojde</title><link rel="stylesheet" href="/static/style.css"></head>
<body><header><h1>Vad stilmallen rojde</h1>
<p class="lead">Uppdateras var femte sekund, utan JavaScript - det ar
<code>&lt;meta http-equiv="refresh"&gt;</code> som gor det.</p>
%s
<div class="actions"><a href="/noscript"><button>Ny session</button></a>
<a href="/"><button>Tillbaka till leakscope</button></a></div>
</header><main><section>
<h3>Slutsatser</h3><ul class="invlist">%s</ul>
<h3>Mediafragor som slog till</h3>%s
<h3>Typsnitt (%d av %d finns)</h3>
<p class="muted">En forfragan betyder att typsnittet <em>saknas</em>. Att servern
inte hor av sig ar alltsa beviset for att du har det.</p>
<table>%s</table>
<p class="muted">IP: <code>%s</code> &middot; User-Agent: <code>%s</code></p>
</section></main></body></html>""" % (
        status,
        "".join("<li>%s</li>" % x for x in slutsats) or "<li class='muted'>Inget an.</li>",
        rows or "<p class='muted'>Inga an.</p>",
        len(present), len(FONT_PROBES), fontrows,
        esc(rec.get("ip", "-")), esc((rec.get("ua", "-") or "-")[:90]))

# --------------------------------------------------- klassrumslaget ----
# Entropisiffrorna i sidan ar uppskattningar. Har mats unikheten i stallet,
# i den faktiska grupp som surfat in - vilket ar betydligt mer overtygande
# an en teoretisk siffra. Pa som flagga, eftersom det samlar uppgifter om
# andra personer an den som startat servern.

def board_record(fp, attrs, ip):
    """Kallorna sparas per avtryck, men vi raknar aven hur manga skilda IP
    som gett samma avtryck. Tva enheter med identiskt avtryck ar just det
    som gor nagon icke-unik, och utan IP-rakningen skulle de kollapsa till
    en rad och se unika ut."""
    with LOCK:
        rec = BOARD.setdefault(fp, {"first": now(), "ips": [], "hits": 0})
        rec["t"] = now()
        rec["attrs"] = attrs
        rec["hits"] += 1
        if ip not in rec["ips"]:
            rec["ips"].append(ip)
        cap_dict(BOARD, MAX_BOARD, ts="t")   # minst nyligen aktiv slas ut, aldrig hela tavlan


def board_stats(my_fp=None):
    """For varje attribut: hur manga av besokarna delar ditt varde?"""
    with LOCK:
        snapshot = {k: dict(v) for k, v in BOARD.items()}
    n = len(snapshot)
    mine = snapshot.get(my_fp, {}).get("attrs", {})

    keys = set()
    for v in snapshot.values():
        keys.update(v["attrs"].keys())

    rows = []
    for k in keys:
        counts = {}
        for v in snapshot.values():
            val = v["attrs"].get(k)
            if val is not None:
                counts[val] = counts.get(val, 0) + 1
        if not counts:
            continue
        my_val = mine.get(k)
        share = counts.get(my_val, 0) if my_val is not None else 0
        # Ett attribut som bara en enda besokare rapporterat sager ingenting
        # om unikhet - da saknas jamforelsematerial, det ar inte ett bevis.
        coverage = sum(counts.values())
        rows.append({
            "key": k,
            "distinct": len(counts),
            "coverage": coverage,
            "biggest_group": max(counts.values()),
            "you_share_with": share,
            "unique_here": share == 1 and coverage >= 2,
            "enough_data": coverage >= 2,
            "my_value": my_val,
        })
    rows.sort(key=lambda r: (r["you_share_with"], -r["distinct"]))

    # Ett avtryck som setts fran flera IP delas av flera enheter - det ar
    # det enda direkta beviset vi har pa att nagon INTE ar unik.
    shared = [fp for fp, v in snapshot.items() if len(v.get("ips", [])) > 1]
    devices = len({ip for v in snapshot.values() for ip in v.get("ips", [])})
    my_ips = len(snapshot.get(my_fp, {}).get("ips", [])) if my_fp else 0
    return {
        "fingerprints": n,
        "devices": devices,
        "shared_fingerprints": len(shared),
        "unique_fingerprints": n - len(shared),
        "you_are_unique": bool(my_fp) and my_fp in snapshot and my_ips <= 1,
        "you_share_with_devices": max(0, my_ips - 1),
        "rows": rows,
        "has_me": bool(my_fp) and my_fp in snapshot,
    }

# ------------------------------------------------- tredjepartsdemon ----
# Tva sajter du besoker, och en tredje part du aldrig besoker som finns pa
# bada. Precis sa fungerar Meta Pixel och Google Analytics: sajten baddar in
# en bild och ett skript fran sparningsnatverket, och natverket far din
# IP, din Referer och sin egen cookie - utan att du nagonsin varit dar.

GIF_1PX = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
           b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
           b"\x00\x00\x02\x02D\x01\x00;")

TRACKER_TAG = """/* Sparningsnatverkets tagg. Laddas av varje sajt som ar med.
   Den mater ett latt fingeravtryck och skickar det som en bildforfragan -
   samma teknik som riktiga pixlar, och den gar inte att stoppa med CORS. */
(function () {
  function light() {
    var c = document.createElement('canvas');
    c.width = 200; c.height = 40;
    var x = c.getContext('2d');
    x.textBaseline = 'top'; x.font = '13px Arial';
    x.fillStyle = '#39f'; x.fillRect(0, 0, 80, 18);
    x.fillStyle = '#107'; x.fillText('tracker \u00e5\u00e4\u00f6', 2, 12);
    var gl = document.createElement('canvas').getContext('webgl');
    var dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
    var parts = [
      navigator.userAgent, navigator.language, navigator.languages.join(','),
      screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
      window.devicePixelRatio, navigator.hardwareConcurrency,
      navigator.deviceMemory, navigator.maxTouchPoints,
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '',
      c.toDataURL()
    ].join('|');
    var h1 = 0x811c9dc5, h2 = 0x1000193;
    for (var i = 0; i < parts.length; i++) {
      h1 = (h1 ^ parts.charCodeAt(i)) >>> 0;
      h1 = (h1 * 16777619) >>> 0;
      h2 = (h2 + parts.charCodeAt(i) * (i % 31 + 7)) >>> 0;
    }
    return ('00000000' + h1.toString(16)).slice(-8) + ('00000000' + h2.toString(16)).slice(-8);
  }
  var fp;
  try { fp = light(); } catch (e) { fp = 'fel'; }
  var px = new Image();
  px.src = '__TRACKER__/t/px.gif?fp=' + fp
         + '&u=' + encodeURIComponent(location.href)
         + '&t=' + Date.now();
  window.__trackerFp = fp;
})();
"""


def tracker_origin(port):
    return "http://%s:%d" % (TRACKER, port)


def record_hit(ip, cookie_id, cookie_was_sent, fp, url, referer, ua):
    with LOCK:
        TRACKER_HITS.append({
            "t": now(), "ip": ip, "cookie": cookie_id,
            "cookie_sent": cookie_was_sent, "fp": fp,
            "url": url, "referer": referer, "ua": ua,
        })
        del TRACKER_HITS[:-MAX_HITS]


def tracker_profile():
    """Vad natverket kan satta ihop. Tva oberoende sparningsvagar:
    cookien (blockeras ofta) och fingeravtrycket (blockeras sallan)."""
    with LOCK:
        hits = list(TRACKER_HITS)
    by_cookie, by_fp = {}, {}
    for h in hits:
        by_cookie.setdefault(h["cookie"], []).append(h)
        by_fp.setdefault(h["fp"], []).append(h)

    def site_of(url):
        try:
            host = urlparse(url).hostname or "?"
        except ValueError:
            host = "?"
        return SITE_NAMES.get(host, host)

    groups = []
    for fp, hs in by_fp.items():
        cookies = sorted({h["cookie"] for h in hs})
        blocked = all(not h["cookie_sent"] for h in hs) and len(cookies) > 1
        groups.append({
            "fp": fp,
            "cookies": cookies,
            "cookie_blocked": blocked,
            "sites": sorted({site_of(h["url"]) for h in hs}),
            "hits": len(hs),
            "first": min(h["t"] for h in hs),
            "last": max(h["t"] for h in hs),
            "ip": hs[-1]["ip"],
            "ua": hs[-1]["ua"],
            "trail": [{"t": h["t"], "site": site_of(h["url"]), "url": h["url"],
                       "referer": h["referer"], "cookie": h["cookie"],
                       "cookie_sent": h["cookie_sent"]} for h in hs[-25:]],
        })
    groups.sort(key=lambda g: -g["last"])
    return {"groups": groups, "total_hits": len(hits),
            "distinct_cookies": len(by_cookie), "distinct_fingerprints": len(by_fp)}


def demo_page(role, port):
    """Sidorna som baddar in sparningstaggen. Avsiktligt vardagliga."""
    tracker = tracker_origin(port)
    other = SITE_B if role == SITE_A else SITE_A
    other_name = SITE_NAMES[other]
    body = {
        SITE_A: ("Nyhetssidan", "Dagens rubriker",
                 ["Kommunen bygger ny cykelbro", "Elpriset vande nedat i natt",
                  "Sa blir vadret i helgen"]),
        SITE_B: ("Webbutiken", "Veckans erbjudanden",
                 ["Horlurar - 30 % rabatt", "Skrivbordslampa i ek",
                  "Tangentbord med brun switch"]),
    }[role]
    items = "".join("<li>%s</li>" % i for i in body[2])
    return """<!DOCTYPE html>
<html lang="sv"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title><link rel="stylesheet" href="/static/style.css"></head><body>
<header><h1>%s</h1><p class="lead">%s</p></header>
<main>
<section>
  <ul class="takeaway">%s</ul>
  <div class="verdict bad" style="margin-top:28px">
    Den har sidan baddar in en bild och ett skript fran
    <code>%s</code> - ett sparningsnatverk du aldrig besokt.
    Det sker automatiskt, utan att du godkanner nagot.
  </div>
  <p class="lead">Besok nu <a href="http://%s:%d/demo/site-%s">%s</a> och oppna sedan
    <a href="%s/t/">sparningsnatverkets egen vy</a> for att se vad det satt ihop.</p>
  <p class="muted">Tillbaka till <a href="http://%s:%d/demo">demons startsida</a>
    eller <a href="http://%s:%d/">leakscope</a>.</p>
</section>
</main>
<!-- Sa har ser det ut pa riktigt: en pixel och en tagg -->
<img src="%s/t/px.gif?u=%s&amp;noscript=1" width="1" height="1" alt="" style="position:absolute">
<script src="%s/t/tag.js"></script>
</body></html>""" % (
        body[0], body[0], body[1], items, tracker,
        other, port, "b" if other == SITE_B else "a", other_name, tracker,
        SITE_A, port, SITE_A, port,
        tracker, ("http://%s:%d/demo/site-%s" % (role, port, "a" if role == SITE_A else "b")),
        tracker)


def demo_landing(port):
    return """<!DOCTYPE html>
<html lang="sv"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tredjepartsdemo</title><link rel="stylesheet" href="/static/style.css"></head><body>
<header><h1>Spard utan att godkanna nagot</h1>
<p class="lead">Tva sajter pa skilda vardar, och en tredje part som finns pa bada.
Du besoker aldrig den tredje parten - anda vet den var du varit. Det ar sa
Meta Pixel och Google Analytics fungerar.</p></header>
<main><section>
<h2>Gor sa har</h2>
<ul class="takeaway">
<li><strong>1.</strong> Besok <a href="http://%s:%d/demo/site-a">Sajt A - nyhetssidan</a></li>
<li><strong>2.</strong> Besok <a href="http://%s:%d/demo/site-b">Sajt B - webbutiken</a></li>
<li><strong>3.</strong> Oppna <a href="%s/t/">sparningsnatverkets vy</a> och se vad det vet</li>
<li><strong>4.</strong> Slag pa blockering av tredjepartscookies i webblasaren och gor om det.
Cookien forsvinner - fingeravtrycket gor det inte.</li>
</ul>
<p class="muted">De tre varddatorerna ar <code>%s</code>, <code>%s</code> och
<code>%s</code> pa loopback. Skilda vardnamn ger skilda origins och skilda
cookie-burkar, sa det ar en akta tredjepartssituation och inte en simulering.</p>
<p class="muted"><a href="http://%s:%d/">Tillbaka till leakscope</a></p>
</section></main></body></html>""" % (SITE_A, port, SITE_B, port, tracker_origin(port),
                                      SITE_A, SITE_B, TRACKER, SITE_A, port)


def tracker_dashboard(port, my_fp=None):
    d = tracker_profile()
    rows = []
    for g in d["groups"]:
        mine = " (du)" if my_fp and g["fp"] == my_fp else ""
        name = ("bildpixeln, utan JavaScript" if g["fp"] == "utan-js"
                else "fingeravtryck " + g["fp"][:8])
        trail = ("<tr><td class='k'>tid</td><td>sajt</td><td>Referer - vad webblasaren "
                 "slappte ifran sig</td><td>u= - vad taggen sjalv skickade</td>"
                 "<td>cookie</td></tr>") + "".join(
            "<tr><td class='k'>%s</td><td>%s</td><td><code>%s</code></td>"
            "<td><code>%s</code></td><td><code>%s</code></td></tr>" % (
                time.strftime("%H:%M:%S", time.localtime(h["t"])), esc(h["site"]),
                esc((h["referer"] or "-")[:50]), esc((h["url"] or "-")[:50]),
                esc(h["cookie"][:10]) + ("" if h["cookie_sent"] else " (ny)"))
            for h in g["trail"])
        verdict = ""
        if g["cookie_blocked"] and len(g["sites"]) > 1:
            verdict = ("<p class='verdict bad'>Din webblasare blockerade tredjepartscookien - "
                       "natverket fick dela ut ett nytt id vid varje traff och kunde inte "
                       "folja dig den vagen. <strong>Fingeravtrycket band anda ihop besoken "
                       "till en och samma person, over bada sajterna.</strong> Du gjorde ratt "
                       "och blev spard anda.</p>")
        elif g["cookie_blocked"]:
            verdict = ("<p class='verdict bad'>Tredjepartscookien bets inte - ett nytt id "
                       "delades ut vid varje traff.</p>")
        elif len(g["sites"]) > 1:
            verdict = ("<p class='verdict bad'>Samma person pa %d sajter, hopkopplad via "
                       "cookien. Natverket har aldrig besokts av dig, och du har inte "
                       "godkant nagot.</p>" % len(g["sites"]))
        rows.append(
            "<div class='row'><div class='row-head'><span class='label'>Profil - %s%s</span>"
            "<span class='bits'>%d traffar</span></div>"
            "<div class='kv'><span>Fingeravtryck</span><code class='hl'>%s</code></div>"
            "<div class='kv'><span>Cookie-id</span><code>%s</code></div>"
            "<div class='kv'><span>Sedd pa</span><code>%s</code></div>"
            "<div class='kv'><span>IP</span><code>%s</code></div>"
            "<div class='kv'><span>User-Agent</span><code>%s</code></div>"
            "%s<details class='sub'><summary>Sparet (%d)</summary><table>%s</table></details></div>"
            % (esc(name), mine, g["hits"], esc(g["fp"]),
               esc(", ".join(c[:12] for c in g["cookies"])),
               esc(" + ".join(g["sites"])), esc(g["ip"]), esc((g["ua"] or "")[:90]),
               verdict, len(g["trail"]), trail))

    empty = ("<p class='muted'>Inget registrerat an. Besok de tva sajterna forst.</p>"
             if not rows else "")
    return """<!DOCTYPE html>
<html lang="sv"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sparningsnatverket</title><link rel="stylesheet" href="/static/style.css"></head><body>
<header><h1>Sparningsnatverkets vy</h1>
<p class="lead">Det har ser den tredje parten. Du har aldrig oppnat den har varden
sjalv - allt nedan kom fran bilder och skript som andra sajter baddade in.</p>
<p class="lead">Jamfor de tva kolumnerna i varje spar. <strong>Referer</strong> ar vad
webblasaren slappte ifran sig: moderna webblasare kortar den till bara ursprunget for
att skydda dig. <strong>u=</strong> ar hela adressen som sparningstaggen sjalv skickade
med. Skyddet finns, och skriptet gar runt det.</p>
<div class="summary">
<div class="card"><span class="card-label">Profiler</span><code class="big">%d</code>
<span class="card-note">skilda fingeravtryck</span></div>
<div class="card"><span class="card-label">Traffar</span><code class="big">%d</code>
<span class="card-note">bildforfragningar fran sajterna</span></div>
<div class="card"><span class="card-label">Cookie-id</span><code class="big">%d</code>
<span class="card-note">utdelade - fler an profiler betyder blockerade cookies</span></div>
</div>
<div class="actions"><a href="%s/t/"><button>Uppdatera</button></a>
<a href="%s/t/reset"><button>Nollstall</button></a>
<span class="stamp">Sajterna: <a href="http://%s:%d/demo/site-a">A</a> ·
<a href="http://%s:%d/demo/site-b">B</a> ·
<a href="http://%s:%d/demo">demons start</a></span></div>
</header>
<main><section>%s%s</section></main></body></html>""" % (
        d["distinct_fingerprints"], d["total_hits"], d["distinct_cookies"],
        tracker_origin(port), tracker_origin(port),
        SITE_A, port, SITE_B, port, SITE_A, port, empty, "".join(rows))

# -------------------------------------------------------------- tls ----
def ensure_cert(certdir):
    os.makedirs(certdir, exist_ok=True)
    cert = os.path.join(certdir, "leakscope-cert.pem")
    key = os.path.join(certdir, "leakscope-key.pem")
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    print("[*] genererar sjalvsignerat certifikat ...")
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "365",
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit("kunde inte generera certifikat (behover openssl): %s" % e)
    return cert, key


def main():
    ap = argparse.ArgumentParser(description="visa vad du lamnar ifran dig")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--tls", action="store_true",
                    help="kor https och visa TLS-fingeravtryck (JA3)")
    ap.add_argument("--certdir", default=os.path.join(HERE, ".certs"))
    ap.add_argument("--store", default=os.path.join(HERE, "visits"),
                    help="mapp for sparade besok, en JSON-fil per besok")
    ap.add_argument("--no-store", action="store_true",
                    help="spara besok bara i minnet, skriv ingenting till disk")
    ap.add_argument("--demo", action="store_true",
                    help="starta tredjepartsdemon pa 127.0.0.1, .2 och .3")
    ap.add_argument("--board", action="store_true",
                    help="klassrumslage: mat unikhet over alla som surfar in")
    args = ap.parse_args()

    global STORE, DEMO, BOARD_ON
    DEMO = args.demo
    BOARD_ON = args.board
    if not args.no_store:
        STORE = JsonDirStore(args.store)
        migrate_legacy(os.path.join(HERE, "visits.json"))
    load_visits()

    srv = PeekingServer((args.host, args.port), Handler)
    scheme = "http"
    if args.tls:
        cert, key = ensure_cert(args.certdir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])
        srv.tls_context = ctx
        scheme = "https"

    # Demon behover tva extra lyssnare. Skilda loopback-adresser ger skilda
    # origins, vilket ar hela poangen - annars delar de cookie-burk.
    extra = []
    if DEMO:
        for addr in (SITE_B, TRACKER):
            try:
                sub = PeekingServer((addr, args.port), Handler)
                sub.tls_context = srv.tls_context
                threading.Thread(target=sub.serve_forever, daemon=True).start()
                extra.append(sub)
            except OSError as e:
                print("[!] kunde inte lyssna pa %s:%d - %s" % (addr, args.port, e))
                print("[!] demon behover att %s ar uppe (vanligt pa Linux)" % addr)

    url = "%s://%s:%d/" % (scheme, args.host, args.port)
    print("[*] leakscope kor pa %s" % url)
    if BOARD_ON:
        print("[*] klassrumslage pa - avtryck fran alla besokare samlas i minnet")
    if DEMO:
        print("[*] tredjepartsdemo: %s://%s:%d/demo  (sparare pa %s)"
              % (scheme, SITE_A, args.port, TRACKER))
    print("[*] allt stannar lokalt. ctrl-c for att avsluta.")
    print("[*] besok sparas automatiskt vid varje anslutning -> %s (%d inlasta)"
          % (STORE.describe(), len(VISITS)))
    if args.tls:
        print("[!] sjalvsignerat cert - webblasaren kommer varna. det ar vantat.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] hej da")


if __name__ == "__main__":
    main()
