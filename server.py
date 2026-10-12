#!/usr/bin/env python3
"""Exposure-telemetry web server for the AI usage-preferences paper.

Serves a small corpus of test pages, each carrying a different AI-preference
directive combination, and logs every request (timestamp, User-Agent, path,
client network identity) to a CSV file. Deploy it on a public host, wait
days/weeks, then analyze which crawlers retrieved which pages.

Purpose: RETRIEVAL OBSERVATION (evidence-ladder level 1-2). This harness
observes that a client retrieved a page carrying the signal. It does NOT
and cannot measure compliance: fetch logs cannot establish compliance
with a usage preference (see paper §1, §6.3). Crawler identity is
established by IP reverse-DNS verification, never by User-Agent alone
(user-agents are trivially spoofable).

Evidence ladder (paper §6.4):
  1. retrieval ............. a client requested the page (this harness)
  2. verified crawler ...... rDNS-verified operator identity (this harness)
  3. claimed support ........ operator documents support (out of scope)
  4. observed processing .... controlled behavioral change (future work)
  5. usage compliance ....... generally unobservable from outside

Privacy/ethics: client IPs are truncated to /24 (IPv4) or /48 (IPv6)
in canonical form via the ipaddress module and then HMAC-hashed with a
per-deployment secret before logging; raw IPs are never persisted.
User-Agent strings are length-capped and control-character-stripped,
and all logged fields are neutralized against spreadsheet formula
injection. Operator identity is established by forward-confirmed
reverse DNS (never User-Agent alone); only the verified registrable
operator domain (e.g. "googlebot.com") is logged -- never the full PTR
hostname, which routinely embeds the client IP. Retention: rows older
than --retention-days (default 90) are deleted at startup. Pass
--secret or set AIPREF_HMAC_SECRET to a random value per deployment;
if neither is given, an ephemeral secret is generated (client IDs
change on restart) and a warning is printed. Never publish the secret.

Stdlib only. No dependencies.

Usage:
    python3 server.py [--port 8000] [--log requests.csv] [--secret RANDOM]

Then point crawlers at it (submit the sitemap URL to search consoles, link
the pages from an indexed page, or simply wait for discovery).
"""
import argparse
import csv
import datetime
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

CANARY_PREFIX = "aiprefbinding"

# Normative RSL 1.0 license document (RSL-SPEC-1.0 §3): XML in the
# https://rslstandard.org/rsl namespace, served as application/rsl+xml.
# Linked from /rsl.html via <link rel="license" type="application/rsl+xml">
# (RSL 1.0 §4.6.1). <content url=""> applies the license to the scope
# established by the HTML <link> association (§3.3.1, §4.6.1).
RSL_LICENSE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rslstandard.org/rsl">
  <content url="">
    <license>
      <prohibits type="usage">ai-train</prohibits>
    </license>
  </content>
</rsl>
"""


def _rsl_head(host):
    """Normative RSL 1.0 §4.6 HTML association forms for /rsl.html.

    Returns the <head> fragment carrying BOTH normative carriers:
      - §4.6.1 linked license: <link rel="license"
        type="application/rsl+xml" href="<absolute-URL>"> (href must be
        absolute per spec; built from the request Host header)
      - §4.6.2 inline license: <script type="application/rsl+xml">
        embedding a complete RSL document with exactly one <content>
        element.

    JSON-LD is NOT a normative RSL carrier (RSL is an XML vocabulary,
    RSL-SPEC-1.0 §1); it must not be used here.
    """
    href = f"https://{host}/rsl-license.xml"
    inline = (
        '<rsl xmlns="https://rslstandard.org/rsl">'
        '<content url="">'
        "<license>"
        '<prohibits type="usage">ai-train</prohibits>'
        "</license>"
        "</content>"
        "</rsl>"
    )
    return (
        f'<link rel="license" type="application/rsl+xml" href="{href}">\n'
        f'<script type="application/rsl+xml">{inline}</script>'
    )


PAGES = {
    # Control: no directives at all. Every crawler should fetch this.
    "/control.html": {
        "title": "Control page (no directives)",
        "head": "",
        "headers": {},
        "canary": f"{CANARY_PREFIX}-control-7f3a9q",
    },
    # Proposed binding: preference to disallow training + other AI use,
    # preference to allow AIPREF-defined search.
    "/content-usage-deny-training.html": {
        "title": "content-usage: train-ai/ai-use disallow, search allow",
        "head": '<meta name="content-usage" content="train-ai=n, ai-use=n, search=y">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cutraining-2b8x1m",
    },
    # Proposed binding: preference to disallow all AI-related uses.
    "/content-usage-deny-all.html": {
        "title": "content-usage: all AI uses disallow",
        "head": '<meta name="content-usage" content="train-ai=n, ai-use=n, search=n">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cuall-9k4p2z",
    },
    # Edge case: duplicate keys (LAST wins per RFC 9651 -> train-ai=y).
    "/content-usage-duplicate-keys.html": {
        "title": "content-usage: duplicate keys (last wins)",
        "head": '<meta name="content-usage" content="train-ai=n, train-ai=y, search=y">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cudup-3m7q1w",
    },
    # Edge case: non-token value (unknown for that key per AIPREF §6.5).
    "/content-usage-nontoken.html": {
        "title": "content-usage: non-token value",
        "head": '<meta name="content-usage" content="train-ai=maybe, search=y">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cunt-6n2r4t",
    },
    # Edge case: uppercase key (invalid dictionary -> whole statement unknown).
    "/content-usage-uppercase-key.html": {
        "title": "content-usage: uppercase key (invalid dictionary)",
        "head": '<meta name="content-usage" content="Train-AI=n, search=y">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cuuc-1a9b3c",
    },
    # Edge case: tag in body (MUST be ignored per processing model).
    "/content-usage-body-tag.html": {
        "title": "content-usage: tag in body (ignored)",
        "head": "",
        "body_extra": '<meta name="content-usage" content="train-ai=n, ai-use=n, search=n">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-cubody-8p5s2v",
    },
    # AIPREF header carrier (same vocabulary, HTTP binding).
    "/header-content-usage.html": {
        "title": "Content-Usage header binding",
        "head": "",
        "headers": {"Content-Usage": "train-ai=n, ai-use=n, search=y"},
        "canary": f"{CANARY_PREFIX}-headermirror-8j3k5s",
    },
    # AIPREF robots.txt carrier: group-level Content-Usage rule.
    "/robots-content-usage.html": {
        "title": "robots.txt Content-Usage rule (see /robots.txt)",
        "head": "",
        "headers": {},
        "canary": f"{CANARY_PREFIX}-robotscu-5d7e2f",
    },
    # Coexistence: TDM Reservation Protocol.
    "/tdmrep.html": {
        "title": "TDM Reservation Protocol",
        "head": '<meta name="tdm-reservation" content="1">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-tdmrep-4w9x1z",
    },
    # Coexistence: RSL (prohibition form, not ai-train=n).
    # Normative RSL 1.0 §4.6 HTML association: BOTH the linked form
    # (<link rel="license" type="application/rsl+xml">, §4.6.1) and the
    # inline form (<script type="application/rsl+xml">, §4.6.2). The
    # inline document uses the RSL namespace and exactly one <content>
    # element, as the spec requires.
    "/rsl.html": {
        "title": "RSL prohibition (normative XML forms)",
        "head": _rsl_head,  # callable(host) -> str; see _rsl_head
        "headers": {},
        "canary": f"{CANARY_PREFIX}-rsl-2g8h4j",
    },
    # Bing-style: noarchive (no AI training, stay in search).
    "/robots-noarchive.html": {
        "title": "robots noarchive",
        "head": '<meta name="robots" content="noarchive">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-noarchive-5t7w3n",
    },
    # Bing-style: nocache (Copilot limited to URL/title/snippet).
    "/robots-nocache.html": {
        "title": "robots nocache",
        "head": '<meta name="robots" content="nocache">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-nocache-1r6v8b",
    },
    # Named-bot block (per-bot, not per-purpose): contrast case.
    "/named-gptbot-block.html": {
        "title": "named bot block (GPTBot)",
        "head": '<meta name="GPTBot" content="noindex, nofollow">',
        "headers": {},
        "canary": f"{CANARY_PREFIX}-gptbot-4d2f6h",
    },
}

ROBOTS_TXT = """User-agent: *
Allow: /
Content-Usage: train-ai=n, ai-use=n, search=y
"""

SITEMAP_PATHS = sorted(PAGES.keys())


def page_html(spec, host=None):
    head = spec["head"]
    if callable(head):
        # Dynamic head (e.g. /rsl.html builds an absolute href from Host).
        head = head(host or "localhost")
    body_extra = spec.get("body_extra", "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{spec['title']}</title>
{head}
</head>
<body>
{body_extra}
<h1>{spec['title']}</h1>
<p>This is a test page for AI usage-preference binding research.
Canary string: {spec['canary']}</p>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. This paragraph
exists so the page has indexable body content distinct from the canary.</p>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Privacy hardening: input sanitization, minimization, output neutralization
# ---------------------------------------------------------------------------

_MAX_UA_LEN = 512    # logged User-Agent cap (prevents multi-MB log bloat)
_MAX_PATH_LEN = 2048  # logged path cap


def _sanitize_ua(ua):
    """Bound and clean a User-Agent string for logging.

    - Truncates to _MAX_UA_LEN characters (a hostile client can send a
      multi-megabyte User-Agent; it must not bloat the log).
    - Replaces ASCII control characters (log/terminal injection).
    """
    if not ua:
        return "-"
    ua = re.sub(r"[\x00-\x1f\x7f]", " ", ua).strip()
    if not ua:
        return "-"
    return ua[:_MAX_UA_LEN]


def _sanitize_path(path):
    """Bound and clean a request path for logging."""
    if not path:
        return "/"
    path = re.sub(r"[\x00-\x1f\x7f]", " ", path).strip()
    return (path[:_MAX_PATH_LEN] or "/")


def _csv_safe(value):
    """Neutralize spreadsheet formula injection (OWASP "CSV Injection").

    The log is a CSV that an analyst will open in Excel/Sheets. Cells
    beginning with = + - @ (or tab/CR) are executed as formulas on
    import. Prefixing with a single quote forces text treatment.
    Applied to every attacker-influenced logged field.
    """
    if value and value[0] in "=@+-\t\r":
        return "'" + value
    return value


def _truncate_ip(ip):
    """Minimize to the routable prefix, in canonical string form.

    IPv4 -> /24 network ("192.0.2.0/24"); IPv6 -> /48 network
    ("2001:db8::/48"), computed with the ipaddress module so that
    compressed, expanded, and zone-id forms all canonicalize to the
    same HMAC input. Unparseable input maps to the constant "invalid"
    (a single bucket) instead of leaking the raw string into the hash.
    """
    host = ip.split("%", 1)[0].strip()  # strip IPv6 zone id, if any
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "invalid"
    prefix = 48 if isinstance(addr, ipaddress.IPv6Address) else 24
    return str(ipaddress.ip_network((addr, prefix), strict=False))


def _same_ip(a, b):
    """True if two textual IP forms denote the same address.

    String comparison alone false-rejects IPv6 textual variants
    (e.g. "2001:db8::1" vs "2001:0db8:0000::0001").
    """
    try:
        return (ipaddress.ip_address(a.split("%", 1)[0])
                == ipaddress.ip_address(b.split("%", 1)[0]))
    except ValueError:
        return a == b


# Bundled snapshot of multi-label public suffixes (subset of the Mozilla
# Public Suffix List) used for registrable-domain computation. Unknown
# suffixes fall back to last-two-labels; extend this set (or vendor the
# full PSL) if operator PTRs under other two-level suffixes appear.
# Source: https://publicsuffix.org/list/public_suffix_list.dat
_MULTI_LABEL_SUFFIXES = frozenset("""\
co.uk org.uk me.uk net.uk ltd.uk plc.uk sch.uk ac.uk gov.uk nhs.uk
com.au net.au org.au edu.au gov.au asn.au id.au
co.nz net.nz org.nz govt.nz school.nz ac.nz
co.jp ne.jp or.jp go.jp ac.jp ad.jp ed.jp
co.kr or.kr go.kr ac.kr ne.kr
com.cn net.cn org.cn gov.cn edu.cn
com.br net.br org.br gov.br edu.br
com.mx net.mx org.mx gob.mx edu.mx
co.in net.in org.in gov.in ac.in res.in
co.za net.za org.za gov.za ac.za
com.sg net.sg org.sg gov.sg edu.sg
com.hk net.hk org.hk gov.hk edu.hk
com.tw net.tw org.tw gov.tw edu.tw idv.tw
com.ar net.ar org.ar gob.ar edu.ar int.ar
com.co net.co nom.co edu.co gov.co
com.pe net.pe org.pe gob.pe edu.pe
com.ve net.ve org.ve gov.ve edu.ve
co.id net.id or.id go.id ac.id web.id
com.my net.my org.my gov.my edu.my
com.ph net.ph org.ph gov.ph edu.ph
com.tr net.tr org.tr gov.tr edu.tr gen.tr web.tr
co.th net.th or.th go.th ac.th
com.vn net.vn org.vn gov.vn edu.vn
com.ua net.ua org.ua gov.ua edu.ua in.ua
co.ke or.ke go.ke ac.ke ne.ke
com.ng net.ng org.ng gov.ng edu.ng
com.pk net.pk org.pk gov.pk edu.pk
com.bd net.bd org.bd gov.bd edu.bd
com.np net.np org.np gov.np edu.np
com.lk net.lk org.lk gov.lk edu.lk
co.il net.il org.il gov.il ac.il
com.sa net.sa org.sa gov.sa edu.sa med.sa
com.eg net.eg org.eg gov.eg edu.eg
co.tz go.tz or.tz ac.tz ne.tz
co.ug or.ug go.ug ac.ug ne.ug
com.kw net.kw org.kw gov.kw edu.kw
com.qa net.qa org.qa gov.qa edu.qa
com.bh net.bh org.bh gov.bh edu.bh
com.om net.om org.om gov.om edu.om
com.jo net.jo org.jo gov.jo edu.jo net.jo
com.lb net.lb org.lb gov.lb edu.lb
com.cy net.cy org.cy gov.cy
com.mt net.mt org.mt gov.mt edu.mt
eu.com gb.com uk.com us.com de.com
co.cr ac.cr go.cr or.cr ed.cr fi.cr sa.cr
com.do net.do org.do gov.do edu.do
com.gt net.gt org.gt gob.gt edu.gt ind.gt
com.hn net.hn org.hn gob.hn edu.hn
com.pa net.pa org.pa gob.pa edu.pa sld.pa
com.py net.py org.py gov.py edu.py
com.uy net.uy org.uy gub.uy edu.uy
com.ec net.ec info.ec pro.ec edu.ec gov.ec med.ec fin.ec
com.bo net.bo org.bo gob.bo edu.bo tv.bo
nom.es org.es gob.es edu.es
com.pt net.pt org.pt gov.pt edu.pt
""".split())


def _registrable_domain(hostname):
    """Registrable domain (eTLD+1) of a hostname.

    Uses the bundled multi-label suffix snapshot above; unknown
    suffixes fall back to last-two-labels (documented limitation --
    extend the snapshot for full PSL coverage). Returns "" for empty
    input or IP literals (an IP-shaped "hostname" must never be logged
    as an operator domain).
    """
    host = (hostname or "").strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""  # IP literal: not a domain, log nothing
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _hmac_client_id(truncated_ip, secret):
    """HMAC-SHA256 of the truncated IP keyed by the per-deployment secret.

    A keyed HMAC (not a plain salted hash) so the client identifier
    cannot be reversed by enumerating the /24 input space.
    """
    return hmac.new(
        secret.encode(), truncated_ip.encode(), hashlib.sha256
    ).hexdigest()[:16]


_DNS_TIMEOUT = 5.0  # seconds; applied as a SCOPED socket timeout


def _verify_operator(ip):
    """Forward-confirmed reverse DNS.

    1. Reverse-lookup the source IP -> hostname.
    2. Forward-lookup the hostname -> address list.
    3. Confirm the original IP is in the forward results, compared as
       parsed addresses (not strings), so IPv6 textual variants cannot
       cause a false reject.

    Returns (verified: bool, operator_domain: str). The operator
    domain is the registrable domain (eTLD+1, public-suffix-aware) --
    never the full PTR hostname, which routinely embeds the client IP
    (e.g. "crawl-66-249-60-1.googlebot.com" -> "googlebot.com").
    Unverified clients yield (False, "").

    DNS uses a scoped timeout: the previous default is restored in a
    finally block (the old code called socket.setdefaulttimeout(5),
    mutating global process state). The lookups still block this
    single-threaded server while in flight -- acceptable for a
    low-traffic research harness; see SECURITY.md.
    """
    prev_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_DNS_TIMEOUT)
    try:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            return (False, "")
        try:
            _, _, addrs = socket.gethostbyname_ex(hostname)
        except Exception:
            return (False, "")
        if not any(_same_ip(ip, a) for a in addrs):
            return (False, "")
    finally:
        socket.setdefaulttimeout(prev_timeout)
    return (True, _registrable_domain(hostname))


class Handler(BaseHTTPRequestHandler):
    log_path = "requests.csv"
    secret = "change-me"

    def _log(self, path):
        ua = _csv_safe(_sanitize_ua(self.headers.get("User-Agent", "-")))
        safe_path = _csv_safe(_sanitize_path(path))
        ip = self.client_address[0]
        ident = _hmac_client_id(_truncate_ip(ip), self.secret)
        verified, operator = _verify_operator(ip)
        operator = _csv_safe(operator)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        new_file = not os.path.exists(self.log_path)
        with open(self.log_path, "a", newline="") as f:
            if new_file:
                # The log can re-identify /24 prefixes to anyone holding
                # the HMAC secret: restrict it to the owner on creation.
                try:
                    os.chmod(self.log_path, 0o600)
                except OSError:
                    pass
            w = csv.writer(f)
            if new_file:
                w.writerow(["timestamp_utc", "client_id", "operator",
                            "verified", "user_agent", "path"])
            w.writerow([ts, ident, operator if verified else "",
                        "yes" if verified else "no", ua, safe_path])

    def do_GET(self):
        path = urlparse(self.path).path
        self._log(path)
        if path == "/robots.txt":
            body = ROBOTS_TXT.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/sitemap.txt":
            body = ("\n".join(SITEMAP_PATHS) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/rsl-license.xml":
            # Linked RSL license document for /rsl.html (RSL 1.0 §4.6.1).
            body = RSL_LICENSE_XML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/rsl+xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in ("/", "/index.html"):
            links = "\n".join(
                f'<li><a href="{p}">{p}</a></li>' for p in SITEMAP_PATHS
            )
            body = f"""<!DOCTYPE html><html><head><title>Exposure telemetry corpus</title></head>
<body><h1>Test corpus</h1><ul>{links}</ul></body></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        spec = PAGES.get(path)
        if spec is None:
            self.send_response(404)
            self.end_headers()
            return
        body = page_html(spec, self.headers.get("Host")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in spec["headers"].items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # request logging goes to the CSV, not stderr


_DEFAULT_RETENTION_DAYS = 90


def _prune_old_rows(log_path, retention_days):
    """Enforce the retention policy: delete rows older than retention_days.

    Runs at startup, when no concurrent writers exist (single-threaded
    server). The file is rewritten atomically via os.replace. Rows with
    unparseable timestamps are KEPT -- never silently delete data whose
    age cannot be determined -- and counted in the returned warnings.

    Returns (kept, deleted, unparseable).
    """
    if not retention_days or retention_days <= 0:
        return (0, 0, 0)
    if not os.path.exists(log_path):
        return (0, 0, 0)
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=retention_days))
    header = None
    kept_rows = []
    deleted = 0
    unparseable = 0
    with open(log_path, newline="") as f:
        for row in csv.reader(f):
            if header is None:
                header = row
                continue
            if not row:
                continue
            try:
                ts = datetime.datetime.fromisoformat(row[0])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
            except (ValueError, IndexError):
                unparseable += 1
                kept_rows.append(row)
                continue
            if ts < cutoff:
                deleted += 1
            else:
                kept_rows.append(row)
    if deleted:
        tmp = log_path + ".prune-tmp"
        with open(tmp, "w", newline="") as f:
            w = csv.writer(f)
            if header is not None:
                w.writerow(header)
            w.writerows(kept_rows)
        os.replace(tmp, log_path)
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
    return (len(kept_rows), deleted, unparseable)


def main():
    ap = argparse.ArgumentParser(description="AI usage-preference exposure-telemetry server")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", default="requests.csv")
    ap.add_argument("--secret", default=None,
                    help="per-deployment HMAC secret for client-ID hashing. "
                         "May also be set via the AIPREF_HMAC_SECRET "
                         "environment variable (preferred: avoids exposing "
                         "the secret in the process list). If neither is "
                         "given, an ephemeral random secret is generated "
                         "and client IDs change on restart. Never publish it.")
    ap.add_argument("--retention-days", type=int, default=_DEFAULT_RETENTION_DAYS,
                    help="rows older than this many days are deleted at "
                         "startup (0 disables; default 90)")
    args = ap.parse_args()
    secret = args.secret or os.environ.get("AIPREF_HMAC_SECRET")
    if not secret:
        # The old default ("change-me") meant every careless deployment
        # shared one public HMAC key, making client IDs reversible by
        # /24 enumeration. An ephemeral secret is the safe default.
        secret = secrets.token_hex(32)
        print("WARNING: no --secret / AIPREF_HMAC_SECRET provided; generated "
              "an ephemeral secret. Client IDs will NOT be stable across "
              "restarts. Pass a persistent secret for stable IDs.",
              file=sys.stderr, flush=True)
    elif len(secret) < 16:
        print("WARNING: HMAC secret is shorter than 16 characters; use a "
              "long random value (e.g. `openssl rand -hex 32`).",
              file=sys.stderr, flush=True)
    Handler.log_path = args.log
    Handler.secret = secret
    kept, deleted, unparseable = _prune_old_rows(args.log, args.retention_days)
    if deleted or unparseable:
        print(f"Retention: kept {kept} rows, deleted {deleted} rows older "
              f"than {args.retention_days} days"
              + (f"; {unparseable} rows with unparseable timestamps kept"
                 if unparseable else ""),
              flush=True)
    srv = HTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Serving {len(PAGES)} test pages on port {args.port}; logging to {args.log}", flush=True)
    print("Pages:", ", ".join(SITEMAP_PATHS), flush=True)
    print("Privacy: client IPs truncated (/24, /48, canonical) and "
          "HMAC-hashed with a per-deployment secret; User-Agents capped at "
          f"{_MAX_UA_LEN} chars and control-stripped; CSV fields neutralized "
          "against spreadsheet formula injection; only forward-confirmed "
          "registrable operator domains logged (never full PTR hostnames "
          "or raw IPs); log file created mode 0600; "
          f"rows older than {args.retention_days} days deleted at startup. "
          "See SECURITY.md.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
