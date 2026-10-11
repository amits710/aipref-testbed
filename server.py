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
and then HMAC-hashed with a per-deployment secret before logging; raw
IPs are never persisted. Operator identity is established by
forward-confirmed reverse DNS (never User-Agent alone); only the
verified operator domain (e.g. "googlebot.com") is logged -- never the
full PTR hostname, which routinely embeds the client IP. Retention:
90 days. See --salt/--secret and --truncate/--hash-ips.

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
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

CANARY_PREFIX = "aiprefbinding"

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
    "/rsl.html": {
        "title": "RSL prohibition",
        "head": '<script type="application/ld+json">{"@context": "https://rslstandard.org/rsl", "@type": "License", "prohibits": {"type": "usage", "use": "ai-train"}}</script>',
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


def page_html(spec):
    body_extra = spec.get("body_extra", "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{spec['title']}</title>
{spec['head']}
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


def _truncate_ip(ip):
    """Minimize: /24 for IPv4, /48 for IPv6."""
    if ":" in ip:  # IPv6
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::/48"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip


def _hmac_client_id(truncated_ip, secret):
    """HMAC-SHA256 of the truncated IP keyed by the per-deployment secret.

    A keyed HMAC (not a plain salted hash) so the client identifier
    cannot be reversed by enumerating the /24 input space.
    """
    return hmac.new(
        secret.encode(), truncated_ip.encode(), hashlib.sha256
    ).hexdigest()[:16]


def _verify_operator(ip):
    """Forward-confirmed reverse DNS.

    1. Reverse-lookup the source IP -> hostname.
    2. Forward-lookup the hostname -> address list.
    3. Confirm the original IP is in the forward results.

    Returns (verified: bool, operator_domain: str). The operator domain
    is the last two DNS labels (e.g. "googlebot.com") -- never the full
    PTR hostname, which routinely embeds the client IP
    (e.g. "crawl-66-249-60-1.googlebot.com"). Unverified clients yield
    (False, "").
    """
    try:
        socket.setdefaulttimeout(5)
        hostname = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except Exception:
        return (False, "")
    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
    except Exception:
        return (False, "")
    # Normalize for comparison (IPv6 forms may vary textually).
    if ip not in addrs:
        return (False, "")
    labels = hostname.split(".")
    operator = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    return (True, operator)


class Handler(BaseHTTPRequestHandler):
    log_path = "requests.csv"
    secret = "change-me"

    def _log(self, path):
        ua = self.headers.get("User-Agent", "-")
        ip = self.client_address[0]
        ident = _hmac_client_id(_truncate_ip(ip), self.secret)
        verified, operator = _verify_operator(ip)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        exists = os.path.exists(self.log_path)
        with open(self.log_path, "a", newline="") as f:
            w = csv.writer(f)
            if not exists:
                w.writerow(["timestamp_utc", "client_id", "operator",
                            "verified", "user_agent", "path"])
            w.writerow([ts, ident, operator if verified else "",
                        "yes" if verified else "no", ua, path])

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
        body = page_html(spec).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in spec["headers"].items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # request logging goes to the CSV, not stderr


def main():
    ap = argparse.ArgumentParser(description="AI usage-preference exposure-telemetry server")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", default="requests.csv")
    ap.add_argument("--secret", default="change-me",
                    help="per-deployment HMAC secret for client-ID hashing "
                         "(pass a random value; never publish it)")
    args = ap.parse_args()
    Handler.log_path = args.log
    Handler.secret = args.secret
    srv = HTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Serving {len(PAGES)} test pages on port {args.port}; logging to {args.log}", flush=True)
    print("Pages:", ", ".join(SITEMAP_PATHS), flush=True)
    print("Privacy: client IPs truncated (/24, /48) and HMAC-hashed with a "
          "per-deployment secret; only forward-confirmed operator domains "
          "logged (never full PTR hostnames or raw IPs). "
          "Suggested retention: 90 days.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
