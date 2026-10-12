#!/usr/bin/env python3
"""Analyze exposure-telemetry request logs.

Reads the CSV written by server.py and reports, per test page and per
(verified) crawler identity:
  - first retrieval time, retrieval count
  - whether the client retrieved pages carrying preference directives

Identity: established by forward-confirmed reverse DNS (reverse lookup,
then forward lookup confirming the source IP), NEVER by User-Agent
alone (user-agents are trivially spoofable). A client is attributed to
a crawler family only when its operator domain is verified and matches
a known pattern; otherwise it is reported as unverified. The log
contains only verified operator domains (e.g. "googlebot.com"), never
full PTR hostnames or raw IPs.

Evidence ladder (paper §6.4): this tool reports level 1 (retrieval)
and level 2 (verified crawler retrieval). It says nothing about
levels 3-5 (claimed support, observed processing effect, usage
compliance).

Usage:
    python3 analyze.py [--log requests.csv]

This is descriptive, not inferential: it reports which (verified)
crawlers retrieved the signal and when. It makes NO compliance
determinations — retrieval logs cannot establish compliance with a
usage preference (see paper §1, §6.3). Absence of a retrieval proves
nothing (the crawler may not have discovered the page yet).
"""
import argparse
import csv
import re
from collections import defaultdict

# Verified operator domains -> family. A client is attributed only when
# server.py forward-confirmed the domain; UA is shown for context but
# never used for identity.
#
# server.py logs REGISTRABLE domains (eTLD+1, public-suffix-aware), so
# patterns here must match registrable domains, not full PTR hostnames:
# e.g. "crawl-1-2-3.googlebot.com" is logged as "googlebot.com", and
# "x.applebot.apple.com" is logged as "apple.com".
OPERATOR_PATTERNS = [
    (re.compile(r"(^|\.)openai\.com$"), "OpenAI"),
    (re.compile(r"(^|\.)googlebot\.com$|(^|\.)google\.com$"), "Google"),
    (re.compile(r"(^|\.)apple\.com$"), "Apple"),
    (re.compile(r"(^|\.)(amazonaws\.com|amazon\.com)$"), "Amazon"),
    (re.compile(r"(^|\.)commoncrawl\.org$"), "CommonCrawl"),
    (re.compile(r"(^|\.)perplexity\.ai$"), "Perplexity"),
    (re.compile(r"(^|\.)anthropic\.com$"), "Anthropic"),
    (re.compile(r"(^|\.)facebook\.com$"), "Meta"),
    (re.compile(r"(^|\.)bing\.com$|(^|\.)msn\.com$"), "Microsoft/Bing"),
    (re.compile(r"(^|\.)yandex\.[a-z.]+$"), "Yandex"),
    (re.compile(r"(^|\.)baidu\.com$"), "Baidu"),
    (re.compile(r"(^|\.)duckduckgo\.com$"), "DuckDuckGo"),
]

SIGNAL_PAGES = {
    "/content-usage-deny-training.html",
    "/content-usage-deny-all.html",
    "/content-usage-duplicate-keys.html",
    "/content-usage-nontoken.html",
    "/content-usage-uppercase-key.html",
    "/content-usage-body-tag.html",
    "/header-content-usage.html",
    "/robots-content-usage.html",
    "/tdmrep.html",
    "/rsl.html",
    "/robots-noarchive.html",
    "/robots-nocache.html",
    "/named-gptbot-block.html",
}


def _safe_ua_snippet(ua):
    """Short UA snippet safe to print: control chars neutralized."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", (ua or "")[:40])


def identify(operator, verified_flag, ua):
    """Return (family, verified: bool)."""
    operator = (operator or "").lower().rstrip(".")
    verified = verified_flag == "yes" and bool(operator)
    if verified:
        for pat, fam in OPERATOR_PATTERNS:
            if pat.search(operator):
                return fam, True
        return f"verified-unknown ({operator})", True
    return f"unverified ({_safe_ua_snippet(ua)})", False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="requests.csv")
    args = ap.parse_args()

    hits = defaultdict(list)  # (family, verified, path) -> [timestamps]
    with open(args.log, newline="") as f:
        for row in csv.DictReader(f):
            # Back-compat: older logs used "reverse_dns"; new logs use
            # "operator"/"verified".
            operator = row.get("operator", "") or row.get("reverse_dns", "")
            verified_flag = row.get("verified", "yes" if row.get("reverse_dns") else "no")
            fam, verified = identify(operator, verified_flag,
                                     row.get("user_agent", ""))
            hits[(fam, verified, row["path"])].append(row["timestamp_utc"])

    fams = sorted({(fam, v) for fam, v, _ in hits})
    print(f"Client identities observed: {len(fams)} "
          f"({sum(1 for _, v in fams if v)} forward-confirmed)")
    print()
    print(f"{'family':<28} {'verif':<6} {'page':<36} {'n':<5} {'first_seen_utc'}")
    print("-" * 110)
    for fam, verified in fams:
        for path in sorted({p for (f, v, p) in hits if (f, v) == (fam, verified)}):
            ts = sorted(hits[(fam, verified, path)])
            flag = "  <-- SIGNAL-TAGGED" if path in SIGNAL_PAGES else ""
            print(f"{fam:<28} {'yes' if verified else 'no':<6} "
                  f"{path:<36} {len(ts):<5} {ts[0]}{flag}")
    print()
    print("INTERPRETATION (evidence ladder, paper §6.4):")
    print("- Level 1 (retrieval): a client requested a signal-tagged page.")
    print("- Level 2 (verified crawler): forward-confirmed reverse DNS")
    print("  establishes the operator; User-Agent is never used for identity.")
    print("- This report covers levels 1-2 ONLY.")
    print("- A retrieval does NOT demonstrate (non-)compliance: the crawler")
    print("  must retrieve the page to read its tags, and may honor the")
    print("  preference invisibly thereafter.")
    print("- Absence of a retrieval proves nothing (page may be undiscovered).")
    print("- Unverified clients are never attributed to an operator.")


if __name__ == "__main__":
    main()
