# Exposure-telemetry harness

Serves a corpus of test pages carrying AI usage-preference directives and
logs every client retrieval. Used for the *retrieval-observation* half of
the paper — which (verified) crawlers retrieved pages carrying the
`<meta name="content-usage">` signal, and when.

**Explicit non-claim:** this harness does not and cannot measure
compliance. Fetch logs cannot establish compliance with a usage
preference: a crawler must fetch a page to read its meta tags, and may
then honor the preference invisibly or violate it invisibly (paper §1,
§6.3). Crawler identity is established by forward-confirmed reverse DNS,
never by User-Agent alone (paper §6.4, evidence ladder rungs 1–2).

## Corpus

| Path | Directive | Purpose |
|---|---|---|
| `/control.html` | none | Control — every crawler should retrieve |
| `/content-usage-deny-training.html` | `train-ai=n, ai-use=n, search=y` | Proposed binding: preference to disallow training/AI-use, allow search |
| `/content-usage-deny-all.html` | `train-ai=n, ai-use=n, search=n` | Proposed binding: preference to disallow all AI uses |
| `/content-usage-duplicate-keys.html` | `train-ai=n, train-ai=y, search=y` | Edge case: last-wins → `train-ai=y` (RFC 9651) |
| `/content-usage-nontoken.html` | `train-ai=maybe, search=y` | Edge case: non-token → unknown (AIPREF §6.5) |
| `/content-usage-uppercase-key.html` | `Train-AI=n, search=y` | Edge case: invalid dictionary → all unknown |
| `/content-usage-body-tag.html` | tag in `<body>` | Edge case: must be ignored per processing model |
| `/header-content-usage.html` | `Content-Usage: train-ai=n, ...` | AIPREF HTTP header carrier |
| `/robots-content-usage.html` | (see `/robots.txt`) | AIPREF robots.txt Content-Usage rule |
| `/tdmrep.html` | `<meta name="tdm-reservation" content="1">` | Coexistence: TDM Reservation Protocol |
| `/rsl.html` | RSL `prohibits` JSON-LD | Coexistence: RSL (prohibition form) |
| `/robots-noarchive.html` | `<meta name="robots" content="noarchive">` | Bing-style: no AI training |
| `/robots-nocache.html` | `<meta name="robots" content="nocache">` | Bing-style: limited Copilot use |
| `/named-gptbot-block.html` | `<meta name="GPTBot" content="noindex, nofollow">` | Per-bot block (contrast case) |

Each page embeds a unique canary string (`aiprefbinding-*`) identifying
it as part of this research corpus. `/robots.txt` allows all crawlers and
carries a group-level `Content-Usage: train-ai=n, ai-use=n, search=y`
rule (we want to observe meta-tag behavior, not robots.txt blocking).
`/sitemap.txt` lists the corpus.

## Parser conformance suite

`parser.py` is the dependency-free reference parser implementing the
paper's §3.2 processing model: strict RFC 9651 dictionary parsing,
AIPREF §6.5 value mapping, AIPREF §5.1 multi-statement combination, and
three-carrier evaluation (robots.txt → HTTP header → HTML meta).

```bash
python3 parser.py --self-test   # 71/71 must pass
```

`html5lib_reference.py` is a second, independent implementation of the
HTML extraction layer using html5lib (a WHATWG-conforming tree builder).
It implements the normative §3.2 tree model directly and is used for
differential validation:

```bash
pip install html5lib
python3 html5lib_reference.py --self-test       # 10/10 malformed vectors
python3 html5lib_reference.py --differential    # 34/34 agree, 0 divergences
```

## Deploy

```bash
cd compliance-test
python3 server.py --port 8000 --log requests.csv --secret "$(openssl rand -hex 16)"
```

Requirements: Python 3.8+, stdlib only. Expose the port publicly (VPS,
tunnel, or spare host). The server binds `0.0.0.0`.

**Privacy:** client IPs are truncated (/24 IPv4, /48 IPv6) and HMAC-hashed
with a per-deployment secret; raw IPs are never persisted. Operator
identity uses forward-confirmed reverse DNS; only the verified operator
domain is logged, never the full PTR hostname. Pass a random `--secret`
per deployment and never publish it. Suggested retention: 90 days (see
paper §6.5).

To attract crawlers:
1. Submit the sitemap URL to Bing/Google Search Console.
2. Link the corpus index from an already-indexed page.
3. Or simply wait — AI crawlers discover new hosts via certificate-transparency
   logs and link graphs within days.

## Observe

Crawlers operate on their own schedules. Plan for **4+ weeks** of logging
before drawing conclusions; directive-change response (edit a page's tag,
watch for re-retrieval) needs a second window after the change.

```bash
python3 analyze.py --log requests.csv
```

The analyzer attributes clients by **forward-confirmed reverse DNS
only** — never by User-Agent alone — and reports which verified crawlers
retrieved the signal and when (evidence-ladder rungs 1–2). Interpretation
rules (see paper §6.3–6.4):
- A retrieval of a signal-tagged page = the client *retrieved* the signal.
  Nothing more. It does not demonstrate non-compliance.
- Unverified clients are never attributed to an operator.
- Absence of a retrieval proves nothing (page may be undiscovered).

## Files

- `server.py` — test corpus + retrieval logger (CSV: timestamp, HMAC
  client ID, verified operator domain, verification flag, UA, path)
- `parser.py` — reference parser + 71-vector test suite
  (`--self-test`); also implements `evaluate()` for three-carrier
  assessment
- `html5lib_reference.py` — second implementation of HTML extraction
  via html5lib (WHATWG tree builder); differential runner
  (`--differential`) and malformed-document vectors (`--self-test`)
- `analyze.py` — retrieval report grouped by forward-confirmed operator
  (descriptive only)
- `httpwg-corpus-check.py` — RFC 9651 external-corpus validation
- `README.md` — this file
