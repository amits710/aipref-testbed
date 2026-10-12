# Security: AIPREF exposure-telemetry deployment

This document covers access control, secret lifecycle, data retention,
and incident response for the `server.py` exposure-telemetry harness.
Read it before deploying on a public host.

## What is logged (data minimization)

Each request appends one CSV row:

| Column | Content | Privacy treatment |
|---|---|---|
| `timestamp_utc` | Request time | — |
| `client_id` | HMAC-SHA256 (truncated to 64 bits) of the truncated client prefix | Keyed by the per-deployment secret; see below |
| `operator` | Verified registrable operator domain (e.g. `googlebot.com`) | Only after forward-confirmed reverse DNS; never the full PTR hostname (which routinely embeds the client IP) |
| `verified` | `yes`/`no` | — |
| `user_agent` | Client User-Agent | Capped at 512 chars, control characters stripped, spreadsheet-formula neutralized |
| `path` | Request path | Capped at 2048 chars, control characters stripped, spreadsheet-formula neutralized |

**Never logged:** raw client IPs, full PTR hostnames, request bodies,
query-string values beyond the path.

**Residual re-identification risk:** anyone holding both the log and
the HMAC secret can re-derive which /24 (IPv4) or /48 (IPv6) prefix
each `client_id` corresponds to (by enumerating the prefix space).
Treat the log as sensitive and the secret as a credential.

## Access control (deployment checklist)

- [ ] Run the server as an unprivileged user (never root).
- [ ] SSH: key authentication only; disable password auth.
- [ ] Host firewall: allow inbound only on the telemetry port (and SSH
      from your IPs); deny everything else.
- [ ] The log file is created mode `0600` (owner-only). Do not loosen
      it. If a log shipper needs access, run it as the same user.
- [ ] Do not publish the HMAC secret: not in the repo, not in shell
      history (prefer the `AIPREF_HMAC_SECRET` env var over `--secret`
      on the command line, since argv is visible in `ps`), not in
      screenshots or docs.
- [ ] Keep the host patched; this harness is stdlib-only Python with no
      dependencies to audit, but the OS and SSH still need updates.

## HMAC secret lifecycle

1. **Generate** per deployment: `openssl rand -hex 32`.
2. **Store**: environment variable `AIPREF_HMAC_SECRET` (preferred) or
   `--secret` flag. Never commit to git.
3. **Default behavior**: if no secret is provided, the server generates
   an ephemeral random secret at startup and warns on stderr. Client
   IDs are then **not stable across restarts** — this is the safe
   default (the old `"change-me"` default meant every careless
   deployment shared one public key).
4. **Rotate** by restarting with a new secret. Rotation is
   privacy-positive: old `client_id` values become unlinkable to new
   ones, since the HMAC key changed.
5. **Weak secrets** (< 16 chars) trigger a stderr warning; use long
   random values.

## Retention and deletion (90-day policy)

- Default `--retention-days 90`: at startup, rows older than 90 days
  are deleted (atomic rewrite). Pass `--retention-days 0` to disable.
- Rows with unparseable timestamps are **kept** (never silently delete
  data whose age can't be determined) and reported at startup.
- **Manual purge** (e.g. after an incident, or to honor a deletion
  request): stop the server, delete or truncate the CSV, restart.
  ```bash
  # delete everything older than 30 days with a one-liner, or:
  : > requests.csv   # wipe the whole log
  ```
- The server does not replicate the log anywhere; deletion is complete
  once the file (and your backups, if any) are gone. **Do not back up
  the log to unencrypted storage.**

## Incident response

**HMAC secret compromised** (leaked in a log, screenshot, repo, chat):
1. Generate a new secret.
2. Restart the server with the new secret (old client IDs become
   unlinkable — this is the desired outcome).
3. Assess what the holder could do with the old log + old secret:
   re-derive /24 prefixes per client_id. If the log was also exposed,
   treat as a data exposure (next item).
4. Scrub the secret from wherever it leaked (rotate, force-push a
   cleaned history if committed, revoke pastes).

**Log file exposed** (downloaded, misconfigured permissions, backup leak):
1. Restrict access immediately; delete exposed copies you control.
2. Rotate the HMAC secret (limits future linkability; does not undo
   the exposure of already-logged prefixes).
3. Assess: the log contains truncated prefixes (not full IPs) plus
   User-Agents and timestamps. Determine whether any rows need
   individual notification under applicable law (this is a research
   harness, not legal advice — consult counsel if unsure).
4. Document the incident: what was exposed, for how long, to whom,
   and what was done.

**Host compromised**:
1. Take the host offline; preserve the log for forensics if needed,
   then wipe per the retention policy.
2. Rotate the HMAC secret and any SSH/API credentials on that host.
3. Rebuild from a clean image; do not reuse the old secret.

**Abuse of the endpoint** (someone hammering the server):
- The parser has input size caps; the server caps logged field
  lengths. For sustained abuse, block at the firewall and consider
  putting the harness behind a reverse proxy with rate limiting.

## Known limitations (not vulnerabilities, but know them)

- **DNS verification is heuristic.** Forward-confirmed reverse DNS
  resists casual spoofing but a determined adversary controlling
  reverse DNS for their own netblock can mint a plausible PTR.
  Identity here is "verified operator domain", not cryptographic proof.
- **Single-threaded server.** Each request does up to two blocking DNS
  lookups (scoped 5 s timeout each). A slow DNS server stalls all
  requests briefly. Fine for low-traffic telemetry; not for production.
- **Public-suffix snapshot is bundled, not live.** `_registrable_domain`
  uses a built-in subset of the Mozilla PSL; unknown two-level
  suffixes fall back to last-two-labels. Extend the set if operator
  PTRs under other suffixes appear.
- **IPv6 /48 is coarse on some networks.** A /48 can be a single
  subscriber on some ISPs. This is the documented minimization
  tradeoff; tighten only with a clear research need and updated docs.
- **Request-line limits are stdlib defaults.** Enormous request lines
  are rejected by `http.server`'s own 64 KiB header cap; logged fields
  are additionally truncated.

## Reporting

Security issues in this harness: open an issue or contact the
maintainer directly. Do not file public issues with exploit details
before a fix is available.
