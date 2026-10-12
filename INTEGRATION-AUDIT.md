# AIPREF Testbed — Integration Audit

**Date:** 2026-10-12
**Scope:** Post-fix integration check after five parallel agents applied changes on 2026-10-11.
**Status:** AUDIT ONLY — no push, no tags, no deploy.

---

## 1. Git State

**Branch:** `main`, 1 commit ahead of `origin/main` (`a0877fc` — artifact files: LICENSE, CITATION.cff, CI workflow, MAINTENANCE.md).

**Uncommitted changes (4 files, +877/−108):**

| File | Change |
|---|---|
| `parser.py` | +504/−~80 — RFC 9651 fixes (quoted-string escapes, Base64 validation, integer/decimal limits, date/dispstr/inner-list) + RFC 9309 fixes (wildcard/`$`, percent-encoding, octet specificity, group selection) |
| `server.py` | +438/−~20 — Normative RSL XML (`_rsl_head`, `/rsl-license.xml`), privacy hardening (UA sanitization, IP truncation, CSV injection defense) |
| `analyze.py` | +20/−~5 — Registrable-domain operator patterns, UA snippet sanitization |
| `README.md` | +23/−~3 — RSL normative XML docs, privacy section rewrite, SECURITY.md reference |

**Untracked files:** `RFC9651-FIXES.md`, `RFC9309-FIXES.md`, `SECURITY.md`, `__pycache__/` (build artifact, should be gitignored).

**Overlapping-edit assessment:** The five agents edited different concerns in shared files, but the diffs are coherent — no merge conflicts, no duplicated functions, no contradictory logic. `parser.py` received both RFC 9651 and RFC 9309 changes; they touch different functions (`_parse_*` vs `_pattern_to_regex`/`robots_*`) with no overlap. `server.py` received RSL + privacy changes in different sections. **No conflicts found.**

---

## 2. Import Check

| Module | Result |
|---|---|
| `server.py` | ✅ Imports cleanly |
| `parser.py` | ✅ Imports cleanly |
| `analyze.py` | ✅ Imports cleanly |
| `html5lib_reference.py` | ✅ Imports cleanly (after `pip install html5lib`; this is a CI dependency, not a code issue) |

**`_rsl_head` NameError:** FIXED. Function defined at `server.py:77`, referenced at line 188 (after definition). No NameError on import or startup.

---

## 3. Test Suite Results

No standalone pytest files — tests run via `--self-test` flags (matching CI workflow).

| Suite | Command | Result |
|---|---|---|
| Parser conformance | `python3 parser.py --self-test` | ✅ **117/117 pass** |
| Reference oracle malformed | `python3 html5lib_reference.py --self-test` | ✅ **10/10 pass** |
| Differential validation | `python3 html5lib_reference.py --differential` | ✅ **34/34 agree, 0 divergences** |
| Server smoke test | `timeout 5 python3 server.py --port 18080` | ✅ Starts, serves 14 pages, exits cleanly |

**Total: 161/161 checks pass.** (117 parser + 10 oracle + 34 differential)

Note: The parser self-test now reports 117 vectors (was 71 in CI config + 26 new RFC 9651 + 20 new RFC 9309). The CI workflow file still says "71 vectors" in its step name — cosmetic, should be updated.

---

## 4. analyze.py End-to-End

**Test procedure:**
1. Started `server.py` on port 18081
2. Made 2 curl requests (control page + signal-tagged page)
3. Ran `python3 analyze.py --log requests.csv`

**Result:** ✅ **Works.** Produced correct output:
- Identified 1 client (forward-confirmed via localhost)
- Correctly flagged `/content-usage-deny-training.html` as SIGNAL-TAGGED
- Displayed evidence-ladder interpretation (levels 1–2 only)
- No errors, no tracebacks

**This was the first confirmed end-to-end run of analyze.py.**

---

## 5. Reconstructed README Review

**File:** `~/workspace/babylonia-paper/measurements/compliance-test/README.md`
**Status:** Complete and coherent. No truncation, no placeholder text, no obviously wrong paths.

**Issues found:**
1. **Stale test count:** Says `python3 parser.py --self-test   # 71/71 must pass` — actual is now 117/117. Needs update.
2. **References missing file:** Mentions `httpwg-corpus-check.py` twice (parser section + files list), but the file doesn't exist.
3. **Paper section refs:** Cites "paper §6.3" and "paper §6.4" — consistent with V8 structure, but should be verified against the final paper.

Otherwise the README is well-structured: corpus table (15 pages), parser conformance docs, deploy instructions, privacy notes, and interpretation rules all present and accurate.

---

## 6. Missing File Check

**`httpwg-corpus-check.py`:** ❌ **Confirmed missing.** Referenced in:
- `README.md` line 65 ("validates the RFC 9651 dictionary parser against the HTTPWG `structured-field-tests` external corpus")
- `README.md` line 128 (files list)

This is a known gap from the original implementation — the file was never created. The README should either have the file created or the references removed.

---

## 7. Blocking vs Non-Blocking Issues

### Blocking (must fix before release)

1. **`httpwg-corpus-check.py` missing** — README references a non-existent file. Either create it or remove the references. A broken file reference in the README is a red flag for reviewers.

2. **Uncommitted changes** — 4 modified files + 3 new docs are not committed. Need a clean commit before push. (Note: pushing requires Amit's authorization + GitHub app per-file approval.)

3. **`__pycache__/` untracked** — Should be added to `.gitignore` to avoid accidental commit of build artifacts.

### Non-blocking (should fix, not urgent)

4. **CI workflow says "71 vectors"** — Cosmetic; actual is 117. Update the step name in `.github/workflows/test.yml`.

5. **Reconstructed README stale test count** — Says 71/71, should say 117/117.

6. **Reconstructed README paper refs** — Verify §6.3/§6.4 match the final paper structure.

7. **`.github/workflows/test.yml` can't be pushed via API** — Known limitation: the GitHub app lacks workflows permission. Amit must paste it manually via web UI.

---

## 8. Summary

- **Git:** 4 files modified, 3 docs added, no conflicts, 1 commit ahead of origin.
- **Imports:** All 4 modules import cleanly. `_rsl_head` NameError is fixed.
- **Tests:** 161/161 pass (117 parser + 10 oracle + 34 differential + server smoke).
- **analyze.py:** First confirmed end-to-end run — works correctly.
- **Top blocking issues:**
  1. `httpwg-corpus-check.py` referenced but missing
  2. Uncommitted changes need a clean commit
  3. `__pycache__/` needs gitignore entry
