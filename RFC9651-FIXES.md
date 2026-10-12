# RFC 9651 Parser Fixes — Summary

**Date:** 2026-10-11
**File:** `~/workspace/aipref-testbed/parser.py`
**Tests:** 97/97 passing (71 original + 26 new)

## Fixes Applied

### 1. Quoted-string escapes (RFC 9651 §4.2.6)
**Problem:** Parser accepted any `\X` escape sequence.
**Fix:** Only `\"` and `\\` are valid escapes. Any other `\` followed by a character now fails parsing. Also removed bare backslash from the allowed unescaped character set.
**Tests:** 5 new vectors (valid `\"`, valid `\\`, invalid `\n`, invalid `\t`, bare backslash).

### 2. Byte sequence Base64 validation (RFC 4648)
**Problem:** Parser accepted any content between `:` delimiters without validating Base64.
**Fix:** Validates RFC 4648 Base64 alphabet (`A-Za-z0-9+/` with `=` padding), requires length multiple of 4, validates padding structure (max 2 `=` at end only).
**Tests:** 5 new vectors (valid padded, unpadded rejected, invalid chars, bad padding, wrong length).

### 3. Integer/decimal range limits (RFC 9651 §4.2.4)
**Problem:** No range checking; accepted arbitrarily large integers.
**Fix:** Enforces ±999,999,999,999,999 (max 15 digits). Applies to both integer and decimal integer parts. Leading zeros handled correctly.
**Tests:** 7 new vectors (max/min valid, too large/small, decimal precision, decimal with large integer part).

### 4. Negative dates rejected (RFC 9651 §3.3.7)
**Problem:** Dead code (`if ch == "-": pass`) — negative dates not explicitly handled.
**Fix:** Explicitly reject `@-` prefix. Dates are non-negative per spec.
**Tests:** 2 new vectors (negative rejected, valid date accepted).

### 5. Display string parsing (RFC 9651 §4.2.8)
**Problem:** Simplified implementation didn't handle pct-encoding or validate UTF-8.
**Fix:** Full implementation with:
- `\"` and `\\` escapes (same as strings)
- `%XX` pct-decoding for bytes
- UTF-8 validation of decoded output
- Rejection of bare CTLs, DEL, and non-ASCII (must use pct-encoding)
- Returns decoded string (was returning `None`)
**Tests:** 5 new vectors (simple ASCII, pct-encoded "Hello", escaped DQUOTE, invalid pct-encoding, bare non-ASCII).

### 6. Nested inner lists rejected (RFC 9651 §4.2.1.2)
**Problem:** Parser recursively accepted `((a b))` — nested inner lists.
**Fix:** Return `None` (parse failure) when `(` encountered inside inner list.
**Tests:** 2 new vectors (nested rejected, simple inner list accepted).

### 7. Base32 decoding utility (HTTPWG JSON interop)
**Problem:** No Base32 support for HTTPWG JSON `binary` type mappings.
**Fix:** Added `decode_base32()` function (not used by RFC 9651 parser itself, which uses Base64). Handles RFC 4648 Base32 with case normalization, whitespace stripping, and padding validation. Documented as interop helper.
**Tests:** Manual verification (not in VECTORS as it's a utility, not parser behavior).

## Files Changed
- `~/workspace/aipref-testbed/parser.py` — all fixes + 26 new test vectors
- `~/workspace/aipref-testbed/parser.py.bak` — backup of original (can be deleted)

## Notes
- All 71 original tests still pass (no regressions)
- 26 new test vectors added, all passing
- The `decode_base32()` function is a standalone utility, not integrated into the dictionary parser (RFC 9651 uses Base64 for byte sequences)
- Display string return value changed from `None` to decoded string — this is a behavior change but more correct per spec
