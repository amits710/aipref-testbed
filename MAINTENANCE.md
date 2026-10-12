# Maintenance and Versioning

## Versioning policy

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — incompatible changes to the processing model, parser API,
  corpus layout, or CSV log schema.
- **MINOR** — new corpus pages, new conformance vectors, new analyzer
  output columns, backwards-compatible features.
- **PATCH** — bug fixes with no behavioral change to the normative model.

The `version` field in `CITATION.cff` is updated on every release.

## Release process

1. All conformance suites pass on every supported Python version:
   `python3 parser.py --self-test` (71/71),
   `python3 html5lib_reference.py --self-test` (10/10),
   `python3 html5lib_reference.py --differential` (34/34, 0 divergences).
2. Update `CITATION.cff` `version` and `date-released`.
3. Tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"` and push the tag.
4. Create a GitHub Release from the tag; attach the Zenodo DOI once minted
   (see below).

## Immutable archive / DOI (Zenodo)

For the camera-ready paper submission, the exact code revision used for all
reported numbers must be immutably archived with a DOI:

1. Tag the release (`v1.0.0`) as above.
2. Ensure the [GitHub–Zenodo integration](https://zenodo.org/account/settings/github/)
   is enabled for `amits710/aipref-testbed`.
3. Create the GitHub Release — Zenodo automatically archives the tag
   snapshot and mints a DOI.
4. Add the DOI to the paper's artifact appendix and to this file.

Do **not** cite a moving `main` branch in the paper; cite the Zenodo DOI.

## External outputs

The project produces the following external outputs at runtime:

| Output | Producer | Format | Contents |
|---|---|---|---|
| `requests.csv` | `server.py --log` | CSV | Retrieval log: timestamp, HMAC client ID, verified operator domain, verification flag, User-Agent, path |
| Analysis report | `analyze.py --log` | stdout text | Retrieval report grouped by forward-confirmed reverse-DNS operator (descriptive only) |
| Corpus pages | `server.py` | HTML | 14 test corpus pages (see README corpus table), `/robots.txt`, `/sitemap.txt` |

No raw client IPs are ever persisted (truncated to /24 IPv4, /48 IPv6 and
HMAC-hashed with a per-deployment secret). Suggested log retention: 90 days.

## Maintenance status

Active research artifact. Issues and pull requests are reviewed on a
best-effort basis. Security issues: please report privately via GitHub
Security Advisories rather than public issues.
