# KEV + EPSS snapshot 2026-10-29
Frozen copy of the CISA KEV catalog and the EPSS scores, used by step2.js.
- kev.json: CISA KEV catalog 2026.10.28 (1,762 entries)
- epss_scores.csv.gz: EPSS scores for 396,966 CVEs, score date 2026-10-28, model v2026.06.15
- manifest.json: where each file came from and its SHA-256 fingerprint
step2.js checks both SHA-256 fingerprints on every run and stops if a file has changed.
