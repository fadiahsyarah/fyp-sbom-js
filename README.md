# fyp-sbom-js - SBOM vulnerability pipeline (JavaScript / Node.js)

C300 FYP: AI-Enhanced Software Vulnerability Management with Software Bill of Materials.
Scans 3 JavaScript repos, makes a CycloneDX SBOM for each, finds their known vulnerabilities,
and ranks them by how likely they are to be exploited (CISA KEV + EPSS) instead of by severity alone.

## How to run

    node step1.js    # download each repo at its frozen commit -> SBOM (Syft) -> vulnerabilities (Grype)
    node step2.js    # add EPSS + CISA KEV, set priority P1-P5, rank -> CycloneDX

## Output (one folder per repo, so each repo's owners can fix their own repo)

| File | Made by | What it is |
|---|---|---|
| `output/<repo>/sbom.cdx.json` | Syft (step1.js) | The SBOM: every component (library + version) in the repo, CycloneDX |
| `output/<repo>/grype.json` | Grype (step1.js) | The known vulnerabilities Grype matched to the SBOM |
| `output/<repo>/ranked.cdx.json` | step2.js | The components + vulnerabilities, ranked, with EPSS, KEV and priority, CycloneDX 1.7 |

## Repos scanned (`testset.json`)
Juice Shop, NodeGoat and DVNA - each forked to my account and pinned to one exact commit,
so the scan always uses the same code.

## Frozen inputs (so the results never change by themselves)
- **Code:** each repo pinned to an exact commit (`testset.json`); npm lock files saved in `locks/`
- **Tools:** Syft 1.55.0, Grype 0.121.0
- **Grype vulnerability database:** built 2026-10-22T18:51:21Z, auto-update turned off in `~/.grype.yaml`
- **KEV + EPSS data:** `kev-epss-snapshot/2026-10-29/` (KEV catalog 2026.10.28, EPSS score date 2026-10-28).
  `step2.js` checks the SHA-256 fingerprint of both files on every run and stops if either has changed.

## Priority and ranking
P1 - in CISA KEV (being exploited) / P2 - EPSS >= 10% / P3 - EPSS 1-10% / P4 - EPSS < 1% / P5 - no EPSS score.
Within each repo: in KEV first, then higher EPSS score, then higher EPSS percentile, then higher severity.
In `ranked.cdx.json` each vulnerability carries these as properties: `fyp:exploitability_rank`, `fyp:priority`,
`fyp:epss:score`, `fyp:epss:percentile`, `fyp:epss:cve`, `fyp:kev:in_kev`, `fyp:kev:date_added`,
`fyp:kev:due_date`, `fyp:kev:ransomware_use`, `fyp:fix_state`.
