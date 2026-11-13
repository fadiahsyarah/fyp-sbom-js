# fyp-sbom-js - SBOM vulnerability pipeline (JavaScript / Node.js)

![Verify signatures](https://github.com/fadiahsyarah/fyp-sbom-js/actions/workflows/verify.yml/badge.svg)

C300 FYP: AI-Enhanced Software Vulnerability Management with Software Bill of Materials.
Scans 3 JavaScript repos, makes a CycloneDX SBOM for each, finds their known vulnerabilities,
ranks them by how likely they are to be exploited (CISA KEV + EPSS), and records a reviewed and
signed VEX statement for every vulnerability (local LLM suggestion + my sign-off).

## How to run

    node step1.js        # download each repo at its frozen commit -> SBOM (Syft) -> vulnerabilities (Grype)
    node step2.js        # add EPSS + CISA KEV, set priority P1-P5, rank -> CycloneDX
    node step3_llm.js    # evidence + local LLM (Ollama, llama3.2:3b) suggests a VEX state -> review.csv
    node review.js       # I check the LLM's answers in the terminal: agree / change (all P1 + P2; --all for every one)
    node step3_vex.js    # my decisions (+ LLM answers I did not check, clearly marked) -> CycloneDX VEX, linked to the SBOM
    node sign.js         # sign every output file with my private key (Ed25519)
    node verify.js       # anyone: check the signatures and the frozen KEV/EPSS data

## Output (one folder per repo, so each repo's owners can fix their own repo)

| File | Made by | What it is |
|---|---|---|
| `output/<repo>/sbom.cdx.json` | Syft (step1.js) | The SBOM: every component (library + version) in the repo, CycloneDX |
| `output/<repo>/grype.json` | Grype (step1.js) | The known vulnerabilities Grype matched to the SBOM |
| `output/<repo>/ranked.cdx.json` | step2.js | The components + vulnerabilities, ranked, with EPSS, KEV and priority, CycloneDX 1.7 |
| `output/<repo>/llm.json` | step3_llm.js | For each vulnerability: the evidence, the prompt and the LLM's suggestion + the model's exact version |
| `output/<repo>/review.csv` | step3_llm.js + review.js | The LLM suggestions and my decision for each one I checked (agree / change) |
| `output/<repo>/vex.cdx.json` | step3_vex.js | The VEX: final state of each vulnerability (exploitable / not_affected / in_triage ...), CycloneDX 1.7 |
| `output/<repo>/signatures.json` | sign.js | SHA-256 + my Ed25519 signature for every file above |

## Repos scanned (`testset.json`)
Juice Shop, NodeGoat and DVNA - each forked to my account and pinned to one exact commit,
so the scan always uses the same code.

## Frozen inputs (so the results never change by themselves)
- **Code:** each repo pinned to an exact commit (`testset.json`); npm lock files saved in `locks/`
- **Tools:** Syft 1.55.0, Grype 0.121.0
- **Grype vulnerability database:** built 2026-10-22T18:51:21Z, auto-update turned off in `~/.grype.yaml`
- **KEV + EPSS data:** `kev-epss-snapshot/2026-10-29/` (KEV catalog 2026.10.28, EPSS score date 2026-10-28).
  `step2.js` checks the SHA-256 fingerprint of both files on every run and stops if either has changed.
- **LLM:** Ollama, model `llama3.2:3b`, temperature 0, seed 42; the model digest is saved in `llm.json` and `vex.cdx.json`.
  Answers are cached by prompt SHA-256, so re-running gives the same suggestions.

## Priority and ranking
P1 - in CISA KEV (being exploited) / P2 - EPSS >= 10% / P3 - EPSS 1-10% / P4 - EPSS < 1% / P5 - no EPSS score.
Within each repo: in KEV first, then higher EPSS score, then higher EPSS percentile, then higher severity.
In `ranked.cdx.json` each vulnerability carries these as properties: `fyp:exploitability_rank`, `fyp:priority`,
`fyp:epss:score`, `fyp:epss:percentile`, `fyp:epss:cve`, `fyp:kev:in_kev`, `fyp:kev:date_added`,
`fyp:kev:due_date`, `fyp:kev:ransomware_use`, `fyp:fix_state`.

## Step 3 - VEX with LLM suggestion and my sign-off
1. `step3_llm.js` collects facts for each vulnerability by code (is the package a direct or indirect dependency,
   production or development only, which package pulls it in, is it imported by the app's own code) and asks the
   local LLM for a VEX state: `exploitable`, `not_affected` (with a justification) or `in_triage`.
2. I check the suggestions with `review.js` (one at a time in the terminal): `agree`, or `change` with my own state and reason.
   Every P1 + P2 vulnerability must be checked (`step3_vex.js` stops otherwise); `node review.js --all` checks every one.
   Any vulnerability I did not check keeps the LLM's suggestion and is marked `fyp:review:decision = LLM only - not reviewed`.
3. `step3_vex.js` writes `vex.cdx.json`. Each vulnerability's `analysis` is my final decision; the LLM's suggestion
   is kept as `fyp:llm:*` properties and my decision as `fyp:review:decision`. `affects` points to the component in
   `sbom.cdx.json` with a CycloneDX BOM-Link. The metadata records the sign-off (`fyp:signoff:by`, `fyp:signoff:date`, `fyp:signoff:status`).
4. `sign.js` signs every output file. The private key stays on my laptop; the public key is `keys/fadiah-ed25519.pub.pem`.
   `verify.js` checks them, and GitHub Actions (`.github/workflows/verify.yml`) runs it after every push.
