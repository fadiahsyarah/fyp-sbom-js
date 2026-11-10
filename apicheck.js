// One-time check: does the live FIRST EPSS API give the same scores as our frozen snapshot?
// Checks EVERY CVE that has an EPSS score in our results (not just a sample), on the snapshot's score date.
const fs = require("fs");
const path = require("path");
const OUT = path.join(__dirname, "output");
const API = "https://api.first.org/data/v1/epss";

(async () => {
  const meta = JSON.parse(fs.readFileSync(path.join(OUT, "step2_metadata.json"), "utf8"));
  const { findings } = JSON.parse(fs.readFileSync(path.join(OUT, "enriched_findings.json"), "utf8"));
  const day = meta.epss.score_date.slice(0, 10); // e.g. 2026-10-28
  const ours = new Map();
  for (const f of findings) if (f.epss_cve && !ours.has(f.epss_cve)) ours.set(f.epss_cve, { epss: f.epss_score, percentile: f.epss_percentile });
  const cves = [...ours.keys()];
  console.log(`Checking all ${cves.length} CVEs with an EPSS score against the live API (date ${day})...`);

  const api = new Map();
  try {
    for (let i = 0; i < cves.length; i += 50) {               // 50 CVEs per request keeps the web address short
      const url = `${API}?cve=${cves.slice(i, i + 50).join(",")}&date=${day}&limit=100`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      for (const d of (await res.json()).data || []) api.set(d.cve, d);
    }
  } catch (e) {
    console.log(`API check skipped (no internet?): ${e.message}`);
    return;
  }

  const rows = cves.map(cve => {
    const o = ours.get(cve), d = api.get(cve);
    const match = Boolean(d) && Math.abs(Number(d.epss) - o.epss) < 1e-6 && Math.abs(Number(d.percentile) - o.percentile) < 1e-6;
    return { cve, snapshot_epss: o.epss, snapshot_percentile: o.percentile,
             api_epss: d ? Number(d.epss) : null, api_percentile: d ? Number(d.percentile) : null, match };
  });
  const matches = rows.filter(r => r.match).length;
  const different = rows.filter(r => !r.match);
  for (const r of different.slice(0, 20))
    console.log(`  DIFFERENT ${r.cve}: snapshot ${r.snapshot_epss} / ${r.snapshot_percentile}, API ${r.api_epss ?? "not returned"} / ${r.api_percentile ?? "-"}`);
  for (const r of rows.slice(0, 5))
    console.log(`  e.g. ${r.cve.padEnd(16)} snapshot ${r.snapshot_epss}  API ${r.api_epss}  ${r.match ? "MATCH" : "DIFFERENT"}`);

  const result = { checked_at: new Date().toISOString(), api: API, date: day, checked: rows.length, matches, different: different.length, rows };
  fs.writeFileSync(path.join(OUT, "epss_api_check.json"), JSON.stringify(result, null, 2));
  console.log(`\nAPI check (${day}): ${matches}/${rows.length} CVEs match. Wrote output/epss_api_check.json`);
})();
