// Cross-check: does the live FIRST EPSS API give the same scores as our frozen snapshot?
// Takes the first 10 different EPSS CVEs from the ranked list and asks the API for the snapshot's score date.
const fs = require("fs");
const path = require("path");
const OUT = path.join(__dirname, "output");

(async () => {
  const meta = JSON.parse(fs.readFileSync(path.join(OUT, "step2_metadata.json"), "utf8"));
  const { findings } = JSON.parse(fs.readFileSync(path.join(OUT, "enriched_findings.json"), "utf8"));
  const day = meta.epss.score_date.slice(0, 10); // e.g. 2026-10-28
  const sample = [];
  for (const f of findings) {
    if (f.epss_cve && !sample.some(x => x.cve === f.epss_cve)) sample.push({ cve: f.epss_cve, epss: f.epss_score, percentile: f.epss_percentile });
    if (sample.length === 10) break;
  }
  const url = `https://api.first.org/data/v1/epss?cve=${sample.map(x => x.cve).join(",")}&date=${day}`;
  let api;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    api = new Map(((await res.json()).data || []).map(d => [d.cve, d]));
  } catch (e) {
    console.log(`API cross-check skipped (no internet?): ${e.message}`);
    return;
  }
  let match = 0;
  const rows = sample.map(x => {
    const d = api.get(x.cve);
    const ok = d && Math.abs(Number(d.epss) - x.epss) < 1e-6 && Math.abs(Number(d.percentile) - x.percentile) < 1e-6;
    if (ok) match++;
    console.log(`  ${x.cve.padEnd(16)} snapshot ${x.epss} / ${x.percentile}   API ${d ? Number(d.epss) + " / " + Number(d.percentile) : "not returned"}   ${ok ? "MATCH" : "DIFFERENT"}`);
    return { cve: x.cve, snapshot_epss: x.epss, snapshot_percentile: x.percentile, api_epss: d ? Number(d.epss) : null, api_percentile: d ? Number(d.percentile) : null, match: Boolean(ok) };
  });
  const result = { checked_at: new Date().toISOString(), api: "https://api.first.org/data/v1/epss", date: day, sample_size: sample.length, matches: match, rows };
  fs.writeFileSync(path.join(OUT, "epss_api_check.json"), JSON.stringify(result, null, 2));
  console.log(`\nAPI cross-check (${day}): ${match}/${sample.length} match. Wrote output/epss_api_check.json`);
})();
