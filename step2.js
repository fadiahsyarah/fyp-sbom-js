// Step 2: add EPSS + CISA KEV to every finding and rank by exploitability
// Uses the team's frozen catalog (github.com/caffeineintaker/fyp-vuln-catalog) - no live downloads.
// Usage: node step2.js [--catalog ~/fyp/vuln-catalog] [--snapshot 2026-10-29]
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const arg = (name, def) => { const i = process.argv.indexOf(name); return i > -1 ? process.argv[i + 1] : def; };
const CATALOG = arg("--catalog", path.join(process.env.HOME || "", "fyp", "vuln-catalog"));
const SNAPSHOT = arg("--snapshot", "2026-10-29");
const SNAP_DIR = path.join(CATALOG, "snapshots", SNAPSHOT);

// Team priority labels - must match the other pipelines EXACTLY
const P1 = "P1 - in CISA KEV", P2 = "P2 - EPSS >= 10%", P3 = "P3 - EPSS 1-10%", P4 = "P4 - EPSS < 1%", P5 = "P5 - no EPSS score";
const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, negligible: 1 };

function fail(msg) { console.error("Step 2 failed: " + msg); process.exit(1); }
const sha256 = buf => crypto.createHash("sha256").update(buf).digest("hex");

// ---------- 1. Load the frozen snapshot and check it is untouched ----------
if (!fs.existsSync(SNAP_DIR)) fail(`snapshot not found: ${SNAP_DIR}\n  Clone the catalog first: git clone https://github.com/caffeineintaker/fyp-vuln-catalog ~/fyp/vuln-catalog`);
const manifest = JSON.parse(fs.readFileSync(path.join(SNAP_DIR, "manifest.json"), "utf8"));
const kevRaw = fs.readFileSync(path.join(SNAP_DIR, manifest.kev.file));
const epssRaw = fs.readFileSync(path.join(SNAP_DIR, manifest.epss.file));
if (sha256(kevRaw) !== manifest.kev.sha256) fail("kev.json does not match the SHA-256 in manifest.json");
if (sha256(epssRaw) !== manifest.epss.sha256) fail("epss_scores.csv.gz does not match the SHA-256 in manifest.json");

const kev = new Map();
for (const v of JSON.parse(kevRaw).vulnerabilities || []) kev.set(v.cveID, v);

const epss = new Map();
for (const line of zlib.gunzipSync(epssRaw).toString("utf8").split(/\r?\n/)) {
  const [cve, score, pct] = line.split(",");
  if (/^CVE-\d{4}-\d+$/.test(cve)) epss.set(cve, { epss: Number(score), percentile: Number(pct) });
}
console.log(`Snapshot ${SNAPSHOT}: KEV ${kev.size} (catalog ${manifest.kev.catalog_version}), EPSS ${epss.size} CVEs (score date ${manifest.epss.score_date})`);

// ---------- 2. Load Step 1 findings ----------
const step1 = JSON.parse(fs.readFileSync(path.join(OUT, "findings.json"), "utf8"));
const findings = Array.isArray(step1) ? step1 : step1.findings;

// ---------- 3. GHSA advisories with no CVE from Grype: ask GitHub's advisory database ----------
const ghsaCacheFile = path.join(OUT, "ghsa_cve_lookup.json");
const ghsaCache = fs.existsSync(ghsaCacheFile) ? JSON.parse(fs.readFileSync(ghsaCacheFile, "utf8")) : {};
const needLookup = [...new Set(findings.filter(f => !(f.cve_ids || []).length && /^GHSA-/.test(f.vuln_id)).map(f => f.vuln_id))]
  .filter(id => !(id in ghsaCache));
if (needLookup.length) {
  console.log(`Looking up ${needLookup.length} GHSA IDs without a CVE on GitHub (gh api)...`);
  for (const id of needLookup) {
    try {
      const adv = JSON.parse(execFileSync("gh", ["api", `/advisories/${id}`], { stdio: ["ignore", "pipe", "ignore"] }).toString());
      ghsaCache[id] = adv.cve_id || null;
    } catch { ghsaCache[id] = null; }
  }
  fs.writeFileSync(ghsaCacheFile, JSON.stringify(ghsaCache, null, 2));
}

// ---------- 4. Enrich every finding ----------
const enriched = findings.map(f => {
  let cves = f.cve_ids || [];
  let cve_source = cves.length ? "grype" : "none";
  if (!cves.length && ghsaCache[f.vuln_id]) { cves = [ghsaCache[f.vuln_id]]; cve_source = "github"; }
  let best = null; // if several CVEs, use the one with the highest EPSS
  for (const c of cves) {
    const e = epss.get(c);
    if (e && (!best || e.epss > best.epss)) best = { cve: c, ...e };
  }
  const kevHit = cves.map(c => kev.get(c)).find(Boolean);
  const out = { ...f, cve_ids: cves };
  delete out.epss; delete out.kev; // old Step 1 placeholders
  Object.assign(out, {
    cve_source,
    epss_score: best ? best.epss : null,
    epss_percentile: best ? best.percentile : null,
    epss_cve: best ? best.cve : null,
    in_kev: Boolean(kevHit),
    kev_date_added: kevHit ? kevHit.dateAdded : null,
    kev_due_date: kevHit ? kevHit.dueDate : null,
    kev_ransomware_use: kevHit ? kevHit.knownRansomwareCampaignUse : null,
  });
  out.priority = out.in_kev ? P1 : out.epss_score === null ? P5 : out.epss_score >= 0.10 ? P2 : out.epss_score >= 0.01 ? P3 : P4;
  return out;
});

// ---------- 5. Rank: KEV first > EPSS score > EPSS percentile > severity ----------
const num = v => (v === null ? -1 : v);
const sev = f => SEVERITY_ORDER[String(f.severity).toLowerCase()] || 0;
enriched.sort((a, b) => (b.in_kev - a.in_kev) || (num(b.epss_score) - num(a.epss_score)) ||
  (num(b.epss_percentile) - num(a.epss_percentile)) || (sev(b) - sev(a)));
enriched.forEach((f, i) => { f.exploitability_rank = i + 1; });

// ---------- 6. Write the three Step 2 files ----------
fs.writeFileSync(path.join(OUT, "enriched_findings.json"),
  JSON.stringify({ schema_version: "1.0", generated_at: new Date().toISOString(), snapshot: SNAPSHOT, findings: enriched }, null, 2));

const cols = [["exploitability_rank", "exploitability_rank"], ["priority", "priority"], ["repo", "repo"], ["package", "package"], ["version", "version"],
  ["vuln_id", "vuln_id"], ["cve_ids", "cve_ids"], ["severity", "severity"], ["epss_score", "epss_score"], ["epss_percentile", "epss_percentile"],
  ["in_kev", "in_kev"], ["kev_date_added", "kev_date_added"], ["kev_ransomware_use", "kev_ransomware_use"], ["fix_versions", "fix_versions"], ["cve_source", "cve_source"]];
const cell = (k, v) => {
  if (k === "in_kev") return v ? "Yes" : "No";
  const s = Array.isArray(v) ? v.join(" ") : v === null || v === undefined ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
fs.writeFileSync(path.join(OUT, "ranked_findings.csv"),
  [cols.map(c => c[1]).join(","), ...enriched.map(f => cols.map(([k]) => cell(k, f[k])).join(","))].join("\n") + "\n");

const byPriority = Object.fromEntries([P1, P2, P3, P4, P5].map(p => [p, enriched.filter(f => f.priority === p).length]));
const repos = [...new Set(enriched.map(f => f.repo))];
const meta = {
  generated_at: new Date().toISOString(),
  pipeline: "JavaScript (step2.js)",
  snapshot: SNAPSHOT,
  catalog: "https://github.com/caffeineintaker/fyp-vuln-catalog",
  kev: { catalog_version: manifest.kev.catalog_version, count: manifest.kev.count, sha256: manifest.kev.sha256 },
  epss: { score_date: manifest.epss.score_date, model_version: manifest.epss.model_version, count: manifest.epss.count, sha256: manifest.epss.sha256 },
  ranking: "1) in KEV  2) higher EPSS score  3) higher EPSS percentile  4) higher severity",
  counts: {
    findings: enriched.length,
    unique_cves: new Set(enriched.flatMap(f => f.cve_ids)).size,
    with_epss: enriched.filter(f => f.epss_score !== null).length,
    in_kev: enriched.filter(f => f.in_kev).length,
    no_cve: enriched.filter(f => f.cve_source === "none").length,
    by_priority: byPriority,
    by_repo: Object.fromEntries(repos.map(r => [r, Object.fromEntries([P1, P2, P3, P4, P5].map(p => [p.slice(0, 2), enriched.filter(f => f.repo === r && f.priority === p).length]))])),
  },
};
fs.writeFileSync(path.join(OUT, "step2_metadata.json"), JSON.stringify(meta, null, 2));

// ---------- 7. Print a summary ----------
const c = meta.counts;
console.log(`\n${c.findings} findings, ${c.unique_cves} unique CVEs, ${c.with_epss} with EPSS, ${c.in_kev} in KEV, ${c.no_cve} with no CVE`);
for (const [p, n] of Object.entries(byPriority)) console.log(`  ${p.padEnd(20)} ${n}`);
console.log("\nBy repo (P1 / P2 / P3 / P4 / P5):");
for (const [r, v] of Object.entries(c.by_repo)) console.log(`  ${r.padEnd(12)} ${Object.values(v).join(" / ")}`);
console.log("\nTop 10 most exploitable:");
for (const f of enriched.slice(0, 10))
  console.log(`  #${String(f.exploitability_rank).padEnd(3)} ${f.priority.slice(0, 2)}  ${f.repo.padEnd(11)} ${f.package} ${f.version}  ${f.epss_cve || f.vuln_id}  EPSS=${f.epss_score ?? "-"}  ${f.severity}`);
console.log("\nWrote output/enriched_findings.json, output/ranked_findings.csv, output/step2_metadata.json");
