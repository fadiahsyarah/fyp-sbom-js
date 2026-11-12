// STEP 2 - add EPSS + CISA KEV to every vulnerability, rank them, and save the result as CycloneDX.
// One result per repo, so each repo's owners can see and fix their own vulnerabilities.
//   Input : output/<repo>/sbom.cdx.json + output/<repo>/grype.json (from step1.js)
//           kev-epss-snapshot/2026-10-29/ (frozen KEV + EPSS data, checked with SHA-256)
//   Output: output/<repo>/ranked.cdx.json (CycloneDX 1.7: components + ranked vulnerabilities)
// Run: node step2.js
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const SNAPSHOT = "2026-10-29";
const SNAP_DIR = path.join(ROOT, "kev-epss-snapshot", SNAPSHOT);
const read = f => JSON.parse(fs.readFileSync(f, "utf8"));

// Priority rules
const P1 = "P1 - in CISA KEV", P2 = "P2 - EPSS >= 10%", P3 = "P3 - EPSS 1-10%", P4 = "P4 - EPSS < 1%", P5 = "P5 - no EPSS score";
const PRIORITIES = [P1, P2, P3, P4, P5];
const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, negligible: 1 };
const CDX_SEVERITY = { critical: "critical", high: "high", medium: "medium", low: "low", negligible: "info" };  // words CycloneDX allows
const CVSS_METHOD = { "2.0": "CVSSv2", "3.0": "CVSSv3", "3.1": "CVSSv31", "4.0": "CVSSv4" };

// ---------- 1. Load the frozen KEV + EPSS snapshot and check its SHA-256 fingerprints ----------
const sha256 = buf => crypto.createHash("sha256").update(buf).digest("hex");
const manifest = read(path.join(SNAP_DIR, "manifest.json"));
const kevRaw = fs.readFileSync(path.join(SNAP_DIR, manifest.kev.file));
const epssRaw = fs.readFileSync(path.join(SNAP_DIR, manifest.epss.file));
if (sha256(kevRaw) !== manifest.kev.sha256 || sha256(epssRaw) !== manifest.epss.sha256) {
  console.error("STOP: the KEV/EPSS files do not match the SHA-256 in manifest.json - the frozen data has changed.");
  process.exit(1);
}
const kev = new Map(JSON.parse(kevRaw).vulnerabilities.map(v => [v.cveID, v]));
const epss = new Map();
for (const line of zlib.gunzipSync(epssRaw).toString("utf8").split("\n")) {
  const [cve, score, percentile] = line.split(",");
  if (/^CVE-\d+-\d+$/.test(cve)) epss.set(cve, { score: Number(score), percentile: Number(percentile) });
}
console.log(`Snapshot ${SNAPSHOT} (SHA-256 OK): KEV ${kev.size} entries, EPSS ${epss.size} CVEs (score date ${manifest.epss.score_date})`);

// ---------- 2. Each repo ----------
const { repos } = read(path.join(ROOT, "testset.json"));
const prop = (name, value) => (value === null || value === undefined ? null : { name, value: String(value) });
const sourceFor = id =>
  id.startsWith("GHSA-") ? { name: "GitHub Advisory Database", url: `https://github.com/advisories/${id}` } :
  id.startsWith("CVE-") ? { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${id}` } :
  { name: "OSV", url: `https://osv.dev/vulnerability/${id}` };

for (const repo of repos) {
  const dir = path.join(OUT, repo.name);
  const sbom = read(path.join(dir, "sbom.cdx.json"));
  const grype = read(path.join(dir, "grype.json"));

  // Each SBOM component has a bom-ref; vulnerabilities point to the component they affect
  const refsByPurl = new Map();
  for (const c of sbom.components || []) if (c.purl) refsByPurl.set(c.purl, [...(refsByPurl.get(c.purl) || []), c["bom-ref"]]);

  // 2a. Enrich every vulnerability Grype found
  const vulns = grype.matches.map(m => {
    const v = m.vulnerability, pkg = m.artifact, related = m.relatedVulnerabilities || [];
    // CVE IDs: the vulnerability's own ID if it is a CVE, plus the CVEs Grype lists as the same vulnerability
    const cves = [...new Set([v.id, ...related.map(r => r.id)].filter(id => /^CVE-/.test(id)))];
    let best = null;                                       // several CVEs -> use the highest EPSS
    for (const c of cves) { const e = epss.get(c); if (e && (!best || e.score > best.score)) best = { cve: c, ...e }; }
    const inKev = cves.map(c => kev.get(c)).find(Boolean);
    const priority = inKev ? P1 : !best ? P5 : best.score >= 0.10 ? P2 : best.score >= 0.01 ? P3 : P4;
    // Highest CVSS score from the vulnerability or its CVEs
    const cvss = [...(v.cvss || []), ...related.flatMap(r => r.cvss || [])]
      .filter(c => c.metrics && typeof c.metrics.baseScore === "number")
      .sort((a, b) => b.metrics.baseScore - a.metrics.baseScore)[0];
    return { v, pkg, cves, best, inKev, priority, cvss };
  });

  // 2b. Rank: in KEV first > higher EPSS score > higher EPSS percentile > higher severity
  const n = x => (x === undefined ? -1 : x);
  const sev = x => SEVERITY_ORDER[String(x.v.severity).toLowerCase()] || 0;
  vulns.sort((a, b) => (Boolean(b.inKev) - Boolean(a.inKev)) || (n(b.best?.score) - n(a.best?.score)) ||
    (n(b.best?.percentile) - n(a.best?.percentile)) || (sev(b) - sev(a)));

  // 2c. Write them as CycloneDX vulnerabilities
  const vulnerabilities = vulns.map((x, i) => {
    const rating = { source: { name: "Grype" }, severity: CDX_SEVERITY[String(x.v.severity).toLowerCase()] || "unknown" };
    if (x.cvss) { rating.score = x.cvss.metrics.baseScore; rating.method = CVSS_METHOD[x.cvss.version] || "other"; if (x.cvss.vector) rating.vector = x.cvss.vector; }
    const refs = refsByPurl.get(x.pkg.purl) || [];
    const fixes = (x.v.fix && x.v.fix.versions) || [];
    const out = {
      "bom-ref": `vuln-${i + 1}`,
      id: x.v.id,
      source: sourceFor(x.v.id),
      references: x.cves.filter(c => c !== x.v.id).map(c => ({ id: c, source: sourceFor(c) })),
      ratings: [rating],
      description: x.v.description || (x.pkg.name + " " + x.pkg.version),
      recommendation: fixes.length ? `Upgrade ${x.pkg.name} to ${fixes.join(" or ")}` : "No fixed version available",
      affects: refs.map(ref => ({ ref, versions: [{ version: x.pkg.version, status: "affected" }] })),
      properties: [
        prop("fyp:exploitability_rank", i + 1),
        prop("fyp:priority", x.priority),
        prop("fyp:epss:score", x.best?.score),
        prop("fyp:epss:percentile", x.best?.percentile),
        prop("fyp:epss:cve", x.best?.cve),
        prop("fyp:kev:in_kev", Boolean(x.inKev)),
        prop("fyp:kev:date_added", x.inKev?.dateAdded),
        prop("fyp:kev:due_date", x.inKev?.dueDate),
        prop("fyp:kev:ransomware_use", x.inKev?.knownRansomwareCampaignUse),
        prop("fyp:fix_state", x.v.fix?.state),
      ].filter(Boolean),
    };
    if (!out.references.length) delete out.references;
    if (!out.affects.length) delete out.affects;
    return out;
  });

  const bom = {
    $schema: "http://cyclonedx.org/schema/bom-1.7.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [
        ...((sbom.metadata && sbom.metadata.tools && sbom.metadata.tools.components) || []),       // Syft
        { type: "application", author: "anchore", name: "grype", version: grype.descriptor.version },
        { type: "application", name: "fyp-sbom-js step2.js", version: "1.0" },
      ] },
      component: {
        "bom-ref": `repo:${repo.name}`, type: "application", name: repo.name, version: repo.commit,
        externalReferences: [repo.url, repo.upstream].filter(Boolean).map(url => ({ type: "vcs", url })),
      },
      properties: [
        prop("fyp:grype:db_built", grype.descriptor.db && grype.descriptor.db.status && grype.descriptor.db.status.built),
        prop("fyp:snapshot", SNAPSHOT),
        prop("fyp:kev:catalog_version", manifest.kev.catalog_version),
        prop("fyp:kev:sha256", manifest.kev.sha256),
        prop("fyp:epss:score_date", manifest.epss.score_date),
        prop("fyp:epss:model_version", manifest.epss.model_version),
        prop("fyp:epss:sha256", manifest.epss.sha256),
        prop("fyp:ranking", "1) in CISA KEV  2) higher EPSS score  3) higher EPSS percentile  4) higher severity"),
      ].filter(Boolean),
    },
    components: sbom.components || [],
    dependencies: sbom.dependencies || [],
    vulnerabilities,
  };
  fs.writeFileSync(path.join(dir, "ranked.cdx.json"), JSON.stringify(bom, null, 2));

  // 2d. Print a summary for this repo
  const count = p => vulns.filter(x => x.priority === p).length;
  console.log(`\n== ${repo.name}: ${vulns.length} vulnerabilities | ` + PRIORITIES.map(p => `${p.slice(0, 2)} ${count(p)}`).join(" / "));
  for (const [i, x] of vulns.slice(0, 5).entries())
    console.log(`  #${i + 1} ${x.priority.slice(0, 2)}  ${x.pkg.name} ${x.pkg.version}  ${x.best?.cve || x.v.id}  EPSS ${x.best ? x.best.score : "-"}  ${x.v.severity}`);
}
console.log("\nStep 2 done: output/<repo>/ranked.cdx.json");
