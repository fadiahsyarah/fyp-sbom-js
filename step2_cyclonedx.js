// Step 2 (standard format): write the ranked findings as CycloneDX, the SBOM standard.
// For each repo: copies the components from the Syft SBOM and adds a "vulnerabilities" list where every
// vulnerability points to the component it affects and carries EPSS, KEV, priority and rank as properties.
// Input : output/enriched_findings.json (from step2.js), output/<repo>.cdx.json (from step1.js), output/step2_metadata.json
// Output: output/<repo>.enriched.cdx.json  (CycloneDX 1.6 JSON)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const read = f => JSON.parse(fs.readFileSync(f, "utf8"));
const { findings } = read(path.join(OUT, "enriched_findings.json"));
const meta = read(path.join(OUT, "step2_metadata.json"));
const testset = read(path.join(ROOT, "testset.json")).repos;
const grypeDb = fs.existsSync(path.join(OUT, "grype-db-status.txt"))
  ? (fs.readFileSync(path.join(OUT, "grype-db-status.txt"), "utf8").match(/Built:\s*(\S+)/) || [])[1] || "" : "";

// CycloneDX only allows these severity words
const SEV = { critical: "critical", high: "high", medium: "medium", low: "low", negligible: "info", unknown: "unknown" };
const prop = (name, value) => (value === null || value === undefined || value === "" ? null : { name, value: String(value) });
const sourceFor = id =>
  id.startsWith("GHSA-") ? { name: "GitHub Advisory Database", url: `https://github.com/advisories/${id}` } :
  id.startsWith("CVE-") ? { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${id}` } :
  { name: "OSV", url: `https://osv.dev/vulnerability/${id}` };

let written = 0;
for (const repo of testset) {
  const sbomFile = path.join(OUT, `${repo.name}.cdx.json`);
  if (!fs.existsSync(sbomFile)) { console.log(`  skip ${repo.name}: no SBOM`); continue; }
  const sbom = read(sbomFile);
  const components = sbom.components || [];
  const refsByPurl = new Map();
  for (const c of components) if (c.purl) refsByPurl.set(c.purl, [...(refsByPurl.get(c.purl) || []), c["bom-ref"]]);

  const repoFindings = findings.filter(f => f.repo === repo.name).sort((a, b) => a.exploitability_rank - b.exploitability_rank);
  let unmatched = 0;
  const vulnerabilities = repoFindings.map(f => {
    const refs = refsByPurl.get(f.purl) || [];
    if (!refs.length) unmatched++;
    const rating = { source: { name: "Grype" }, severity: SEV[String(f.severity).toLowerCase()] || "unknown" };
    if (typeof f.cvss_max === "number") { rating.score = f.cvss_max; rating.method = "other"; }
    const v = {
      "bom-ref": `vuln-${f.exploitability_rank}`,
      id: f.vuln_id,
      source: sourceFor(f.vuln_id),
      references: (f.cve_ids || []).filter(c => c !== f.vuln_id).map(c => ({ id: c, source: sourceFor(c) })),
      ratings: [rating],
      description: f.description || undefined,
      recommendation: (f.fix_versions || []).length ? `Upgrade ${f.package} to ${f.fix_versions.join(" or ")}` : "No fixed version available",
      affects: refs.map(ref => ({ ref, versions: [{ version: f.version, status: "affected" }] })),
      properties: [
        prop("fyp:priority", f.priority),
        prop("fyp:exploitability_rank", f.exploitability_rank),
        prop("fyp:epss:score", f.epss_score),
        prop("fyp:epss:percentile", f.epss_percentile),
        prop("fyp:epss:cve", f.epss_cve),
        prop("fyp:kev:in_kev", f.in_kev),
        prop("fyp:kev:date_added", f.kev_date_added),
        prop("fyp:kev:due_date", f.kev_due_date),
        prop("fyp:kev:ransomware_use", f.kev_ransomware_use),
        prop("fyp:cve_source", f.cve_source),
        prop("fyp:fix_state", f.fix_state),
      ].filter(Boolean),
    };
    if (!v.references.length) delete v.references;
    if (!v.affects.length) delete v.affects;
    return v;
  });

  const bom = {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [
        { type: "application", author: "anchore", name: "syft", version: "1.55.0" },
        { type: "application", author: "anchore", name: "grype", version: "0.121.0" },
        { type: "application", name: "fyp-sbom-js step2.js", version: "1.0" },
      ] },
      component: {
        "bom-ref": `repo:${repo.name}`, type: "application", name: repo.name, version: repo.commit,
        externalReferences: [repo.url, repo.upstream].filter(Boolean).map(url => ({ type: "vcs", url })),
      },
      properties: [
        prop("fyp:snapshot", meta.snapshot),
        prop("fyp:kev:catalog_version", meta.kev && meta.kev.catalog_version),
        prop("fyp:kev:sha256", meta.kev && meta.kev.sha256),
        prop("fyp:epss:score_date", meta.epss && meta.epss.score_date),
        prop("fyp:epss:model_version", meta.epss && meta.epss.model_version),
        prop("fyp:epss:sha256", meta.epss && meta.epss.sha256),
        prop("fyp:grype:db_built", grypeDb),
        prop("fyp:ranking", meta.ranking),
      ].filter(Boolean),
    },
    components,
    vulnerabilities,
  };
  fs.writeFileSync(path.join(OUT, `${repo.name}.enriched.cdx.json`), JSON.stringify(bom, null, 2));
  written++;
  console.log(`  ${repo.name.padEnd(11)} ${String(vulnerabilities.length).padStart(4)} vulnerabilities, ${components.length} components` + (unmatched ? `  (${unmatched} not linked to a component)` : ""));
}
console.log(`\nWrote ${written} CycloneDX files: output/<repo>.enriched.cdx.json`);
