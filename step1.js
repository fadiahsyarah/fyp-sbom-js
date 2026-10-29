const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const REPOS_DIR = path.join(ROOT, "repos");
const OUT_DIR = path.join(ROOT, "output");

function run(cmd, args, opts = {}) {
  console.log(`  $ ${cmd} ${args.join(" ")}`);
  return execFileSync(cmd, args, { stdio: ["ignore", "pipe", "inherit"], maxBuffer: 1 << 30, ...opts }).toString();
}

function cloneRepo(repo) {
  const dir = path.join(REPOS_DIR, repo.name);
  if (!fs.existsSync(dir)) run("git", ["clone", "--depth", "1", "--branch", repo.ref, repo.url, dir]);
  if (repo.commit && run("git", ["-C", dir, "rev-parse", "HEAD"]).trim() !== repo.commit) {
    run("git", ["-C", dir, "fetch", "--depth", "1", "origin", repo.commit]);
    run("git", ["-C", dir, "checkout", "--quiet", repo.commit]);
  }
  const commit = run("git", ["-C", dir, "rev-parse", "HEAD"]).trim();
  const hasLock = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"].some(f => fs.existsSync(path.join(dir, f)));
  if (!hasLock && fs.existsSync(path.join(dir, "package.json"))) {
    console.log("  no lock file found -> generating package-lock.json (no scripts run)");
    try { run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: dir }); }
    catch { console.warn("  ! could not generate lock file"); }
  }
  return { dir, commit };
}

function normalise(grypeJson, repo, commit) {
  return (grypeJson.matches || []).map(m => {
    const v = m.vulnerability, a = m.artifact;
    const ids = [v.id, ...(m.relatedVulnerabilities || []).map(r => r.id)];
    const cves = [...new Set(ids.filter(id => /^CVE-\d{4}-\d+$/.test(id)))];
    const cvss = [...(v.cvss || []), ...(m.relatedVulnerabilities || []).flatMap(r => r.cvss || [])]
      .map(c => c.metrics && c.metrics.baseScore).filter(n => typeof n === "number");
    return {
      repo: repo.name, commit, language: "javascript", package_type: a.type,
      package: a.name, version: a.version, purl: a.purl || null,
      vuln_id: v.id, cve_ids: cves, severity: v.severity,
      cvss_max: cvss.length ? Math.max(...cvss) : null,
      fix_state: v.fix ? v.fix.state : "unknown",
      fix_versions: v.fix ? v.fix.versions : [],
      locations: (a.locations || []).map(l => l.path),
      description: v.description || (m.relatedVulnerabilities || [])[0]?.description || "",
      epss: null, epss_percentile: null, kev: null, llm_verdict: null
    };
  });
}

fs.mkdirSync(REPOS_DIR, { recursive: true });
fs.mkdirSync(OUT_DIR, { recursive: true });
const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
const all = [];
for (const repo of repos) {
  console.log(`\n== ${repo.name}`);
  const { dir, commit } = cloneRepo(repo);
  const sbomPath = path.join(OUT_DIR, `${repo.name}.cdx.json`);
  fs.writeFileSync(sbomPath, run("syft", [`dir:${dir}`, "-o", "cyclonedx-json", "-q"]));
  const comps = JSON.parse(fs.readFileSync(sbomPath, "utf8")).components || [];
  console.log(`  SBOM: ${comps.length} components`);
  const raw = run("grype", [`sbom:${sbomPath}`, "-o", "json", "-q"]);
  fs.writeFileSync(path.join(OUT_DIR, `${repo.name}.grype.json`), raw);
  const findings = normalise(JSON.parse(raw), repo, commit);
  console.log(`  Grype: ${findings.length} findings`);
  all.push(...findings);
}
fs.writeFileSync(path.join(OUT_DIR, "findings.json"),
  JSON.stringify({ schema_version: "1.0", generated_at: new Date().toISOString(), findings: all }, null, 2));
console.log(`\nWrote output/findings.json (${all.length} findings)`);
