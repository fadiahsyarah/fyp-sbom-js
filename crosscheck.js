const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
const { findings } = JSON.parse(fs.readFileSync(path.join(ROOT, "output", "findings.json"), "utf8"));

function npmAudit(dir) {
  try {
    return execFileSync("npm", ["audit", "--json"], { cwd: dir, maxBuffer: 1 << 30 }).toString();
  } catch (e) {
    return e.stdout.toString(); // npm audit exits with an error code when it finds vulnerabilities
  }
}

const report = [];
for (const repo of repos) {
  const raw = JSON.parse(npmAudit(path.join(ROOT, "repos", repo.name)));
  const npmIds = new Set();
  for (const pkg of Object.values(raw.vulnerabilities || {})) {
    for (const v of pkg.via || []) {
      if (typeof v === "object" && v.url) {
        const m = v.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/);
        if (m) npmIds.add(m[0]);
      }
    }
  }
  const grypeIds = new Set(findings.filter(f => f.repo === repo.name).map(f => f.vuln_id));
  const both = [...grypeIds].filter(id => npmIds.has(id));
  const grypeOnly = [...grypeIds].filter(id => !npmIds.has(id));
  const npmOnly = [...npmIds].filter(id => !grypeIds.has(id));
  console.log(`\n== ${repo.name}`);
  console.log(`  Grype unique advisories: ${grypeIds.size}`);
  console.log(`  npm audit advisories:    ${npmIds.size}`);
  console.log(`  Found by BOTH:           ${both.length}`);
  console.log(`  Grype only:              ${grypeOnly.length}`);
  console.log(`  npm audit only:          ${npmOnly.length}`);
  report.push({ repo: repo.name, grype: grypeIds.size, npm_audit: npmIds.size, both, grype_only: grypeOnly, npm_only: npmOnly });
}
fs.writeFileSync(path.join(ROOT, "output", "crosscheck.json"), JSON.stringify(report, null, 2));
console.log("\nWrote output/crosscheck.json");
