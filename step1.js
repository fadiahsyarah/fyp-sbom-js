// STEP 1 - SBOM + vulnerability scan, one folder per repo.
// For each repo in testset.json:
//   1. download it (my fork) and switch to its frozen commit
//   2. make sure it has a frozen lock file (exact package versions)
//   3. Syft  -> output/<repo>/sbom-step1.cdx.json   (the SBOM, CycloneDX)
//   4. Grype -> output/<repo>/grype.json      (vulnerabilities matched against the SBOM, Grype's own JSON - read by step2.js)
//            -> output/<repo>/vulnerabilities-step1.vex.cdx.json   (the same findings in CycloneDX, team file name)
// Run: node step1.js
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const REPOS = path.join(ROOT, "repos");   // downloaded repos (not uploaded to GitHub)
const LOCKS = path.join(ROOT, "locks");   // frozen npm lock files
const OUT = path.join(ROOT, "output");

// Run a command, print it first, and return what it prints
function run(cmd, args, cwd) {
  console.log(`  $ ${cmd} ${args.join(" ")}`);
  return execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "inherit"], maxBuffer: 1 << 30 }).toString();
}

const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
for (const repo of repos) {
  console.log(`\n== ${repo.name}`);
  const dir = path.join(REPOS, repo.name);
  const out = path.join(OUT, repo.name);
  fs.mkdirSync(out, { recursive: true });

  // 1. Download the repo and go to the frozen commit
  if (!fs.existsSync(dir)) run("git", ["clone", "--depth", "1", repo.url, dir]);
  if (run("git", ["-C", dir, "rev-parse", "HEAD"]).trim() !== repo.commit) {
    run("git", ["-C", dir, "fetch", "--depth", "1", "origin", repo.commit]);
    run("git", ["-C", dir, "checkout", "--quiet", repo.commit]);
  }

  // 2. Lock file: Syft needs it to see exact package versions.
  //    Use the frozen copy in locks/ if the repo has none; if there is no frozen copy yet, create one and save it.
  const lock = path.join(dir, "package-lock.json");
  const frozen = path.join(LOCKS, `${repo.name}.package-lock.json`);
  if (!fs.existsSync(lock) && fs.existsSync(frozen)) fs.copyFileSync(frozen, lock);
  if (!fs.existsSync(lock)) {
    run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], dir);
    fs.mkdirSync(LOCKS, { recursive: true });
    fs.copyFileSync(lock, frozen);
  }

  // 3. SBOM with Syft (CycloneDX JSON). -q = quiet, so only the SBOM is printed
  const sbomFile = path.join(out, "sbom-step1.cdx.json");
  fs.writeFileSync(sbomFile, run("syft", [`dir:${dir}`, "-o", "cyclonedx-json", "-q"]));

  // 4. Match the SBOM against Grype's frozen vulnerability database
  const grype = run("grype", [`sbom:${sbomFile}`, "-o", "json", "-q"]);
  fs.writeFileSync(path.join(out, "grype.json"), grype);
  fs.writeFileSync(path.join(out, "vulnerabilities-step1.vex.cdx.json"), run("grype", [`sbom:${sbomFile}`, "-o", "cyclonedx-json", "-q"]));

  const components = JSON.parse(fs.readFileSync(sbomFile, "utf8")).components.length;
  console.log(`  SBOM: ${components} components | Grype: ${JSON.parse(grype).matches.length} vulnerabilities`);
}
console.log("\nStep 1 done: output/<repo>/sbom-step1.cdx.json, grype.json and vulnerabilities-step1.vex.cdx.json");
