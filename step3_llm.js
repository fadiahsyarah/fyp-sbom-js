// STEP 3a - collect evidence for every vulnerability and ask a local LLM (Ollama) for a VEX suggestion.
// The LLM only SUGGESTS. I review every suggestion in review.csv, then step3_vex.js writes the VEX.
//   Input : output/<repo>/vulnerabilities-step2.vex.cdx.json (step2.js) + repos/<repo> (the code, from step1.js)
//   Output: output/<repo>/llm.json    (evidence + prompt + LLM answer for every vulnerability)
//           output/<repo>/review.csv  (one row per vulnerability, for me to review in Excel)
// Run: node step3_llm.js            (needs Ollama running: ollama serve, model llama3.2:3b)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const REPOS = path.join(ROOT, "repos");
const OLLAMA = process.env.OLLAMA_URL || "http://localhost:11434";
// Same settings every run, so the same question gives the same answer
const MODEL = "llama3.2:3b";
const OPTIONS = { temperature: 0, seed: 42, top_k: 1, num_ctx: 4096 };
const read = f => JSON.parse(fs.readFileSync(f, "utf8"));
const sha256 = s => crypto.createHash("sha256").update(s).digest("hex");
const prop = (props, name) => (props.find(p => p.name === name) || {}).value;

// ---------- The question the LLM answers (same for every vulnerability) ----------
const SYSTEM = `You are a software security analyst writing a VEX (Vulnerability Exploitability eXchange) statement.
You get facts about ONE known vulnerability in ONE npm package used by a Node.js application.
Decide the VEX state for this application using ONLY the facts given:
- "exploitable": the vulnerable package is used by the running application (production dependency, imported by the app's code or by a package the app uses), and nothing in the facts shows the vulnerable function cannot be reached.
- "not_affected": the facts show the vulnerable code cannot affect the running application, for example the package is only a development dependency (used for building or testing, not shipped). Then give a justification.
- "in_triage": the facts are not enough to decide.
Never say "not_affected" only because the application is a training app or because the score is low.
Justification (only when not_affected), one of: code_not_present, code_not_reachable, requires_configuration, requires_dependency, requires_environment, protected_by_compiler, protected_at_runtime, protected_at_perimeter, protected_by_mitigating_control.
Reason: at most 2 short sentences that point to the facts you used.
Answer only with JSON.`;

const SCHEMA = {
  type: "object",
  properties: {
    state: { type: "string", enum: ["exploitable", "not_affected", "in_triage"] },
    justification: { type: "string", enum: ["none", "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
      "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"] },
    reason: { type: "string" },
  },
  required: ["state", "justification", "reason"],
};

// ---------- Evidence: facts about how the package is used in the repo (worked out by code, not by the LLM) ----------
const CODE_EXT = /\.(js|mjs|cjs|ts|jsx|tsx|ejs|html)$/;
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "coverage", ".angular"]);
function codeFiles(dir, base = dir, list = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) codeFiles(path.join(dir, e.name), base, list); }
    else if (CODE_EXT.test(e.name)) {
      const f = path.join(dir, e.name);
      if (fs.statSync(f).size < 2_000_000) list.push({ file: path.relative(base, f), text: fs.readFileSync(f, "utf8") });
    }
  }
  return list;
}
const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function evidenceFor(repoDir, files, lock, pkgJson, comp, sbomComps, parentsOf) {
  const name = comp.name, version = comp.version;
  const loc = prop(comp.properties || [], "syft:location:0:path") || "";
  // Which package.json declares it? (root or a sub-folder such as frontend/)
  const pj = pkgJson.get(path.dirname(loc).replace(/^\//, "") || ".") || pkgJson.get(".") || {};
  const direct = pj.dependencies && pj.dependencies[name] ? "direct production dependency"
    : pj.devDependencies && pj.devDependencies[name] ? "direct development dependency (devDependencies)"
    : "indirect dependency (pulled in by another package)";
  // Lock file entry: dev = only needed for development/testing, optional = may not be installed
  let dev = null, optional = false;
  const lockFile = lock.get(loc);
  if (lockFile && lockFile.packages) {
    for (const [k, v] of Object.entries(lockFile.packages))
      if ((k === `node_modules/${name}` || k.endsWith(`/node_modules/${name}`)) && v.version === version) {
        dev = dev === false ? false : Boolean(v.dev || v.devOptional);   // false wins: if any copy is production, it is production
        optional = optional || Boolean(v.optional);
      }
  }
  // Shortest chain from a package the app lists itself down to this package
  const top = new Set([...Object.keys(pj.dependencies || {}), ...Object.keys(pj.devDependencies || {})]);
  let chain = null;
  const start = comp["bom-ref"], queue = [[start]], seen = new Set([start]);
  while (queue.length && !chain) {
    const p = queue.shift(), c = sbomComps.get(p[p.length - 1]);
    if (c && top.has(c.name)) { chain = p.map(r => (sbomComps.get(r) || {}).name).reverse().join(" -> "); break; }
    for (const parent of parentsOf.get(p[p.length - 1]) || []) if (!seen.has(parent) && p.length < 8) { seen.add(parent); queue.push([...p, parent]); }
  }
  // Is the package imported by the app's own code?
  const re = new RegExp(`(require\\(\\s*['"\`]|from\\s+['"\`]|import\\s+['"\`]|import\\(\\s*['"\`])${escapeRe(name)}(/[^'"\`]*)?['"\`]`);
  const usedIn = files.filter(f => re.test(f.text)).map(f => f.file);
  return {
    declared_in: loc,
    dependency_type: direct,
    lock_file_scope: dev === null ? "unknown" : dev ? "development only (dev: true in the lock file)" : "production",
    optional,
    dependency_chain: chain || "unknown",
    imported_by_app_code: usedIn.length ? `yes, in ${usedIn.length} file(s): ${usedIn.slice(0, 5).join(", ")}` : "no (not imported directly by the app's own code)",
  };
}

async function ask(prompt) {
  const res = await fetch(`${OLLAMA}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: MODEL, stream: false, format: SCHEMA, options: OPTIONS,
      messages: [{ role: "system", content: SYSTEM }, { role: "user", content: prompt }] }),
  });
  if (!res.ok) throw new Error(`Ollama answered ${res.status}: ${await res.text()}`);
  const answer = JSON.parse((await res.json()).message.content);
  if (answer.state !== "not_affected") answer.justification = "none";
  return answer;
}

const csvCell = v => { const s = v === undefined || v === null ? "" : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

(async () => {
  // Check Ollama is running and the model is there; record the model's digest (its exact version)
  let tags;
  try { tags = await (await fetch(`${OLLAMA}/api/tags`)).json(); }
  catch { console.error(`STOP: Ollama is not running at ${OLLAMA}. Start it with: ollama serve`); process.exit(1); }
  const model = (tags.models || []).find(m => m.name === MODEL || m.model === MODEL);
  if (!model) { console.error(`STOP: model ${MODEL} not found. Run: ollama pull ${MODEL}`); process.exit(1); }
  const { version: ollamaVersion } = await (await fetch(`${OLLAMA}/api/version`)).json();
  console.log(`Ollama ${ollamaVersion}, model ${MODEL} (digest ${model.digest.slice(0, 12)}), options ${JSON.stringify(OPTIONS)}`);

  const { repos } = read(path.join(ROOT, "testset.json"));
  for (const repo of repos) {
    const dir = path.join(OUT, repo.name), repoDir = path.join(REPOS, repo.name);
    const ranked = read(path.join(dir, "vulnerabilities-step2.vex.cdx.json"));
    const llmFile = path.join(dir, "llm.json");
    const old = fs.existsSync(llmFile) ? read(llmFile) : { results: [] };
    const cache = new Map(old.model && old.model.digest === model.digest ? old.results.map(r => [r.prompt_sha256, r.answer]) : []);

    // Load the repo's code, package.json files and lock files once
    const files = codeFiles(repoDir);
    const pkgJson = new Map(), lock = new Map();
    for (const c of ranked.components) {
      const loc = prop(c.properties || [], "syft:location:0:path");
      if (!loc || lock.has(loc)) continue;
      const f = path.join(repoDir, loc);
      lock.set(loc, /lock\.json$/.test(loc) && fs.existsSync(f) ? read(f) : null);
      const pj = path.join(path.dirname(f), "package.json");
      const key = path.dirname(loc).replace(/^\//, "") || ".";
      if (fs.existsSync(pj) && !pkgJson.has(key)) pkgJson.set(key, read(pj));
    }
    if (!pkgJson.has(".") && fs.existsSync(path.join(repoDir, "package.json"))) pkgJson.set(".", read(path.join(repoDir, "package.json")));
    const sbomComps = new Map(ranked.components.map(c => [c["bom-ref"], c]));
    const parentsOf = new Map();
    for (const d of ranked.dependencies || []) for (const child of d.dependsOn || []) parentsOf.set(child, [...(parentsOf.get(child) || []), d.ref]);

    console.log(`\n== ${repo.name}: ${ranked.vulnerabilities.length} vulnerabilities (${files.length} code files searched)`);
    const results = [];
    let fromCache = 0;
    for (const v of ranked.vulnerabilities) {
      const props = v.properties || [];
      const comp = sbomComps.get((v.affects || [{}])[0].ref) || {};
      const evidence = evidenceFor(repoDir, files, lock, pkgJson, comp, sbomComps, parentsOf);
      const facts = {
        application: repo.name,
        package: `${comp.name} ${comp.version}`,
        vulnerability: v.id,
        cve: (v.references || []).map(r => r.id).concat(v.id.startsWith("CVE-") ? [v.id] : []).join(", ") || "none",
        severity: v.ratings[0].severity,
        description: (v.description || "").slice(0, 600),
        fixed_version: v.recommendation,
        epss: prop(props, "fyp:epss:score") || "none",
        in_cisa_kev: prop(props, "fyp:kev:in_kev"),
        ...evidence,
      };
      const prompt = Object.entries(facts).map(([k, x]) => `${k}: ${x}`).join("\n");
      const key = sha256(SYSTEM + "\n" + prompt);
      let answer = cache.get(key);
      if (answer) fromCache++;
      else answer = await ask(prompt);
      results.push({ "bom-ref": v["bom-ref"], id: v.id, rank: Number(prop(props, "fyp:exploitability_rank")), facts, prompt_sha256: key, answer });
      if (process.stdout.isTTY) process.stdout.write(`\r  ${results.length}/${ranked.vulnerabilities.length} asked`);
    }
    fs.writeFileSync(llmFile, JSON.stringify({
      repo: repo.name, created: new Date().toISOString(),
      model: { name: MODEL, digest: model.digest, ollama_version: ollamaVersion, options: OPTIONS },
      system_prompt: SYSTEM, answer_schema: SCHEMA, results }, null, 2));

    // review.csv: my decisions go in the last 4 columns (keep the decisions I already made)
    const reviewFile = path.join(dir, "review.csv");
    const COLS = ["rank", "priority", "vulnerability", "package", "version", "dependency_type", "lock_file_scope", "imported_by_app_code",
      "llm_state", "llm_justification", "llm_reason", "decision", "final_state", "final_justification", "my_note"];
    const before = new Map();
    if (fs.existsSync(reviewFile)) {
      const { rows } = require("./review_csv").readReview(reviewFile);
      for (const r of rows) before.set(`${r.rank}|${r.vulnerability}`, r);
    }
    const lines = [COLS.join(",")];
    for (const r of results) {
      const v = ranked.vulnerabilities.find(x => x["bom-ref"] === r["bom-ref"]);
      const b = before.get(`${r.rank}|${r.id}`) || {};
      const row = { rank: r.rank, priority: prop(v.properties, "fyp:priority"), vulnerability: r.id,
        package: r.facts.package.split(" ")[0], version: r.facts.package.split(" ")[1],
        dependency_type: r.facts.dependency_type, lock_file_scope: r.facts.lock_file_scope, imported_by_app_code: r.facts.imported_by_app_code,
        llm_state: r.answer.state, llm_justification: r.answer.justification, llm_reason: r.answer.reason,
        decision: b.decision || "", final_state: b.final_state || "", final_justification: b.final_justification || "", my_note: b.my_note || "" };
      lines.push(COLS.map(c => csvCell(row[c])).join(","));
    }
    fs.writeFileSync(reviewFile, lines.join("\r\n") + "\r\n");
    const n = s => results.filter(r => r.answer.state === s).length;
    console.log(`\r  LLM suggestions: exploitable ${n("exploitable")} / not_affected ${n("not_affected")} / in_triage ${n("in_triage")}` +
      `  (${fromCache} reused from the last run)`);
  }
  console.log("\nStep 3a done: output/<repo>/llm.json and output/<repo>/review.csv - now review review.csv, then run: node step3_vex.js");
})();
