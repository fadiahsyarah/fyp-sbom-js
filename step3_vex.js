// STEP 3b - turn my reviewed decisions into a CycloneDX VEX file, one per repo.
// VEX = Vulnerability Exploitability eXchange: for each vulnerability, does it really affect this app?
//   Input : output/<repo>/vulnerabilities-step2.vex.cdx.json, sbom-step1.cdx.json, llm.json, review.csv (with my decisions from review.js)
//   Rule  : every P1 + P2 must be reviewed by me; any row I did not review uses the LLM suggestion, marked "LLM only - not reviewed"
//   Output: output/<repo>/vulnerabilities-step3.vex.cdx.json (CycloneDX 1.7 VEX, linked to sbom-step1.cdx.json)
// Run: node step3_vex.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { readReview } = require("./review_csv");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const REVIEWER = "Fadiah (github.com/fadiahsyarah)";       // the person who reviews and signs off
const read = f => JSON.parse(fs.readFileSync(f, "utf8"));
const prop = (props, name) => (props.find(p => p.name === name) || {}).value;
const P = (name, value) => (value === null || value === undefined || value === "" ? null : { name, value: String(value) });

const STATES = ["exploitable", "not_affected", "in_triage", "false_positive", "resolved"];
const JUSTIFICATIONS = ["code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment",
  "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"];

const now = new Date().toISOString();
const errors = [];
const { repos } = read(path.join(ROOT, "testset.json"));
const summary = [];

for (const repo of repos) {
  const dir = path.join(OUT, repo.name);
  const ranked = read(path.join(dir, "vulnerabilities-step2.vex.cdx.json"));
  const sbom = read(path.join(dir, "sbom-step1.cdx.json"));
  const llm = read(path.join(dir, "llm.json"));
  const { rows } = readReview(path.join(dir, "review.csv"));
  const review = new Map(rows.map(r => [`${r.rank}|${r.vulnerability}`, r]));
  const llmById = new Map(llm.results.map(r => [r["bom-ref"], r]));
  const oldVex = fs.existsSync(path.join(dir, "vulnerabilities-step3.vex.cdx.json")) ? read(path.join(dir, "vulnerabilities-step3.vex.cdx.json")) : null;
  const firstIssued = new Map(((oldVex && oldVex.vulnerabilities) || []).map(v => [`${v.id}|${(v.affects || [{}])[0].ref}`, v.analysis && v.analysis.firstIssued]));
  // BOM-Link: points from this VEX to the exact component inside sbom-step1.cdx.json
  const sbomSerial = sbom.serialNumber.replace("urn:uuid:", "");
  const bomLink = ref => `urn:cdx:${sbomSerial}/${sbom.version || 1}#${encodeURIComponent(ref)}`;

  let reviewed = 0, agreed = 0, changed = 0;
  const vulnerabilities = ranked.vulnerabilities.map(v => {
    const props = v.properties || [];
    const rank = prop(props, "fyp:exploitability_rank");
    const ai = llmById.get(v["bom-ref"]);
    const where = `${repo.name} rank ${rank} ${v.id}`;
    if (!ai) { errors.push(`${where}: no LLM answer - run node step3_llm.js first`); return null; }
    const r = review.get(`${rank}|${v.id}`) || {};
    const decision = (r.decision || "").toLowerCase();

    // My decision decides the final state; the LLM's suggestion is kept as a property
    let state, justification, detail, decisionLabel;
    if (decision === "agree") {
      state = ai.answer.state; justification = ai.answer.justification; detail = r.my_note || ai.answer.reason;
      decisionLabel = "agreed with LLM"; reviewed++; agreed++;
    } else if (decision === "change") {
      state = (r.final_state || "").toLowerCase(); justification = (r.final_justification || "").toLowerCase();
      detail = r.my_note;
      decisionLabel = "changed by reviewer"; reviewed++; changed++;
      if (!STATES.includes(state)) errors.push(`${where}: decision is "change" but final_state "${r.final_state}" is not one of ${STATES.join(", ")}`);
      if (!detail) errors.push(`${where}: decision is "change" - write why in my_note`);
    } else if (decision === "") {
      // Not checked by me: the LLM's suggestion is used, and the VEX says clearly that no person checked it
      state = ai.answer.state; justification = ai.answer.justification;
      detail = `LLM suggestion, not reviewed by a person: ${ai.answer.reason}`;
      decisionLabel = "LLM only - not reviewed";
    } else errors.push(`${where}: decision must be agree, change or empty, not "${r.decision}"`);

    if (state === "not_affected" && !JUSTIFICATIONS.includes(justification))
      errors.push(`${where}: not_affected needs a justification (one of ${JUSTIFICATIONS.join(", ")})`);
    const fixes = /^Upgrade /.test(v.recommendation || "");
    const analysis = {
      state,
      ...(state === "not_affected" ? { justification } : {}),
      ...(state === "exploitable" || state === "in_triage" ? { response: [fixes ? "update" : "can_not_fix"] } : {}),
      detail,
      firstIssued: firstIssued.get(`${v.id}|${bomLink((v.affects || [{}])[0].ref)}`) || now,
      lastUpdated: now,
    };
    const out = {
      "bom-ref": v["bom-ref"], id: v.id, source: v.source,
      ...(v.references ? { references: v.references } : {}),
      ratings: v.ratings, recommendation: v.recommendation,
      analysis,
      affects: (v.affects || []).map(a => ({ ref: bomLink(a.ref), versions: a.versions })),
      properties: [
        P("fyp:exploitability_rank", rank), P("fyp:priority", prop(props, "fyp:priority")),
        P("fyp:epss:score", prop(props, "fyp:epss:score")), P("fyp:kev:in_kev", prop(props, "fyp:kev:in_kev")),
        P("fyp:llm:state", ai.answer.state), P("fyp:llm:justification", ai.answer.justification), P("fyp:llm:reason", ai.answer.reason),
        P("fyp:llm:prompt_sha256", ai.prompt_sha256),
        P("fyp:review:decision", decisionLabel), P("fyp:review:by", decision ? REVIEWER : null),
      ].filter(Boolean),
    };
    return out;
  }).filter(Boolean);

  const total = ranked.vulnerabilities.length;
  const vex = {
    $schema: "http://cyclonedx.org/schema/bom-1.7.schema.json",
    bomFormat: "CycloneDX", specVersion: "1.7",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1,
    metadata: {
      timestamp: now,
      authors: [{ name: REVIEWER }],
      tools: { components: [
        { type: "application", name: "ollama", version: llm.model.ollama_version },
        { type: "machine-learning-model", name: llm.model.name, version: llm.model.digest },
        { type: "application", name: "fyp-sbom-js step3_llm.js + step3_vex.js", version: "1.0" },
      ] },
      component: ranked.metadata.component,
      properties: [
        P("fyp:vex:applies_to_sbom", `urn:cdx:${sbomSerial}/${sbom.version || 1}`),
        P("fyp:llm:model", llm.model.name), P("fyp:llm:model_digest", llm.model.digest),
        P("fyp:llm:options", JSON.stringify(llm.model.options)),
        P("fyp:llm:role", "suggests a state; the reviewer checks it (all P1 + P2 at least)"),
        P("fyp:signoff:by", REVIEWER), P("fyp:signoff:date", now),
        P("fyp:signoff:status", reviewed === total ? "complete - every vulnerability reviewed"
          : `${reviewed} of ${total} reviewed by me (all P1 + P2 first); the other ${total - reviewed} use the LLM suggestion, marked "LLM only - not reviewed"`),
        P("fyp:review:agreed_with_llm", agreed), P("fyp:review:changed", changed), P("fyp:review:llm_only", total - reviewed),
      ].filter(Boolean),
    },
    externalReferences: [{ type: "bom", url: `urn:cdx:${sbomSerial}/${sbom.version || 1}`, comment: `The SBOM this VEX is about: output/${repo.name}/sbom-step1.cdx.json` }],
    vulnerabilities,
  };
  const count = s => vulnerabilities.filter(v => v.analysis.state === s).length;
  const p12 = ranked.vulnerabilities.filter(v => /^P[12]/.test(prop(v.properties || [], "fyp:priority")));
  const p12left = p12.filter(v => !((review.get(`${prop(v.properties, "fyp:exploitability_rank")}|${v.id}`) || {}).decision)).length;
  if (p12left) errors.push(`${repo.name}: ${p12left} of the ${p12.length} P1/P2 vulnerabilities are not reviewed yet - run node review.js`);
  summary.push({ repo: repo.name, vex, total, reviewed, agreed, changed, counts: STATES.map(s => `${s} ${count(s)}`).join(" / ") });
}

if (errors.length) {
  console.error(`STOP: ${errors.length} problem(s) in review.csv - nothing was written. Fix these and run again:`);
  for (const e of errors.slice(0, 30)) console.error("  - " + e);
  process.exit(1);
}
for (const s of summary) {
  fs.writeFileSync(path.join(OUT, s.repo, "vulnerabilities-step3.vex.cdx.json"), JSON.stringify(s.vex, null, 2));
  console.log(`== ${s.repo}: reviewed by me ${s.reviewed}/${s.total} (agreed ${s.agreed}, changed ${s.changed}), LLM only ${s.total - s.reviewed} | ${s.counts}`);
}
console.log("\nStep 3b done: output/<repo>/vulnerabilities-step3.vex.cdx.json - now sign everything: node sign.js");
