// STEP 3 review - I check the LLM's suggestions in the terminal (no Excel needed).
// Shows one vulnerability at a time: the facts + the LLM's answer. I press:
//   a = agree   c = change (pick the right state and say why)   s = skip for now   q = save and quit
// By default it asks about P1 + P2 (the most likely to be exploited). To review every vulnerability: node review.js --all
// My answers are saved in output/<repo>/review.csv after every answer.
// Run: node review.js
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { readReview, writeReview } = require("./review_csv");

const ROOT = __dirname;
const ALL = process.argv.includes("--all");
const STATES = ["exploitable", "not_affected", "in_triage", "false_positive", "resolved"];
const JUSTIFICATIONS = ["code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment",
  "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"];

(async () => {
  // Read my typed answers one line at a time
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const lines = [], waiting = [];
  let ended = false;
  rl.on("line", l => (waiting.length ? waiting.shift()(l) : lines.push(l)));
  const stop = () => { console.log("\nStopped. Your answers so far are saved. Run node review.js again to continue."); process.exit(0); };
  rl.on("close", () => { ended = true; if (waiting.length) stop(); });
  rl.question = q => { process.stdout.write(q); return lines.length ? Promise.resolve(lines.shift()) : ended ? stop() : new Promise(r => waiting.push(r)); };
  const askChoice = async (q, list) => {
    for (;;) {
      const a = (await rl.question(q + "\n" + list.map((x, i) => `   ${i + 1} = ${x}`).join("\n") + "\n  Number: ")).trim();
      if (list[Number(a) - 1]) return list[Number(a) - 1];
      console.log("  Please type one of the numbers.");
    }
  };
  const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
  let quit = false, done = 0;
  for (const repo of repos) {
    if (quit) break;
    const file = path.join(ROOT, "output", repo.name, "review.csv");
    const { rows } = readReview(file);
    const todo = rows.filter(r => !r.decision && (ALL || /^P[12]/.test(r.priority)));
    console.log(`\n================ ${repo.name}: ${todo.length} to review ================`);
    for (const [i, r] of todo.entries()) {
      console.log(`\n--- ${repo.name} ${i + 1}/${todo.length}  |  rank ${r.rank}  |  ${r.priority}`);
      console.log(`  Vulnerability : ${r.vulnerability} in ${r.package} ${r.version}`);
      console.log(`  Dependency    : ${r.dependency_type}, ${r.lock_file_scope}`);
      console.log(`  Used by app   : ${r.imported_by_app_code}`);
      console.log(`  LLM says      : ${r.llm_state}${r.llm_justification && r.llm_justification !== "none" ? " (" + r.llm_justification + ")" : ""}`);
      console.log(`  LLM's reason  : ${r.llm_reason}`);
      let a;
      do a = (await rl.question("  [a] agree   [c] change   [s] skip   [q] save and quit : ")).trim().toLowerCase();
      while (!["a", "c", "s", "q"].includes(a));
      if (a === "q") { quit = true; break; }
      if (a === "s") continue;
      if (a === "a") {
        r.decision = "agree";
        r.my_note = (await rl.question("  Your note (optional, e.g. if the LLM's reason is wrong - press Enter to skip): ")).trim();
      } else {
        r.decision = "change";
        r.final_state = await askChoice("  What is the right state?", STATES);
        r.final_justification = r.final_state === "not_affected" ? await askChoice("  Why is it not affected?", JUSTIFICATIONS) : "";
        do r.my_note = (await rl.question("  Why? (required): ")).trim(); while (!r.my_note);
      }
      writeReview(file, rows);              // save after every answer, so nothing is lost
      done++;
    }
    const left = rows.filter(r => !r.decision).length;
    console.log(`  ${repo.name}: ${rows.length - left} of ${rows.length} reviewed`);
  }
  rl.close();
  console.log(`\nSaved ${done} answer(s). Next: node step3_vex.js`);
})();
