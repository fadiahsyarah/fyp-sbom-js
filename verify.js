// VERIFY - anyone can run this (also runs automatically on GitHub Actions after every push).
// Checks that nothing was changed after I signed it:
//   1. the frozen KEV + EPSS files still match the SHA-256 in manifest.json
//   2. every output file matches its SHA-256 and my Ed25519 signature (public key: keys/fadiah-ed25519.pub.pem)
//   3. there are no unsigned files in the output folders
// Run: node verify.js      (exit code 0 = all OK, 1 = something changed)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const sha256 = buf => crypto.createHash("sha256").update(buf).digest("hex");
let bad = 0;
const ok = (good, msg) => { console.log(`  ${good ? "OK  " : "FAIL"} ${msg}`); if (!good) bad++; };

// 1. Frozen KEV + EPSS snapshot
console.log("Frozen KEV + EPSS snapshot");
const snap = path.join(ROOT, "kev-epss-snapshot", "2026-10-29");
const manifest = JSON.parse(fs.readFileSync(path.join(snap, "manifest.json"), "utf8"));
for (const k of ["kev", "epss"]) ok(sha256(fs.readFileSync(path.join(snap, manifest[k].file))) === manifest[k].sha256, `${manifest[k].file} SHA-256`);

// 2 + 3. Signed output files
const publicKey = crypto.createPublicKey(fs.readFileSync(path.join(ROOT, "keys", "fadiah-ed25519.pub.pem")));
console.log(`Public key fingerprint (SHA-256): ${sha256(publicKey.export({ type: "spki", format: "der" }))}`);
const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
for (const repo of repos) {
  const dir = path.join(ROOT, "output", repo.name);
  console.log(`${repo.name}`);
  const sigFile = path.join(dir, "signatures.json");
  if (!fs.existsSync(sigFile)) { ok(false, "signatures.json is missing"); continue; }
  const sigs = JSON.parse(fs.readFileSync(sigFile, "utf8"));
  const listed = new Set(sigs.files.map(f => f.file));
  for (const f of sigs.files) {
    const p = path.join(dir, f.file);
    if (!fs.existsSync(p)) { ok(false, `${f.file} is missing`); continue; }
    const buf = fs.readFileSync(p);
    ok(sha256(buf) === f.sha256 && crypto.verify(null, buf, publicKey, Buffer.from(f.signature, "base64")),
      `${f.file} signed by ${sigs.signed_by} on ${sigs.signed_at.slice(0, 10)}`);
  }
  for (const f of fs.readdirSync(dir)) if (f !== "signatures.json" && !listed.has(f)) ok(false, `${f} is not signed`);
}
console.log(bad ? `\n${bad} check(s) FAILED - a file was changed after it was signed.` : "\nAll checks passed.");
process.exit(bad ? 1 : 0);
