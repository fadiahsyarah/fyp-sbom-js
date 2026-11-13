// STEP 3c - sign every output file (SBOM, scan, ranking, LLM answers, my review, VEX) with my private key.
// A signature proves the file was made/approved by me and has not been changed since.
//   Private key: ~/.fyp-keys/fadiah-ed25519.pem   (stays on my laptop - NEVER upload it)
//   Public key : keys/fadiah-ed25519.pub.pem      (on GitHub, anyone can use it to check my signatures)
//   Output     : output/<repo>/signatures.json
// Run: node sign.js        Check: node verify.js
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const OUT = path.join(ROOT, "output");
const SIGNER = "Fadiah (github.com/fadiahsyarah)";
const PRIVATE = path.join(os.homedir(), ".fyp-keys", "fadiah-ed25519.pem");
const PUBLIC = path.join(ROOT, "keys", "fadiah-ed25519.pub.pem");
const sha256 = buf => crypto.createHash("sha256").update(buf).digest("hex");

// 1. Make my key pair the first time only
if (!fs.existsSync(PRIVATE)) {
  if (fs.existsSync(PUBLIC)) {
    console.error(`STOP: ${PUBLIC} exists but the private key ${PRIVATE} is missing. Copy your private key back - do not make a new one.`);
    process.exit(1);
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.mkdirSync(path.dirname(PRIVATE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(PRIVATE, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.mkdirSync(path.dirname(PUBLIC), { recursive: true });
  fs.writeFileSync(PUBLIC, publicKey.export({ type: "spki", format: "pem" }));
  console.log(`New key pair made. Private: ${PRIVATE} (keep it secret, back it up)  Public: keys/fadiah-ed25519.pub.pem`);
}
const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE));
const publicPem = fs.readFileSync(PUBLIC);
if (crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }) !== publicPem.toString())
  { console.error("STOP: the private key does not match keys/fadiah-ed25519.pub.pem"); process.exit(1); }
const fingerprint = sha256(crypto.createPublicKey(publicPem).export({ type: "spki", format: "der" }));
console.log(`Public key fingerprint (SHA-256): ${fingerprint}`);

// 2. Sign every file in each repo's output folder
const { repos } = JSON.parse(fs.readFileSync(path.join(ROOT, "testset.json"), "utf8"));
for (const repo of repos) {
  const dir = path.join(OUT, repo.name);
  const files = fs.readdirSync(dir).filter(f => f !== "signatures.json").sort();
  const signed = files.map(file => {
    const buf = fs.readFileSync(path.join(dir, file));
    return { file, sha256: sha256(buf), signature: crypto.sign(null, buf, privateKey).toString("base64") };
  });
  fs.writeFileSync(path.join(dir, "signatures.json"), JSON.stringify({
    signed_by: SIGNER, signed_at: new Date().toISOString(), algorithm: "Ed25519",
    public_key: "keys/fadiah-ed25519.pub.pem", public_key_sha256: fingerprint, files: signed }, null, 2));
  console.log(`== ${repo.name}: signed ${signed.map(s => s.file).join(", ")}`);
}
console.log("\nStep 3c done: output/<repo>/signatures.json - check with: node verify.js");
