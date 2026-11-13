// Reads and writes review.csv (also copes with Excel: BOM, quotes, CRLF, ';' as separator).
const fs = require("fs");

const COLS = ["rank", "priority", "vulnerability", "package", "version", "dependency_type", "lock_file_scope", "imported_by_app_code",
  "llm_state", "llm_justification", "llm_reason", "decision", "final_state", "final_justification", "my_note"];

function parse(text, sep) {
  const rows = [];
  let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') q = false;
      else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === sep) { row.push(cell); cell = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); rows.push(row); row = []; cell = "";
    } else cell += ch;
  }
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  return rows.filter(r => r.some(c => c.trim() !== ""));
}

function readReview(file) {
  const text = fs.readFileSync(file, "utf8").replace(/^﻿/, "");
  const first = text.split(/\r?\n/)[0];
  const sep = (first.match(/;/g) || []).length > (first.match(/,/g) || []).length ? ";" : ",";
  const [head, ...body] = parse(text, sep);
  const cols = head.map(h => h.trim().toLowerCase());
  const rows = body.map(r => Object.fromEntries(cols.map((c, i) => [c, (r[i] || "").trim()])));
  return { cols, rows };
}

const cell = v => { const s = v === undefined || v === null ? "" : String(v); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
function writeReview(file, rows) {
  fs.writeFileSync(file, [COLS.join(","), ...rows.map(r => COLS.map(c => cell(r[c])).join(","))].join("\r\n") + "\r\n");
}

module.exports = { COLS, readReview, writeReview };
