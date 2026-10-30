// Tests for scripts/build.js: zip writer, CRC, manifest swap + drift check.
const path = require("path");
const zlib = require("zlib");
const B = require(path.join(__dirname, "..", "scripts", "build.js"));

let pass = 0, fail = 0;
function t(name, cond) {
  if (cond) { pass++; }
  else { fail++; console.log("FAIL:", name); }
}
function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}

// --- crc32 (standard check value) ---
t("crc32 check value", B.crc32(Buffer.from("123456789")) === 0xcbf43926);
t("crc32 empty", B.crc32(Buffer.alloc(0)) === 0);
if (zlib.crc32) {
  const buf = Buffer.from("OAuth Assist for HA ".repeat(100));
  t("crc32 matches zlib", B.crc32(buf) === zlib.crc32(buf));
}

// --- manifests ---
const base = {
  manifest_version: 3,
  name: "OAuth Assist for HA",
  version: "0.1.0",
  permissions: ["webNavigation", "tabs", "storage"],
};
const chromeM = { ...base, background: { service_worker: "background.js" } };
const firefoxM = {
  ...base,
  background: { scripts: ["shared.js", "background.js"] },
  browser_specific_settings: { gecko: { id: "x@y" } },
};
const files = (c, f) => ({
  "manifest.json": Buffer.from(JSON.stringify(c)),
  "manifest.firefox.json": Buffer.from(JSON.stringify(f)),
  "shared.js": Buffer.from("// shared"),
});
t("matching manifests pass", B.checkManifests(files(chromeM, firefoxM)) === "0.1.0");
t("version drift rejected", throws(() => B.checkManifests(files(chromeM, { ...firefoxM, version: "0.1.1" }))));
t("permission drift rejected", throws(() =>
  B.checkManifests(files(chromeM, { ...firefoxM, permissions: ["tabs"] }))));
t("missing firefox manifest rejected", throws(() =>
  B.checkManifests({ "manifest.json": Buffer.from(JSON.stringify(chromeM)) })));
t("shared.js must load first in firefox", throws(() =>
  B.checkManifests(files(chromeM, { ...firefoxM, background: { scripts: ["background.js", "shared.js"] } }))));
t("bad version rejected", throws(() =>
  B.checkManifests(files({ ...chromeM, version: "v1" }, { ...firefoxM, version: "v1" }))));
const desc = (n) => "x".repeat(n);
t("132-char description passes", !throws(() =>
  B.checkManifests(files({ ...chromeM, description: desc(132) }, { ...firefoxM, description: desc(132) }))));
t("133-char description rejected", throws(() =>
  B.checkManifests(files({ ...chromeM, description: desc(133) }, { ...firefoxM, description: desc(133) }))));

const fx = B.packageFiles(files(chromeM, firefoxM), "firefox");
t("firefox gets firefox manifest", JSON.parse(fx["manifest.json"]).background.scripts);
t("firefox drops manifest.firefox.json", !("manifest.firefox.json" in fx));
const cr = B.packageFiles(files(chromeM, firefoxM), "chrome");
t("chrome keeps chrome manifest", JSON.parse(cr["manifest.json"]).background.service_worker);
t("chrome drops manifest.firefox.json", !("manifest.firefox.json" in cr));

// --- zip: deterministic, order-independent, readable ---
const a = B.zip({ "b.txt": Buffer.from("two"), "a/x.txt": Buffer.from("one") });
const b = B.zip({ "a/x.txt": Buffer.from("one"), "b.txt": Buffer.from("two") });
t("zip deterministic + order independent", a.equals(b));

// Walk the central directory back out and check each entry.
function readZip(buf) {
  const end = buf.length - 22;
  t("end-of-central-dir signature", buf.readUInt32LE(end) === 0x06054b50);
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = {};
  for (let i = 0; i < count; i++) {
    const nameLen = buf.readUInt16LE(p + 28);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString("utf8");
    const crc = buf.readUInt32LE(p + 16);
    const size = buf.readUInt32LE(p + 20);
    const local = buf.readUInt32LE(p + 42);
    const localNameLen = buf.readUInt16LE(local + 26);
    const data = buf.slice(local + 30 + localNameLen, local + 30 + localNameLen + size);
    t(`crc ok for ${name}`, B.crc32(data) === crc);
    out[name] = data.toString("utf8");
    p += 46 + nameLen;
  }
  return out;
}
const entries = readZip(a);
t("zip round-trips", entries["a/x.txt"] === "one" && entries["b.txt"] === "two");
t("zip entries sorted", JSON.stringify(Object.keys(entries)) === JSON.stringify(["a/x.txt", "b.txt"]));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
