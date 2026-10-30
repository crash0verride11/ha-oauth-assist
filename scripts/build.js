#!/usr/bin/env node
/**
 * OAuth Assist for HA - reproducible store packages
 *
 *   node scripts/build.js [git-ref]      (default: HEAD)
 *
 * Writes dist/oauth-assist-for-ha-<version>-chrome.zip and -firefox.zip and
 * prints their SHA-256. Packages are built from the committed tree at
 * <git-ref>, never the working directory, so:
 *  - anyone can rebuild a store package from a tag and get identical bytes;
 *  - untracked files (local provider profiles, examples/) can't leak in.
 *
 * Determinism: entries are sorted, stored uncompressed (deflate output varies
 * by zlib version), and stamped with a fixed date. No dependencies beyond
 * Node and git.
 *
 * Chrome MV3 requires background.service_worker and Firefox MV3 requires
 * background.scripts, and each rejects the other's key, so the Firefox
 * package carries manifest.firefox.json renamed to manifest.json.
 */

const { execFileSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SRC = "extension";
const DIST = path.join(ROOT, "dist");
const NAME = "oauth-assist-for-ha";

function git(args, opts = {}) {
  return execFileSync("git", args, { cwd: ROOT, maxBuffer: 64 * 1024 * 1024, ...opts });
}

/** { "relative/path": Buffer } for every file under extension/ at `ref`. */
function readTree(ref) {
  const names = git(["ls-tree", "-r", "-z", "--name-only", ref, "--", `${SRC}/`])
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  if (!names.length) throw new Error(`No files under ${SRC}/ at ${ref}.`);
  const files = {};
  for (const name of names) {
    files[name.slice(SRC.length + 1)] = git(["show", `${ref}:${name}`]);
  }
  return files;
}

function packageFiles(files, browser) {
  const out = {};
  for (const [name, data] of Object.entries(files)) {
    if (name === "manifest.json" || name === "manifest.firefox.json") continue;
    out[name] = data;
  }
  out["manifest.json"] = files[browser === "firefox" ? "manifest.firefox.json" : "manifest.json"];
  return out;
}

/**
 * The two manifests are maintained by hand; refuse to package if they drift
 * anywhere except the keys that must differ between browsers.
 */
function checkManifests(files) {
  if (!files["manifest.json"] || !files["manifest.firefox.json"]) {
    throw new Error("Both manifest.json and manifest.firefox.json are required.");
  }
  const chrome = JSON.parse(files["manifest.json"]);
  const firefox = JSON.parse(files["manifest.firefox.json"]);
  const strip = (m) => {
    const { background, browser_specific_settings, ...rest } = m;
    return JSON.stringify(rest);
  };
  if (strip(chrome) !== strip(firefox)) {
    throw new Error(
      "manifest.json and manifest.firefox.json differ outside background / browser_specific_settings.",
    );
  }
  if (!chrome.background?.service_worker || !firefox.background?.scripts) {
    throw new Error("Expected background.service_worker (Chrome) and background.scripts (Firefox).");
  }
  // Firefox has no importScripts in background.scripts; shared.js must load first.
  if (firefox.background.scripts[0] !== "shared.js") {
    throw new Error('manifest.firefox.json background.scripts must start with "shared.js".');
  }
  if (!/^\d+(\.\d+){0,3}$/.test(chrome.version)) {
    throw new Error(`Invalid version ${JSON.stringify(chrome.version)}.`);
  }
  // The Chrome Web Store rejects uploads whose description exceeds 132 characters.
  if (typeof chrome.description === "string" && chrome.description.length > 132) {
    throw new Error(`description is ${chrome.description.length} characters; the Chrome Web Store allows 132.`);
  }
  return chrome.version;
}

// ---------------------------------------------------------------------------
// Minimal deterministic zip writer (stored entries only).
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// 1980-01-01 00:00:00, the earliest DOS timestamp.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;

function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const name of Object.keys(files).sort()) {
    const data = files[name];
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // flags: UTF-8 names
    local.writeUInt16LE(0, 8); // method: stored
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra length
    locals.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    // extra, comment, disk, internal attrs, external attrs: all zero
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);

    offset += local.length + nameBuf.length + data.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  const count = Object.keys(files).length;
  end.writeUInt16LE(count, 8);
  end.writeUInt16LE(count, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

// ---------------------------------------------------------------------------

function main() {
  const ref = process.argv[2] || "HEAD";
  const commit = git(["rev-parse", "--verify", `${ref}^{commit}`]).toString().trim();

  const dirty = git(["status", "--porcelain", "--", `${SRC}/`]).toString().trim();
  if (dirty && ref === "HEAD") {
    console.warn(`Note: ${SRC}/ has uncommitted changes; they are NOT included.\n`);
  }

  const files = readTree(commit);
  const version = checkManifests(files);

  fs.mkdirSync(DIST, { recursive: true });
  console.log(`${NAME} ${version} from ${commit.slice(0, 12)}\n`);
  for (const browser of ["chrome", "firefox"]) {
    const pkg = packageFiles(files, browser);
    const buf = zip(pkg);
    const out = path.join(DIST, `${NAME}-${version}-${browser}.zip`);
    fs.writeFileSync(out, buf);
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    console.log(`${sha}  ${path.relative(ROOT, out)}  (${Object.keys(pkg).length} files)`);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`Build failed: ${e.message}`);
    process.exit(1);
  }
}

module.exports = { zip, crc32, packageFiles, checkManifests };
