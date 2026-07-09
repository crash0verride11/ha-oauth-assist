// Test harness for shared.js validation + flow detection + background matching.
const fs = require("fs");
const vm = require("vm");
// vm.runInThisContext executes ONLY our own local extension scripts (trusted,
// non-module files that expect to run in a shared global scope) — safe here.
const load = (f) => vm.runInThisContext(fs.readFileSync(f, "utf8"), { filename: f });
const path = require("path");
const EXT = require("path").join(__dirname, "..", "extension");

// Minimal chrome stub so shared.js loads.
globalThis.chrome = { storage: { local: { get: async () => ({}) } } };
globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
load(path.join(EXT, "shared.js"));
const A = globalThis.OAuthAssist;

let pass = 0, fail = 0;
function t(name, cond) {
  if (cond) { pass++; }
  else { fail++; console.log("FAIL:", name); }
}

// --- any local profiles validate (profiles are untracked; may be absent) ---
const profileFiles = fs
  .readdirSync(path.join(EXT, "profiles"))
  .filter((f) => f.endsWith(".json") && !["profile.schema.json", "index.json"].includes(f));
for (const f of profileFiles) {
  const raw = JSON.parse(fs.readFileSync(path.join(EXT, "profiles", f), "utf8"));
  const r = A.validateProfile(raw);
  t(`${f} validates`, r.ok);
  if (!r.ok) console.log(r.errors);
}

// --- hostile / malformed profiles rejected ---
// Fictional provider fixture: a custom-scheme redirect plus an https callback,
// the same shape a real profile takes.
const acme = {
  schemaVersion: 1,
  id: "acme-app",
  name: "Acme App",
  loginOrigins: ["https://login.acme-app.com/*"],
  capture: [
    {
      type: "redirect",
      redirectPrefixes: ["com.acme.app://", "https://login.acme-app.com/ios/"],
    },
  ],
  state: { rule: "ha-jwt" },
};
t("fixture validates", A.validateProfile(acme).ok);
const variants = [
  ["missing id", { ...acme, id: undefined }],
  ["bad id chars", { ...acme, id: "Acme App!" }],
  ["wrong schemaVersion", { ...acme, schemaVersion: 2 }],
  ["http login origin", { ...acme, loginOrigins: ["http://login.acme-app.com/*"] }],
  ["non-array loginOrigins", { ...acme, loginOrigins: "https://x.com/*" }],
  ["empty capture", { ...acme, capture: [] }],
  ["unknown capture type", { ...acme, capture: [{ type: "initiation", redirectPrefixes: ["x://y"] }] }],
  ["http redirect prefix", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["http://evil.com/"] }] }],
  ["no-scheme prefix", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["evilprefix"] }] }],
  ["watch HA itself", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["https://my.home-assistant.io/redirect/oauth"] }] }],
  ["extension scheme", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["chrome-extension://abc/"] }] }],
  ["bad state rule", { ...acme, state: { rule: "forward-anywhere" } }],
  ["forward target smuggling", { ...acme, forwardUrl: "https://evil.com" }], // extra field: normalized copy must drop it
];
for (const [name, v] of variants) {
  const r = A.validateProfile(v);
  if (name === "forward target smuggling") {
    t(name, r.ok && !("forwardUrl" in r.profile));
  } else {
    t(name + " rejected", !r.ok);
  }
}

// --- isHomeAssistantFlow ---
function b64url(o) {
  return Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const haState = `${b64url({ alg: "HS256" })}.${b64url({ flow_id: "abc123" })}.sig`;
const nonHaState = `${b64url({ alg: "HS256" })}.${b64url({ sub: "user" })}.sig`;
t("HA JWT accepted", A.isHomeAssistantFlow(haState));
t("non-HA JWT rejected", !A.isHomeAssistantFlow(nonHaState));
t("random state rejected", !A.isHomeAssistantFlow("xyz"));
t("empty state rejected", !A.isHomeAssistantFlow(""));
t("null state rejected", !A.isHomeAssistantFlow(null));
// base64url payload (- and _ chars) — the original examples' plain atob would choke
const payloadWithUrlChars = { flow_id: "a", pad: "ÿþ???>>>" };
const jwt2 = `x.${b64url(payloadWithUrlChars)}.y`;
t("base64url payload accepted", A.isHomeAssistantFlow(jwt2));

// --- background matching flow (simulate) ---
const store = {
  "acme-app": { enabled: true, profile: A.validateProfile(acme).profile },
};
globalThis.chrome = {
  storage: {
    local: { get: async () => ({ profiles: store }), set: async (o) => { globalThis._stored = o; } },
    onChanged: { addListener: () => {} },
  },
  webNavigation: { onBeforeNavigate: { addListener: () => {} }, onErrorOccurred: { addListener: () => {} } },
  tabs: { onUpdated: { addListener: () => {} }, update: (tabId, o) => { globalThis._nav = o.url; } },
  action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
  runtime: { getURL: (p) => `chrome-extension://fake/${p}` },
};
load(path.join(EXT, "background.js"));

(async () => {
  // HA flow -> forwarded to pinned URL
  globalThis._nav = null;
  await handleRedirect(1, `com.acme.app://callback?code=SECRET123&state=${haState}`);
  t("HA flow forwarded", globalThis._nav && globalThis._nav.startsWith("https://my.home-assistant.io/redirect/oauth?"));
  t("code in forward", globalThis._nav.includes("code=SECRET123"));

  // Non-HA state -> capture page (different URL so de-dupe doesn't eat it)
  globalThis._nav = null;
  await handleRedirect(1, `com.acme.app://callback?code=OTHER&state=${nonHaState}`);
  t("non-HA goes to capture", globalThis._nav === "chrome-extension://fake/capture.html");
  t("capture stored", globalThis._stored?.lastCapture?.code === "OTHER");

  // Unwatched URL -> ignored
  globalThis._nav = null;
  await handleRedirect(1, "https://example.com/?code=X&state=" + haState);
  t("unwatched ignored", globalThis._nav === null);

  // iOS https prefix matched
  globalThis._nav = null;
  await handleRedirect(1, `https://login.acme-app.com/ios/cb?code=IOS1&state=${haState}`);
  t("https prefix forwarded", globalThis._nav && globalThis._nav.includes("code=IOS1"));

  // De-dupe: same URL again within 5s -> ignored
  globalThis._nav = null;
  await handleRedirect(1, `https://login.acme-app.com/ios/cb?code=IOS1&state=${haState}`);
  t("duplicate suppressed", globalThis._nav === null);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
