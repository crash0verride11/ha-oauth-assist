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
  ["headers not an array", { ...acme, requestHeaders: { header: "User-Agent" } }],
  ["headers empty", { ...acme, requestHeaders: [] }],
  ["header Cookie", { ...acme, requestHeaders: [{ header: "Cookie", operation: "set", value: "sid=1" }] }],
  ["header Authorization", { ...acme, requestHeaders: [{ header: "Authorization", operation: "set", value: "Bearer x" }] }],
  ["header Origin removed", { ...acme, requestHeaders: [{ header: "Origin", operation: "remove" }] }],
  ["header lookalike", { ...acme, requestHeaders: [{ header: "User-Agent-X", operation: "remove" }] }],
  ["header op append", { ...acme, requestHeaders: [{ header: "User-Agent", operation: "append", value: "x" }] }],
  ["header set no value", { ...acme, requestHeaders: [{ header: "User-Agent", operation: "set" }] }],
  ["header set empty value", { ...acme, requestHeaders: [{ header: "User-Agent", operation: "set", value: "" }] }],
  ["header CRLF injection", { ...acme, requestHeaders: [{ header: "User-Agent", operation: "set", value: "x\r\nCookie: a=b" }] }],
  ["header value too long", { ...acme, requestHeaders: [{ header: "User-Agent", operation: "set", value: "x".repeat(513) }] }],
  ["header remove with value", { ...acme, requestHeaders: [{ header: "Sec-CH-UA", operation: "remove", value: "x" }] }],
  ["header duplicate", { ...acme, requestHeaders: [
    { header: "User-Agent", operation: "set", value: "a" },
    { header: "user-agent", operation: "remove" },
  ] }],
];
for (const [name, v] of variants) {
  const r = A.validateProfile(v);
  if (name === "forward target smuggling") {
    t(name, r.ok && !("forwardUrl" in r.profile));
  } else {
    t(name + " rejected", !r.ok);
  }
}

// --- requestHeaders validation + rule building ---
const MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15";
const acmeMobile = {
  ...acme,
  id: "acme-mobile",
  loginOrigins: ["https://login.acme-app.com/*", "https://*.acme-idp.com/*"],
  requestHeaders: [
    { header: "User-Agent", operation: "set", value: MOBILE_UA },
    { header: "Sec-CH-UA", operation: "remove" },
    { header: "sec-ch-ua-platform", operation: "remove" },
    { header: "Sec-CH-UA-Full-Version-List", operation: "remove" },
  ],
};
const rMobile = A.validateProfile(acmeMobile);
t("requestHeaders profile validates", rMobile.ok);
t("requestHeaders kept in normalized copy", rMobile.ok && rMobile.profile.requestHeaders.length === 4);
t("no requestHeaders key when absent", !("requestHeaders" in A.validateProfile(acme).profile));
const smuggled = A.validateProfile({
  ...acme,
  requestHeaders: [{ header: "User-Agent", operation: "set", value: "x", extra: "y" }],
});
t("header op extra fields dropped", smuggled.ok && !("extra" in smuggled.profile.requestHeaders[0]));

t("host from exact origin", A.loginOriginHost("https://login.acme-app.com/*") === "login.acme-app.com");
t("host from wildcard origin", A.loginOriginHost("https://*.acme-idp.com/*") === "acme-idp.com");
t("host lowercased", A.loginOriginHost("https://Login.Acme-App.com/path/*") === "login.acme-app.com");

const rules = A.buildHeaderRules([
  A.validateProfile(acme).profile, // no requestHeaders -> no rule
  rMobile.profile,
  A.validateProfile({ ...acmeMobile, id: "acme-any", loginOrigins: ["https://*/*"] }).profile,
]);
t("one rule per opted-in profile", rules.length === 1);
t("rule ids start at 1", rules[0].id === 1);
t("rule is modifyHeaders", rules[0].action.type === "modifyHeaders");
t("rule scoped to login hosts", JSON.stringify(rules[0].condition.requestDomains) === JSON.stringify(["login.acme-app.com", "acme-idp.com"]));
t("rule includes main_frame", rules[0].condition.resourceTypes.includes("main_frame"));
t("rule sets UA", rules[0].action.requestHeaders[0].value === MOBILE_UA);
t("all-hosts origin gets no rule", !rules.some((r) => r.condition.requestDomains.includes("*")));
const twoRules = A.buildHeaderRules([rMobile.profile, { ...rMobile.profile, id: "acme-2" }]);
t("rule ids unique", twoRules.length === 2 && twoRules[0].id !== twoRules[1].id);

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
let dynamicRules = [{ id: 7, action: { type: "block" }, condition: {} }]; // stale leftover
let grantedOrigins = new Set(["https://login.acme-app.com/*"]);
const listeners = {};
const listen = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
globalThis.chrome = {
  storage: {
    local: {
      get: async () => ({ profiles: store }),
      set: async (o) => { globalThis._stored = o; },
    },
    onChanged: listen("storage"),
  },
  webNavigation: { onBeforeNavigate: { addListener: () => {} }, onErrorOccurred: { addListener: () => {} } },
  tabs: { onUpdated: { addListener: () => {} }, update: (tabId, o) => { globalThis._nav = o.url; } },
  action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
  runtime: {
    getURL: (p) => `chrome-extension://fake/${p}`,
    onInstalled: listen("installed"),
    onStartup: listen("startup"),
  },
  permissions: {
    contains: async ({ origins }) => origins.every((o) => grantedOrigins.has(o)),
  },
  declarativeNetRequest: {
    getDynamicRules: async () => dynamicRules,
    updateDynamicRules: async ({ removeRuleIds, addRules }) => {
      dynamicRules = dynamicRules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules);
    },
  },
};
// Packaged presets served to loadPresets() via fetch.
let packaged = {};
globalThis.fetch = async (url) => {
  const file = url.replace("chrome-extension://fake/profiles/", "");
  if (!(file in packaged)) throw new Error(`404 ${file}`);
  return { json: async () => packaged[file] };
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

  // --- header rule sync ---
  await syncHeaderRules();
  t("stale dynamic rules removed", !dynamicRules.some((r) => r.id === 7));
  t("no rules without requestHeaders", dynamicRules.length === 0);

  store["acme-mobile"] = { enabled: true, profile: rMobile.profile };
  listeners.storage({ profiles: {} }, "local");
  await headerSync;
  t("storage change installs rule", dynamicRules.length === 1 && dynamicRules[0].action.requestHeaders[0].value === MOBILE_UA);

  store["acme-mobile"].enabled = false;
  // Overlapping syncs must not collide on rule ids.
  syncHeaderRules();
  store["acme-mobile"].enabled = true;
  await syncHeaderRules();
  t("serialized syncs leave one rule", dynamicRules.length === 1);

  store["acme-mobile"].enabled = false;
  await syncHeaderRules();
  t("disabling removes rule", dynamicRules.length === 0);
  delete store["acme-mobile"];

  // --- bundled preset refresh on update ---
  const oldPreset = A.validateProfile({ ...acme, id: "acme-bundled" }).profile;
  const newPreset = A.validateProfile({ ...acmeMobile, id: "acme-bundled", loginOrigins: ["https://login.acme-app.com/*"] }).profile;
  store["acme-bundled"] = { enabled: true, source: "bundled", profile: oldPreset };
  store["acme-imported"] = { enabled: true, source: "imported", profile: A.validateProfile({ ...acme, id: "acme-imported" }).profile };
  packaged = {
    "index.json": { presets: ["acme-bundled.json", "missing.json"] },
    "acme-bundled.json": { ...acmeMobile, id: "acme-bundled", loginOrigins: ["https://login.acme-app.com/*"] },
  };
  globalThis._stored = null;
  await listeners.installed({ reason: "update" });
  const refreshed = globalThis._stored?.profiles?.["acme-bundled"];
  t("bundled snapshot refreshed", refreshed && JSON.stringify(refreshed.profile) === JSON.stringify(newPreset));
  t("refreshed stays enabled when origins granted", refreshed?.enabled === true);
  t("imported profile untouched", !globalThis._stored.profiles["acme-imported"].profile.requestHeaders);

  // New preset version needs an origin the user hasn't granted -> disabled.
  store["acme-bundled"] = { enabled: true, source: "bundled", profile: oldPreset };
  packaged["acme-bundled.json"] = { ...acmeMobile, id: "acme-bundled" }; // adds *.acme-idp.com
  await listeners.installed({ reason: "update" });
  t("refresh needing new origin disables", store["acme-bundled"].enabled === false);

  // Unchanged preset -> no write.
  globalThis._stored = null;
  await listeners.installed({ reason: "update" });
  t("unchanged preset not rewritten", globalThis._stored === null);

  // Fresh install doesn't refresh (nothing stored yet), but still syncs.
  dynamicRules = [{ id: 9, action: { type: "block" }, condition: {} }];
  await listeners.installed({ reason: "install" });
  await headerSync;
  t("install syncs rules", !dynamicRules.some((r) => r.id === 9));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
