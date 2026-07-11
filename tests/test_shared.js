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
  ["unknown schemaVersion", { ...acme, schemaVersion: 3 }],
  ["http login origin", { ...acme, loginOrigins: ["http://login.acme-app.com/*"] }],
  ["non-array loginOrigins", { ...acme, loginOrigins: "https://x.com/*" }],
  ["empty capture", { ...acme, capture: [] }],
  ["unknown capture type", { ...acme, capture: [{ type: "sideload", redirectPrefixes: ["x://y"] }] }],
  ["http redirect prefix", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["http://evil.com/"] }] }],
  ["no-scheme prefix", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["evilprefix"] }] }],
  ["watch HA itself", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["https://my.home-assistant.io/redirect/oauth"] }] }],
  ["extension scheme", { ...acme, capture: [{ type: "redirect", redirectPrefixes: ["chrome-extension://abc/"] }] }],
  // A profile must never claim a sentinel: it would see every handoff.
  ...A.SENTINEL_URL_PREFIXES.map((p, i) => [
    `watch sentinel ${i}`,
    { ...acme, capture: [{ type: "redirect", redirectPrefixes: [p] }] },
  ]),
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

// --- v2: the initiation step and its cross-links ---
const acmeV2 = {
  ...acme,
  schemaVersion: 2,
  capture: [
    { type: "initiation", ttlSeconds: 600 },
    { type: "redirect", redirectPrefixes: ["com.acme.app://"] },
  ],
  state: { rule: "stashed" },
};
const v2 = A.validateProfile(acmeV2);
t("v2 initiation profile validates", v2.ok);
t("v2 keeps initiation first", v2.ok && v2.profile.capture[0].type === "initiation");
t("v2 ttl normalized", v2.ok && A.profileInitiation(v2.profile).ttlSeconds === 600);
t("v2 ttl defaults", (() => {
  const r = A.validateProfile({ ...acmeV2, capture: [{ type: "initiation" }, ...acmeV2.capture.slice(1)] });
  return r.ok && A.profileInitiation(r.profile).ttlSeconds === 600;
})());
t("v1 without initiation still validates", A.validateProfile(acme).ok);
t("v1 profile keeps its version", A.validateProfile(acme).profile.schemaVersion === 1);

const v2bad = [
  ["initiation under v1", { ...acmeV2, schemaVersion: 1 }],
  ["stashed without initiation", { ...acmeV2, capture: [acmeV2.capture[1]] }],
  ["initiation without stashed", { ...acmeV2, state: { rule: "ha-jwt" } }],
  ["stashed under v1", { ...acme, state: { rule: "stashed" } }],
  ["initiation not first", { ...acmeV2, capture: [acmeV2.capture[1], acmeV2.capture[0]] }],
  ["two initiation steps", { ...acmeV2, capture: [acmeV2.capture[0], acmeV2.capture[0], acmeV2.capture[1]] }],
  ["initiation only, no redirect", { ...acmeV2, capture: [acmeV2.capture[0]] }],
  ["ttl too low", { ...acmeV2, capture: [{ type: "initiation", ttlSeconds: 5 }, acmeV2.capture[1]] }],
  ["ttl too high", { ...acmeV2, capture: [{ type: "initiation", ttlSeconds: 99999 }, acmeV2.capture[1]] }],
  ["ttl not integer", { ...acmeV2, capture: [{ type: "initiation", ttlSeconds: 600.5 }, acmeV2.capture[1]] }],
  // The whole point of the step: it carries no URLs to point anywhere hostile.
  ["initiation smuggles a url", { ...acmeV2, capture: [{ type: "initiation", sentinel: "https://evil.com/" }, acmeV2.capture[1]] }],
];
for (const [name, v] of v2bad) t(name + " rejected", !A.validateProfile(v).ok);

// --- matchesLoginOrigin: the open-redirect guard on signin_url ---
const origins = ["https://login.acme-app.com/*"];
t("signin_url exact host", A.matchesLoginOrigin("https://login.acme-app.com/oauth?a=1", origins));
t("signin_url other host rejected", !A.matchesLoginOrigin("https://evil.com/oauth", origins));
t("signin_url http rejected", !A.matchesLoginOrigin("http://login.acme-app.com/oauth", origins));
t("signin_url prefix-confusion rejected", !A.matchesLoginOrigin("https://login.acme-app.com.evil.com/x", origins));
t("signin_url subdomain not implied", !A.matchesLoginOrigin("https://a.login.acme-app.com/x", origins));
t("signin_url garbage rejected", !A.matchesLoginOrigin("not a url", origins));
t("signin_url custom scheme rejected", !A.matchesLoginOrigin("com.acme.app://x", origins));
const wild = ["https://*.acme-app.com/*"];
t("wildcard matches subdomain", A.matchesLoginOrigin("https://login.acme-app.com/x", wild));
t("wildcard matches base", A.matchesLoginOrigin("https://acme-app.com/x", wild));
t("wildcard rejects suffix trick", !A.matchesLoginOrigin("https://evilacme-app.com/x", wild));


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

// --- parseSentinel: everything reaching it is attacker-controlled input ---
// Both sentinel forms (custom scheme and https) must behave identically.
t("two sentinel forms", A.SENTINEL_URL_PREFIXES.length === 2);
for (const SPX of A.SENTINEL_URL_PREFIXES) {
  const label = SPX.startsWith("https:") ? "https sentinel" : "scheme sentinel";
  const goodSentinel = `${SPX}acme-app#state_HA=${haState}&signin_url=${encodeURIComponent("https://login.acme-app.com/o")}`;
  const ps = A.parseSentinel(goodSentinel);
  t(`${label} parses`, ps && ps.profileId === "acme-app" && ps.stateHa === haState);
  t(`${label} signin_url decoded`, ps && ps.signinUrl === "https://login.acme-app.com/o");
  // Params must be in the fragment: a query string is transmitted when the
  // https form is navigated for real (extension absent).
  t(`${label} rejects query params`, A.parseSentinel(`${SPX}acme-app?state_HA=${haState}&signin_url=https://x/`) === null);
  t(`${label} needs both params`, A.parseSentinel(`${SPX}acme-app#state_HA=${haState}`) === null);
  t(`${label} bad profile id`, A.parseSentinel(`${SPX}../evil#state_HA=x&signin_url=y`) === null);
}
t("sentinel wrong host", A.parseSentinel("https://evil.com/initiate/acme-app#state_HA=x&signin_url=y") === null);
t("sentinel non-string", A.parseSentinel(null) === null);

// --- background matching flow (simulate) ---
const store = {
  "acme-app": { enabled: true, profile: A.validateProfile(acme).profile },
  "acme-enc": {
    enabled: true,
    profile: A.validateProfile({
      ...acmeV2,
      id: "acme-enc",
      capture: [
        { type: "initiation", ttlSeconds: 600 },
        { type: "redirect", redirectPrefixes: ["com.acme.enc://"] },
      ],
    }).profile,
  },
  "acme-off": {
    enabled: false,
    profile: A.validateProfile({ ...acmeV2, id: "acme-off" }).profile,
  },
};

// A single storage bag, so pendingFlow written by the sentinel is read back by
// the redirect handler — the whole point of storage-backed pending state.
const bag = { profiles: store };
globalThis.chrome = {
  storage: {
    local: {
      get: async (k) => (typeof k === "string" ? { [k]: bag[k] } : { ...bag }),
      set: async (o) => { Object.assign(bag, o); globalThis._stored = o; },
      remove: async (k) => { delete bag[k]; },
    },
    onChanged: { addListener: () => {} },
  },
  webNavigation: { onBeforeNavigate: { addListener: () => {} }, onErrorOccurred: { addListener: () => {} } },
  tabs: { onUpdated: { addListener: () => {} }, update: (tabId, o) => { globalThis._nav = o.url; } },
  action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
  runtime: { getURL: (p) => `chrome-extension://fake/${p}`, onStartup: { addListener: () => {} } },
};
load(path.join(EXT, "background.js"));

const SP = A.SENTINEL_URL_PREFIXES[0];
const SP_HTTPS = A.SENTINEL_URL_PREFIXES[1];
const SIGNIN = "https://login.acme-app.com/authorize?client_id=x";
const sentinelUrl = (id, stateHa, signin = SIGNIN, prefix = SP) =>
  `${prefix}${id}#state_HA=${stateHa}&signin_url=${encodeURIComponent(signin)}`;
const nav = (tabId, url, frameId = 0) => handleSentinel({ tabId, url, frameId });

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

  // --- the sentinel handoff ---
  // A planted sentinel must be worthless. Each check below removes one thing a
  // hostile page would otherwise get for free.
  globalThis._nav = null;
  delete bag.pendingFlow;
  await nav(10, sentinelUrl("acme-enc", haState));
  t("sentinel navigates to signin_url", globalThis._nav === SIGNIN);
  t("sentinel stashes state_HA", bag.pendingFlow?.stateHa === haState);
  t("sentinel binds tab + profile", bag.pendingFlow?.tabId === 10 && bag.pendingFlow?.profileId === "acme-enc");
  t("sentinel stash starts unconsumed", bag.pendingFlow?.consumedFor === null);

  globalThis._nav = null; delete bag.pendingFlow;
  await nav(11, sentinelUrl("acme-enc", haState), 1);
  t("sentinel ignores subframes", globalThis._nav === null && !bag.pendingFlow);

  globalThis._nav = null; delete bag.pendingFlow;
  await nav(12, sentinelUrl("acme-off", haState));
  t("sentinel ignores disabled profile", globalThis._nav === null && !bag.pendingFlow);

  globalThis._nav = null; delete bag.pendingFlow;
  await nav(13, sentinelUrl("acme-app", haState)); // v1 profile, rule ha-jwt
  t("sentinel ignores non-stashed profile", globalThis._nav === null && !bag.pendingFlow);

  // Open-redirect guard: signin_url outside the profile's own login origins.
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(14, sentinelUrl("acme-enc", haState, "https://evil.com/steal"));
  t("sentinel refuses foreign signin_url", globalThis._nav === null && !bag.pendingFlow);

  globalThis._nav = null; delete bag.pendingFlow;
  await nav(15, sentinelUrl("acme-enc", "not-a-jwt"));
  t("sentinel refuses non-JWT state_HA", globalThis._nav === null && !bag.pendingFlow);

  // --- stashed callback: forward code + stashed state_HA, never the ciphertext state ---
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(20, sentinelUrl("acme-enc", haState));
  await handleRedirect(20, "com.acme.enc://cb?code=CIPHER1&state=ENCSTATE");
  t("stashed forwards to pinned URL", globalThis._nav?.startsWith("https://my.home-assistant.io/redirect/oauth?"));
  t("stashed forwards the code", globalThis._nav?.includes("code=CIPHER1"));
  t("stashed forwards state_HA", globalThis._nav?.includes(`state=${encodeURIComponent(haState)}`));
  t("stashed never forwards provider state", !globalThis._nav?.includes("ENCSTATE"));
  t("stashed marks consumed", bag.pendingFlow?.consumedFor === "com.acme.enc://cb?code=CIPHER1&state=ENCSTATE");

  // Replay of the same callback (e.g. a second event after a worker restart) must
  // not clobber the successful forward with the capture page.
  globalThis._nav = null;
  lastHandledUrl = null; // simulate the in-memory de-dupe dying with the worker
  await handleRedirect(20, "com.acme.enc://cb?code=CIPHER1&state=ENCSTATE");
  t("stashed replay does not clobber", globalThis._nav === null);

  // Control for the test above: without `consumedFor`, the same call DOES act.
  // Otherwise the in-memory de-dupe could be suppressing it and we'd be testing
  // nothing at all.
  globalThis._nav = null;
  lastHandledUrl = null;
  bag.pendingFlow.consumedFor = null;
  await handleRedirect(20, "com.acme.enc://cb?code=CIPHER1&state=ENCSTATE");
  t("replay control: de-dupe really was bypassed", globalThis._nav?.includes("code=CIPHER1"));

  // Wrong tab: a flow planted in one tab cannot capture another tab's callback.
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(21, sentinelUrl("acme-enc", haState));
  await handleRedirect(99, "com.acme.enc://cb?code=OTHERTAB");
  t("stashed rejects foreign tab", globalThis._nav === "chrome-extension://fake/capture.html");

  // Expired TTL -> capture page, not a forward.
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(22, sentinelUrl("acme-enc", haState));
  bag.pendingFlow.time = Date.now() - 11 * 60 * 1000;
  await handleRedirect(22, "com.acme.enc://cb?code=EXPIRED");
  t("stashed expires", globalThis._nav === "chrome-extension://fake/capture.html");

  // HA's MANUAL sign-in path: no sentinel ran, the user must paste the callback
  // URL into HA — so the capture fall-through must keep the raw URL available.
  globalThis._nav = null; delete bag.pendingFlow;
  await handleRedirect(30, "com.acme.enc://cb?code=MANUAL1&state=ENC");
  t("manual path goes to capture", globalThis._nav === "chrome-extension://fake/capture.html");
  t("manual path keeps raw url", bag.lastCapture?.raw === "com.acme.enc://cb?code=MANUAL1&state=ENC");

  // Provider errors are forwarded too, so HA's flow aborts instead of timing out.
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(23, sentinelUrl("acme-enc", haState));
  await handleRedirect(23, "com.acme.enc://cb?error=access_denied&error_description=nope");
  t("stashed forwards errors", globalThis._nav?.includes("error=access_denied"));
  t("stashed error carries state_HA", globalThis._nav?.includes(`state=${encodeURIComponent(haState)}`));

  // The https sentinel form drives the identical flow end to end.
  globalThis._nav = null; delete bag.pendingFlow;
  await nav(24, sentinelUrl("acme-enc", haState, SIGNIN, SP_HTTPS));
  t("https sentinel navigates to signin_url", globalThis._nav === SIGNIN);
  t("https sentinel stashes state_HA", bag.pendingFlow?.stateHa === haState);
  await handleRedirect(24, "com.acme.enc://cb?code=VIAHTTPS&state=ENC2");
  t("https sentinel flow forwards", globalThis._nav?.includes("code=VIAHTTPS") &&
    globalThis._nav?.includes(`state=${encodeURIComponent(haState)}`));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
