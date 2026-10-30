/**
 * OAuth Assist for HA - options page
 *
 * Lists bundled preset profiles and imported ones. Enabling a profile:
 *   1. requests a runtime host permission for the profile's loginOrigins
 *      (chrome.permissions.request — the browser shows a consent prompt);
 *   2. on grant, stores the profile as enabled in chrome.storage.local.
 * Disabling removes the stored enablement and releases the host permission
 * (unless another enabled profile still needs the same origin).
 * The background worker turns enabled profiles' requestHeaders into
 * declarativeNetRequest rules whenever the stored profiles change.
 */

// Note: no destructuring into top-level const here — shared.js's function
// declarations live in the same global scope as this classic script, so
// `const validateProfile = …` would be a duplicate-identifier SyntaxError.
const OA = globalThis.OAuthAssist;

const listEl = document.getElementById("profile-list");
const importFileEl = document.getElementById("import-file");
const importStatusEl = document.getElementById("import-status");

async function saveProfileEntry(profile, { enabled, source }) {
  const store = await OA.loadProfileStore();
  store[profile.id] = {
    profile,
    enabled,
    source,
    addedAt: store[profile.id]?.addedAt || Date.now(),
  };
  await chrome.storage.local.set({ profiles: store });
}

/** Origins still needed by enabled profiles other than `excludeId`. */
async function originsStillNeeded(excludeId) {
  const store = await OA.loadProfileStore();
  const needed = new Set();
  for (const entry of Object.values(store)) {
    if (!entry.enabled || entry.profile.id === excludeId) continue;
    for (const o of entry.profile.loginOrigins) needed.add(o);
  }
  return needed;
}

async function enableProfile(profile, source, statusEl) {
  statusEl.textContent = "Waiting for permission prompt…";
  statusEl.className = "status";
  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: profile.loginOrigins });
  } catch (e) {
    statusEl.textContent = `Permission request failed: ${e.message}`;
    statusEl.className = "status err";
    return;
  }
  if (!granted) {
    statusEl.textContent = "Permission was declined — profile not enabled.";
    statusEl.className = "status err";
    return;
  }
  await saveProfileEntry(profile, { enabled: true, source });
  render();
}

async function disableProfile(id, { remove = false } = {}) {
  const store = await OA.loadProfileStore();
  const entry = store[id];
  if (!entry) return;

  const stillNeeded = await originsStillNeeded(id);
  const releasable = entry.profile.loginOrigins.filter((o) => !stillNeeded.has(o));
  if (releasable.length) {
    try {
      await chrome.permissions.remove({ origins: releasable });
    } catch (e) {
      console.warn("Could not release host permissions:", e);
    }
  }

  if (remove && entry.source === "imported") {
    delete store[id];
  } else {
    entry.enabled = false;
  }
  await chrome.storage.local.set({ profiles: store });
  render();
}

function profileCard(profile, { enabled, source }) {
  const card = document.createElement("div");
  card.className = "card";

  const name = document.createElement("div");
  name.className = "row";
  const nameText = document.createElement("span");
  nameText.className = "name";
  nameText.textContent = profile.name;
  const badge = document.createElement("span");
  badge.className = enabled ? "badge" : "badge off";
  badge.textContent = enabled ? "Active" : "Off";
  name.append(nameText, badge);
  if (source === "imported") {
    const src = document.createElement("span");
    src.className = "badge imported";
    src.textContent = "Imported";
    name.append(src);
  }

  const desc = document.createElement("div");
  desc.className = "desc";
  desc.textContent = profile.description || "";

  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "What this profile watches";
  details.append(summary);
  const dl = document.createElement("div");
  const origins = document.createElement("div");
  origins.append("Login site (permission requested): ");
  profile.loginOrigins.forEach((o, i) => {
    if (i) origins.append(", ");
    const c = document.createElement("code");
    c.textContent = o;
    origins.append(c);
  });
  const prefixes = document.createElement("div");
  prefixes.append("Redirects captured: ");
  OA.profileRedirectPrefixes(profile).forEach((p, i) => {
    if (i) prefixes.append(", ");
    const c = document.createElement("code");
    c.textContent = p;
    prefixes.append(c);
  });
  dl.append(origins, prefixes);
  const headerOps = profile.requestHeaders || [];
  if (headerOps.length) {
    const headers = document.createElement("div");
    headers.append("Request headers changed on the login site: ");
    headerOps.forEach((op, i) => {
      if (i) headers.append(", ");
      const c = document.createElement("code");
      c.textContent = op.operation === "set" ? `${op.header}: ${op.value}` : `${op.header} (removed)`;
      headers.append(c);
    });
    dl.append(headers);
  }
  details.append(dl);

  const row = document.createElement("div");
  row.className = "row";
  const status = document.createElement("div");
  status.className = "status";

  if (!enabled) {
    const btn = document.createElement("button");
    btn.className = "primary";
    btn.textContent = "Enable…";
    btn.addEventListener("click", () => enableProfile(profile, source, status));
    row.append(btn);
  } else {
    const btn = document.createElement("button");
    btn.textContent = "Disable";
    btn.addEventListener("click", () => disableProfile(profile.id));
    row.append(btn);
  }
  if (source === "imported") {
    const rm = document.createElement("button");
    rm.className = "danger";
    rm.textContent = "Remove";
    rm.addEventListener("click", () => disableProfile(profile.id, { remove: true }));
    row.append(rm);
  }

  card.append(name, desc, details, row, status);
  return card;
}

async function render() {
  const [presets, store] = await Promise.all([OA.loadPresets(), OA.loadProfileStore()]);
  listEl.textContent = "";

  const seen = new Set();
  for (const preset of presets) {
    seen.add(preset.id);
    const entry = store[preset.id];
    listEl.append(
      profileCard(entry?.profile || preset, {
        enabled: Boolean(entry?.enabled),
        source: "bundled",
      }),
    );
  }
  for (const entry of Object.values(store)) {
    if (seen.has(entry.profile.id)) continue;
    listEl.append(
      profileCard(entry.profile, {
        enabled: entry.enabled,
        source: entry.source || "imported",
      }),
    );
  }
}

importFileEl.addEventListener("change", async () => {
  importStatusEl.className = "status";
  importStatusEl.textContent = "";
  const file = importFileEl.files?.[0];
  if (!file) return;

  let raw;
  try {
    raw = JSON.parse(await file.text());
  } catch (e) {
    importStatusEl.textContent = `Not valid JSON: ${e.message}`;
    importStatusEl.className = "status err";
    return;
  }

  const result = OA.validateProfile(raw);
  if (!result.ok) {
    importStatusEl.textContent = `Profile rejected:\n- ${result.errors.join("\n- ")}`;
    importStatusEl.className = "status err";
    return;
  }

  const store = await OA.loadProfileStore();
  const existing = store[result.profile.id];
  if (existing?.source === "bundled") {
    importStatusEl.textContent = `A bundled profile already uses id "${result.profile.id}".`;
    importStatusEl.className = "status err";
    return;
  }

  // Re-importing an enabled profile is an update: disable it first so its
  // host permissions are released and Enable asks for consent to the new
  // version (which may watch or change different things).
  if (existing?.enabled) await disableProfile(result.profile.id);

  await saveProfileEntry(result.profile, { enabled: false, source: "imported" });
  importStatusEl.textContent = `${existing ? "Updated" : "Imported"} "${result.profile.name}". Click Enable to grant its site permission and activate it.`;
  importStatusEl.className = "status ok";
  importFileEl.value = "";
  render();
});

render();
