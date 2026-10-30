/**
 * OAuth Assist for HA - background worker
 *
 * Watches navigation for redirect URIs declared by *enabled* config profiles
 * (typically custom-scheme URLs like msauth://… that the browser cannot
 * follow). When one fires with an authorization code and a Home Assistant
 * flow state (JWT with flow_id), the tab is rewritten to Home Assistant's
 * official redirect service. Otherwise a local capture page shows the code
 * for manual use.
 *
 * The forward destination is the constant HA_FORWARD_URL in shared.js and is
 * never configurable — profiles only choose what to watch.
 *
 * Profiles may also declare requestHeaders (restricted to browser-identity
 * headers), applied to their login hosts via declarativeNetRequest.
 */

// Chrome runs this as a service worker (importScripts); Firefox loads
// shared.js first via background.scripts, where importScripts is undefined.
if (typeof importScripts === "function") {
  importScripts("shared.js");
}

// ---------------------------------------------------------------------------
// Profile cache. Service workers are killed and restarted, so the cache is
// rebuilt lazily from storage and refreshed on storage changes.
// ---------------------------------------------------------------------------

let watchCache = null; // [{ profileId, stateRule, prefix }]

async function getWatchList() {
  if (watchCache) return watchCache;
  const store = await loadProfileStore();
  const list = [];
  for (const entry of Object.values(store)) {
    if (!entry || !entry.enabled || !entry.profile) continue;
    for (const prefix of profileRedirectPrefixes(entry.profile)) {
      list.push({
        profileId: entry.profile.id,
        stateRule: entry.profile.state.rule,
        prefix,
      });
    }
  }
  watchCache = list;
  return list;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.profiles) {
    watchCache = null;
    syncHeaderRules();
  }
});

// ---------------------------------------------------------------------------
// Request-header rules. Enabled profiles that declare requestHeaders get a
// declarativeNetRequest dynamic rule on their login hosts (e.g. a mobile
// User-Agent for an IdP that rejects desktop browsers). Dynamic rules persist
// across restarts; they are rebuilt whenever the stored profiles change.
// ---------------------------------------------------------------------------

// Serialized: overlapping syncs would each remove the same old ids and then
// both try to add rule id 1, and the second update would be rejected.
let headerSync = Promise.resolve();

function syncHeaderRules() {
  headerSync = headerSync.then(async () => {
    try {
      const store = await loadProfileStore();
      const enabled = Object.values(store)
        .filter((e) => e && e.enabled && e.profile)
        .map((e) => e.profile);
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existing.map((r) => r.id),
        addRules: buildHeaderRules(enabled),
      });
    } catch (e) {
      console.error("Could not update request-header rules:", e);
    }
  });
  return headerSync;
}

// ---------------------------------------------------------------------------
// Bundled preset refresh. Enabling a profile stores a snapshot of it, so an
// updated preset (say, a new User-Agent string) would otherwise never reach
// users who enabled the old one. On extension update, replace bundled
// snapshots with the packaged versions. If the new version needs a login
// origin the user has not granted, disable it so re-enabling asks for consent.
// ---------------------------------------------------------------------------

async function refreshBundledProfiles() {
  const presets = await loadPresets();
  if (!presets.length) return;
  const store = await loadProfileStore();
  let changed = false;
  for (const preset of presets) {
    const entry = store[preset.id];
    if (!entry || entry.source !== "bundled") continue;
    if (JSON.stringify(entry.profile) === JSON.stringify(preset)) continue;
    entry.profile = preset;
    if (entry.enabled) {
      const granted = await chrome.permissions.contains({ origins: preset.loginOrigins });
      if (!granted) entry.enabled = false;
    }
    changed = true;
  }
  // The storage change triggers syncHeaderRules via onChanged.
  if (changed) await chrome.storage.local.set({ profiles: store });
}

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "update") {
    try {
      await refreshBundledProfiles();
    } catch (e) {
      console.error("Could not refresh bundled profiles:", e);
    }
  }
  syncHeaderRules();
});

chrome.runtime.onStartup.addListener(() => {
  syncHeaderRules();
});

// ---------------------------------------------------------------------------
// Redirect handling
// ---------------------------------------------------------------------------

// De-dupe: onBeforeNavigate and onErrorOccurred can both fire for the same
// non-navigable custom-scheme URL, and behavior varies by browser/version.
let lastHandledUrl = null;
let lastHandledAt = 0;

async function handleRedirect(tabId, url) {
  const watch = await getWatchList();
  const match = watch.find((w) => url.startsWith(w.prefix));
  if (!match) return;

  const now = Date.now();
  if (url === lastHandledUrl && now - lastHandledAt < 5000) return;
  lastHandledUrl = url;
  lastHandledAt = now;

  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    return;
  }
  const q = urlObj.searchParams;
  const code = q.get("code");
  const state = q.get("state");

  // Auto-forward to Home Assistant when this is an HA-initiated flow.
  const haFlow =
    match.stateRule === "ha-jwt" ? isHomeAssistantFlow(state) : Boolean(state);
  if (code && haFlow) {
    const haUrl = new URL(HA_FORWARD_URL);
    haUrl.searchParams.set("code", code);
    haUrl.searchParams.set("state", state);
    chrome.action.setBadgeText({ text: "✓" });
    chrome.action.setBadgeBackgroundColor({ color: "#4CAF50" });
    chrome.tabs.update(tabId, { url: haUrl.toString() });
    return;
  }

  // Otherwise show the local capture page. The payload goes through storage,
  // not the capture URL: nested URLs/tokens in a query string can trip content
  // blockers' anti-redirect filters (ERR_BLOCKED_BY_CLIENT), and storage also
  // avoids URL-length limits.
  await chrome.storage.local.set({
    lastCapture: {
      profileId: match.profileId,
      time: now,
      code: code || "",
      state: state || "",
      error: q.get("error") || "",
      errorDescription: q.get("error_description") || "",
    },
  });

  if (code) {
    chrome.action.setBadgeText({ text: "✓" });
    chrome.action.setBadgeBackgroundColor({ color: "#4CAF50" });
  }
  chrome.tabs.update(tabId, { url: chrome.runtime.getURL("capture.html") });
}

// Fires for real navigation attempts, including most custom-scheme redirects.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  handleRedirect(details.tabId, details.url);
});

// Some browsers fail the custom-scheme navigation before onBeforeNavigate can
// act; the URL then surfaces here instead.
chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.url) handleRedirect(details.tabId, details.url);
});

// Some IdPs (e.g. Auth0 Universal Login) reach the callback URL via
// history.pushState, which never fires webNavigation events. Only https
// prefixes can appear this way.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url && changeInfo.url.startsWith("https://")) {
    handleRedirect(tabId, changeInfo.url);
  }
});
