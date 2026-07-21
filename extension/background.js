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

let watchCache = null; // { watch: [{ profileId, stateRule, prefix }], byId: { id: profile } }

async function getEnabled() {
  if (watchCache) return watchCache;
  const store = await loadProfileStore();
  const watch = [];
  const byId = {};
  for (const entry of Object.values(store)) {
    if (!entry || !entry.enabled || !entry.profile) continue;
    byId[entry.profile.id] = entry.profile;
    for (const prefix of profileRedirectPrefixes(entry.profile)) {
      watch.push({
        profileId: entry.profile.id,
        stateRule: entry.profile.state.rule,
        prefix,
      });
    }
  }
  watchCache = { watch, byId };
  return watchCache;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.profiles) watchCache = null;
});

// A pending flow outlives nothing: not a browser restart, not a disabled profile.
chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.remove("pendingFlow");
});

// ---------------------------------------------------------------------------
// Initiation handling (the HA -> extension handoff)
//
// Some providers use HA's `state` as input to their own crypto and return
// ciphertext, so the callback can't be recognized as an HA flow. HA therefore
// hands us its routing token (state_HA) BEFORE login, by navigating to the
// sentinel. We stash it and send the tab on to the provider's login page.
//
// ANY WEB PAGE CAN NAVIGATE TO THE SENTINEL. A planted handoff must be worthless,
// not merely unlikely. What makes it worthless is that codes only ever go to
// HA_FORWARD_URL, which routes to the victim's OWN instance, where a foreign
// state_HA names a flow_id that does not exist. Worst case is a failed login.
// The checks below then remove everything else an attacker might get for free.
// ---------------------------------------------------------------------------

// De-dupe: onBeforeNavigate and onErrorOccurred both fire for the same
// non-navigable URL. Keyed per (tab, url) so a genuine second attempt still works.
let lastSentinelKey = null;
let lastSentinelAt = 0;

async function handleSentinel(details) {
  // (2) Top-level navigations only: a hidden iframe cannot plant a flow silently.
  if (details.frameId !== 0) return;

  const handoff = parseSentinel(details.url);
  if (!handoff) return;

  const now = Date.now();
  const key = `${details.tabId}|${details.url}`;
  if (key === lastSentinelKey && now - lastSentinelAt < 2000) return;
  lastSentinelKey = key;
  lastSentinelAt = now;

  // (6) Only for a profile the user enabled, and only if it expects a handoff.
  const { byId } = await getEnabled();
  const profile = byId[handoff.profileId];
  if (!profile) return;
  const initiation = profileInitiation(profile);
  if (!initiation || profile.state.rule !== "stashed") return;

  // (1) Never navigate anywhere but this profile's own login pages. Without this
  // the extension is an open redirect for any page that can reach the sentinel.
  if (!matchesLoginOrigin(handoff.signinUrl, profile.loginOrigins)) return;

  // (3) Structural check only — no crypto, ever. HA signs state_HA, so a page
  // cannot forge one; this just rejects garbage before we act on it.
  if (!isHomeAssistantFlow(handoff.stateHa)) return;

  // Persist BEFORE navigating. The reference implementation navigated first, so a
  // service worker killed in between left an unroutable flow and a dead capture.
  // (4) tabId + profileId bind the flow. (5) TTL makes it single-use and short.
  await chrome.storage.local.set({
    pendingFlow: {
      stateHa: handoff.stateHa,
      profileId: profile.id,
      tabId: details.tabId,
      time: now,
      ttlMs: initiation.ttlSeconds * 1000,
      consumedFor: null,
    },
  });

  chrome.action.setBadgeText({ text: "…" });
  chrome.action.setBadgeBackgroundColor({ color: "#03a9f4" });
  chrome.tabs.update(details.tabId, { url: handoff.signinUrl });
}

/**
 * The pending flow for this callback, or null. Enforces the bindings set above.
 * `consumedFor` is how a repeat of the same callback URL is recognized after the
 * service worker has died and taken the in-memory de-dupe with it.
 */
function livePendingFlow(pendingFlow, profileId, tabId, url, now) {
  if (!pendingFlow || !pendingFlow.stateHa) return null;
  if (pendingFlow.profileId !== profileId) return null;
  if (pendingFlow.tabId !== tabId) return null;
  if (now - (pendingFlow.time || 0) >= (pendingFlow.ttlMs || 0)) return null;
  if (pendingFlow.consumedFor && pendingFlow.consumedFor !== url) return null;
  return pendingFlow;
}

// ---------------------------------------------------------------------------
// Redirect handling
// ---------------------------------------------------------------------------

// De-dupe: onBeforeNavigate and onErrorOccurred can both fire for the same
// non-navigable custom-scheme URL, and behavior varies by browser/version.
let lastHandledUrl = null;
let lastHandledAt = 0;

async function handleRedirect(tabId, url) {
  const { watch } = await getEnabled();
  const match = watch.find((w) => url.startsWith(w.prefix));
  if (!match) return;

  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    return;
  }
  const q = urlObj.searchParams;
  const code = q.get("code");
  const state = q.get("state");
  const error = q.get("error");

  // A completed OAuth authorization response always carries either a `code`
  // (success) or an `error` (failure) query parameter. Without one, matching the
  // prefix is not enough to call this a callback: it's the user reaching the
  // redirect URI some other way to start a manual/CLI login. 
  if (!code && !error) return;

  const now = Date.now();
  if (url === lastHandledUrl && now - lastHandledAt < 5000) return;
  lastHandledUrl = url;
  lastHandledAt = now;

  // Encrypted-state flow: the routing token came from the sentinel, not the
  // callback. The provider's own `state` is ciphertext and is never forwarded —
  // HA already holds what it needs to decrypt this server-side.
  if (match.stateRule === "stashed") {
    const { pendingFlow } = await chrome.storage.local.get("pendingFlow");
    const live = livePendingFlow(pendingFlow, match.profileId, tabId, url, now);

    if (live && (code || error)) {
      if (live.consumedFor === url) return; // already forwarded; don't clobber the tab

      const haUrl = new URL(HA_FORWARD_URL);
      if (code) haUrl.searchParams.set("code", code);
      if (error) {
        // Forward the failure too, so HA's flow aborts now instead of timing out.
        haUrl.searchParams.set("error", error);
        const desc = q.get("error_description");
        if (desc) haUrl.searchParams.set("error_description", desc);
      }
      haUrl.searchParams.set("state", live.stateHa);

      chrome.action.setBadgeText({ text: code ? "✓" : "!" });
      chrome.action.setBadgeBackgroundColor({ color: code ? "#4CAF50" : "#c62828" });
      chrome.tabs.update(tabId, { url: haUrl.toString() });

      // Mark consumed AFTER navigating: if the worker dies first, a repeat event
      // simply forwards again to the same URL. Marking first would strand the flow.
      await chrome.storage.local.set({ pendingFlow: { ...live, consumedFor: url } });
      return;
    }

    // No live flow (expired, wrong tab, or never initiated — including HA's
    // MANUAL sign-in path, where the user is expected to paste the callback URL
    // into HA and we intercepted it first). Fall through to the capture page,
    // which offers a forward when a pending flow still exists and otherwise
    // offers the raw callback URL for the manual paste.
    await chrome.storage.local.set({
      lastCapture: {
        profileId: match.profileId,
        time: now,
        rule: "stashed",
        raw: url,
        code: code || "",
        state: "",
        error: error || "",
        errorDescription: q.get("error_description") || "",
      },
    });
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL("capture.html") });
    return;
  }

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
  handleSentinel(details);
  handleRedirect(details.tabId, details.url);
});

// Some browsers fail the custom-scheme navigation before onBeforeNavigate can
// act; the URL then surfaces here instead. Both the sentinel and the callback are
// non-navigable schemes, so both need this.
chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (!details.url) return;
  handleSentinel(details);
  handleRedirect(details.tabId, details.url);
});

// Some IdPs (e.g. Auth0 Universal Login) reach the callback URL via
// history.pushState, which never fires webNavigation events. Only https
// prefixes can appear this way.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url && changeInfo.url.startsWith("https://")) {
    handleRedirect(tabId, changeInfo.url);
  }
});
