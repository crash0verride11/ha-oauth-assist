/**
 * OAuth Assist for HA - shared logic
 *
 * Loaded by the background worker (importScripts in Chrome, background.scripts
 * in Firefox) and by the options/popup/capture pages via <script>.
 *
 * SECURITY INVARIANT: captured authorization codes are only ever forwarded to
 * HA_FORWARD_URL below. Profiles configure WHAT to watch, never WHERE to send.
 * Do not add a forward-target field to the profile schema.
 */

const HA_FORWARD_URL = "https://my.home-assistant.io/redirect/oauth";

/**
 * The "initiation" handoff. Home Assistant navigates the browser to either
 *
 *   ha-oauth-assist-initiate://start/<profileId>#state_HA=<jwt>&signin_url=<url>
 *   https://ha-oauth-assist.example.com/initiate/<profileId>#state_HA=<jwt>&signin_url=<url>
 *
 * and we intercept it in webNavigation. Both carry the parameters in the
 * FRAGMENT, which is never transmitted, so state_HA stays on this machine even
 * when the https form is (briefly) navigated for real.
 *
 * Two forms because their failure modes differ, and integrations may weigh them
 * differently:
 *  - The custom scheme never touches the network at all (no DNS), but a PASTED
 *    copy may be turned into a web search by the omnibox — which would send the
 *    whole URL, fragment included, to a search engine. Omnibox behavior varies
 *    by browser and is not stable enough to rely on.
 *  - The https form pastes reliably everywhere (real public suffix), and its
 *    worst case leaks less: example.com is RFC 2606 reserved, IANA does not
 *    resolve subdomains, so at most a DNS lookup escapes — never the fragment.
 *
 * These are constants for the same reason HA_FORWARD_URL is: profiles say what
 * to watch, never where to send or where to be handed a token.
 *
 * Any web page can navigate here, so a handoff is untrusted input. See
 * parseSentinel() and the checks in background.js.
 */
const SENTINEL_URL_PREFIXES = [
  "ha-oauth-assist-initiate://start/",
  "https://ha-oauth-assist.example.com/initiate/",
];

const PROFILE_SCHEMA_VERSION = 2;

/** Profiles at these versions load. v1 predates the initiation step. */
const PROFILE_SCHEMA_VERSIONS = [1, 2];

/** Bounds on an initiation step's pending-flow TTL. */
const TTL_DEFAULT_SECONDS = 600;
const TTL_MIN_SECONDS = 60;
const TTL_MAX_SECONDS = 900;

/**
 * Returns true when `state` is the JWT Home Assistant's OAuth config flow
 * issues (payload contains a string flow_id). Used to decide auto-forwarding.
 */
function isHomeAssistantFlow(state) {
  if (!state) return false;
  try {
    const parts = state.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );
    return payload && typeof payload.flow_id === "string";
  } catch (e) {
    return false;
  }
}

/**
 * Validates a Chrome match pattern restricted to https origins, e.g.
 * "https://login.acme-app.com/*" or "https://*.example-idp.com/*".
 * Only https is accepted: login pages are always https, and this string is
 * passed to chrome.permissions.request as an origin.
 */
function isValidLoginOrigin(pattern) {
  if (typeof pattern !== "string") return false;
  const m = pattern.match(/^https:\/\/(\*|(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+)\/.*$/i);
  return Boolean(m);
}

/**
 * True when `url` is an https URL whose host is covered by one of the profile's
 * loginOrigins match patterns.
 *
 * Used to check the `signin_url` handed over by a sentinel. Without this the
 * extension is an open redirect: any page could navigate to the sentinel and
 * have us send the user anywhere. Only the host is compared — the login path
 * varies per provider and carries the OAuth query.
 */
function matchesLoginOrigin(url, loginOrigins) {
  let host;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return false;
    host = u.hostname.toLowerCase();
  } catch (e) {
    return false;
  }
  return loginOrigins.some((pattern) => {
    const m = pattern.match(/^https:\/\/([^/]+)\//i);
    if (!m) return false;
    const patternHost = m[1].toLowerCase();
    if (patternHost === "*") return true;
    if (patternHost.startsWith("*.")) {
      const base = patternHost.slice(2);
      // "*.example.com" covers example.com and any subdomain, per match patterns.
      return host === base || host.endsWith("." + base);
    }
    return host === patternHost;
  });
}

/**
 * Validates a redirect prefix. Two shapes are allowed:
 *  - a custom scheme URI, e.g. "com.acme.app://" or "msauth://…" (the browser
 *    cannot navigate these; we catch them in webNavigation)
 *  - an https URL prefix, e.g. "https://login.acme-app.com/ios/" (some
 *    providers finish on an https callback the app intercepts natively)
 * http:// is rejected; so is anything without a scheme.
 */
function isValidRedirectPrefix(prefix) {
  if (typeof prefix !== "string" || prefix.length < 8) return false;
  const m = prefix.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (!m) return false;
  const scheme = m[1].toLowerCase();
  if (scheme === "http") return false;
  // Guard against watching the forward target itself or extension pages.
  if (scheme === "chrome-extension" || scheme === "moz-extension") return false;
  if (prefix.toLowerCase().startsWith("https://my.home-assistant.io")) return false;
  // Load-bearing: a profile must never claim a sentinel as its own redirect
  // target. It would see every other profile's state_HA handoff. Block the
  // custom scheme wholesale and the https sentinel's host.
  const lower = prefix.toLowerCase();
  if (lower.startsWith("ha-oauth-assist-initiate://")) return false;
  if (lower.startsWith("https://ha-oauth-assist.example.com")) return false;
  return true;
}

/**
 * Parses a sentinel URL (either form). Returns { profileId, stateHa, signinUrl }
 * or null.
 *
 * Everything here is attacker-controlled — any page can navigate to the sentinel
 * — so this only parses. background.js decides whether to act on it.
 *
 * Matched by string prefix rather than URL host/pathname: for a non-special
 * scheme, browsers do not agree on how the authority is split.
 */
function parseSentinel(url) {
  if (typeof url !== "string") return null;
  const prefix = SENTINEL_URL_PREFIXES.find((p) => url.startsWith(p));
  if (!prefix) return null;
  const rest = url.slice(prefix.length);
  const hashAt = rest.indexOf("#");
  if (hashAt < 0) return null;

  const profileId = rest.slice(0, hashAt);
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(profileId)) return null;

  const q = new URLSearchParams(rest.slice(hashAt + 1));
  const stateHa = q.get("state_HA");
  const signinUrl = q.get("signin_url");
  if (!stateHa || !signinUrl) return null;

  return { profileId, stateHa, signinUrl };
}

const STATE_RULES = ["ha-jwt", "none", "stashed"];

/**
 * Validates a profile object. Returns { ok: true, profile } with a normalized
 * copy, or { ok: false, errors: [...] }.
 *
 * Schema v2 (v1 still loads; it simply has no initiation step):
 * {
 *   "schemaVersion": 2,
 *   "id": "acme-app",                   // [a-z0-9-], unique
 *   "name": "Acme App",
 *   "description": "…",                 // optional
 *   "loginOrigins": ["https://login.acme-app.com/*"],  // match patterns; runtime permission is requested for these
 *   "capture": [
 *     { "type": "initiation", "ttlSeconds": 600 },     // optional, v2, must come first
 *     { "type": "redirect", "redirectPrefixes": ["com.acme.app://"] }
 *   ],
 *   "state": { "rule": "ha-jwt" }       // "ha-jwt" (default), "none", or "stashed"
 * }
 *
 * The initiation step declares NO urls and NO parameter names on purpose: the
 * sentinel is one of SENTINEL_URL_PREFIXES above, and state_HA/signin_url are names Home
 * Assistant and this extension agree on. There is nothing in the step for an
 * imported profile to point somewhere hostile. All it carries is a TTL.
 *
 * An initiation step and state.rule "stashed" imply each other — a flow either
 * gets its routing token from the sentinel or reads it off the callback, never
 * both and never neither.
 */
function validateProfile(raw) {
  const errors = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, errors: ["Profile must be a JSON object."] };
  }
  const version = raw.schemaVersion;
  if (!PROFILE_SCHEMA_VERSIONS.includes(version)) {
    errors.push(
      typeof version === "number" && version > PROFILE_SCHEMA_VERSION
        ? `schemaVersion ${version} needs a newer version of OAuth Assist for HA.`
        : `schemaVersion must be one of: ${PROFILE_SCHEMA_VERSIONS.join(", ")}.`,
    );
  }
  if (typeof raw.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(raw.id)) {
    errors.push("id must be a short lowercase slug ([a-z0-9-]).");
  }
  if (typeof raw.name !== "string" || !raw.name.trim() || raw.name.length > 100) {
    errors.push("name is required (max 100 chars).");
  }
  if (raw.description !== undefined && typeof raw.description !== "string") {
    errors.push("description must be a string.");
  }

  if (!Array.isArray(raw.loginOrigins) || raw.loginOrigins.length === 0) {
    errors.push("loginOrigins must be a non-empty array of https match patterns.");
  } else {
    for (const o of raw.loginOrigins) {
      if (!isValidLoginOrigin(o)) {
        errors.push(`loginOrigins entry is not a valid https match pattern: ${JSON.stringify(o)}`);
      }
    }
  }

  const redirectPrefixes = [];
  let initiation = null;
  let initiationCount = 0;

  if (!Array.isArray(raw.capture) || raw.capture.length === 0) {
    errors.push("capture must be a non-empty array of capture steps.");
  } else {
    raw.capture.forEach((step, i) => {
      if (!step || typeof step !== "object") {
        errors.push("capture step must be an object.");
        return;
      }

      if (step.type === "initiation") {
        initiationCount++;
        if (version === 1) {
          errors.push('capture type "initiation" requires schemaVersion 2.');
          return;
        }
        if (i !== 0) {
          errors.push('the "initiation" step must come first in capture.');
        }
        if (initiationCount > 1) {
          errors.push('at most one "initiation" step is allowed.');
        }
        for (const key of Object.keys(step)) {
          if (key !== "type" && key !== "ttlSeconds") {
            errors.push(`"initiation" step has no ${JSON.stringify(key)} field.`);
          }
        }
        let ttl = TTL_DEFAULT_SECONDS;
        if (step.ttlSeconds !== undefined) {
          if (!Number.isInteger(step.ttlSeconds) ||
              step.ttlSeconds < TTL_MIN_SECONDS ||
              step.ttlSeconds > TTL_MAX_SECONDS) {
            errors.push(`ttlSeconds must be an integer ${TTL_MIN_SECONDS}-${TTL_MAX_SECONDS}.`);
          } else {
            ttl = step.ttlSeconds;
          }
        }
        initiation = { type: "initiation", ttlSeconds: ttl };
        return;
      }

      if (step.type !== "redirect") {
        errors.push(
          `Unsupported capture step type ${JSON.stringify(step.type)}. This version supports "redirect" and "initiation".`,
        );
        return;
      }
      if (!Array.isArray(step.redirectPrefixes) || step.redirectPrefixes.length === 0) {
        errors.push("redirect step needs a non-empty redirectPrefixes array.");
        return;
      }
      for (const p of step.redirectPrefixes) {
        if (!isValidRedirectPrefix(p)) {
          errors.push(`Invalid redirect prefix: ${JSON.stringify(p)}`);
        } else {
          redirectPrefixes.push(p);
        }
      }
    });
  }

  if (redirectPrefixes.length === 0 && !errors.length) {
    errors.push("capture needs at least one redirect step.");
  }

  let stateRule = "ha-jwt";
  if (raw.state !== undefined) {
    if (!raw.state || typeof raw.state !== "object" || !STATE_RULES.includes(raw.state.rule)) {
      errors.push(`state.rule must be one of: ${STATE_RULES.join(", ")}.`);
    } else {
      stateRule = raw.state.rule;
    }
  }

  // The two halves of an encrypted-state flow. Either alone is a misconfiguration:
  // "stashed" with no initiation can never forward (no state_HA will ever arrive),
  // and an initiation step under another rule stashes a token nothing reads.
  if (stateRule === "stashed" && version !== 1 && !initiation) {
    errors.push('state.rule "stashed" requires an "initiation" capture step.');
  }
  if (initiation && stateRule !== "stashed") {
    errors.push('an "initiation" capture step requires state.rule "stashed".');
  }
  if (stateRule === "stashed" && version === 1) {
    errors.push('state.rule "stashed" requires schemaVersion 2.');
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    profile: {
      schemaVersion: version,
      id: raw.id,
      name: raw.name.trim(),
      description: (raw.description || "").trim(),
      loginOrigins: [...raw.loginOrigins],
      capture: [
        ...(initiation ? [initiation] : []),
        { type: "redirect", redirectPrefixes },
      ],
      state: { rule: stateRule },
    },
  };
}

/** The validated initiation step of a profile, or null. */
function profileInitiation(profile) {
  return profile.capture.find((s) => s.type === "initiation") || null;
}

/** All redirect prefixes of a validated profile, flattened. */
function profileRedirectPrefixes(profile) {
  return profile.capture
    .filter((s) => s.type === "redirect")
    .flatMap((s) => s.redirectPrefixes);
}

/** Loads the enabled-profiles map from storage: { [id]: { profile, enabled, source, addedAt } } */
async function loadProfileStore() {
  const { profiles } = await chrome.storage.local.get("profiles");
  return profiles || {};
}

// Export for the pages (the background worker just uses the globals).
if (typeof globalThis !== "undefined") {
  globalThis.OAuthAssist = {
    HA_FORWARD_URL,
    SENTINEL_URL_PREFIXES,
    PROFILE_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSIONS,
    isHomeAssistantFlow,
    isValidLoginOrigin,
    matchesLoginOrigin,
    isValidRedirectPrefix,
    parseSentinel,
    validateProfile,
    profileRedirectPrefixes,
    profileInitiation,
    loadProfileStore,
  };
}
