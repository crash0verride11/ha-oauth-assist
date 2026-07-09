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

const PROFILE_SCHEMA_VERSION = 1;

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
  return true;
}

const STATE_RULES = ["ha-jwt", "none"];

/**
 * Validates a profile object. Returns { ok: true, profile } with a normalized
 * copy, or { ok: false, errors: [...] }.
 *
 * Schema v1:
 * {
 *   "schemaVersion": 1,
 *   "id": "acme-app",                   // [a-z0-9-], unique
 *   "name": "Acme App",
 *   "description": "…",                 // optional
 *   "loginOrigins": ["https://login.acme-app.com/*"],  // match patterns; runtime permission is requested for these
 *   "capture": [                        // array => room for future step types
 *     { "type": "redirect", "redirectPrefixes": ["com.acme.app://"] }
 *   ],
 *   "state": { "rule": "ha-jwt" }       // optional; "ha-jwt" (default) or "none"
 * }
 *
 * Only capture type "redirect" exists in v1. A future "initiation" step type
 * (an extra HA→extension handoff earlier in the flow, which some providers
 * need) can be added as a new entry in `capture` without changing this shape.
 */
function validateProfile(raw) {
  const errors = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, errors: ["Profile must be a JSON object."] };
  }
  if (raw.schemaVersion !== PROFILE_SCHEMA_VERSION) {
    errors.push(`schemaVersion must be ${PROFILE_SCHEMA_VERSION}.`);
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
  if (!Array.isArray(raw.capture) || raw.capture.length === 0) {
    errors.push("capture must be a non-empty array of capture steps.");
  } else {
    for (const step of raw.capture) {
      if (!step || typeof step !== "object") {
        errors.push("capture step must be an object.");
        continue;
      }
      if (step.type !== "redirect") {
        errors.push(
          `Unsupported capture step type ${JSON.stringify(step.type)} (this version supports "redirect" only).`,
        );
        continue;
      }
      if (!Array.isArray(step.redirectPrefixes) || step.redirectPrefixes.length === 0) {
        errors.push("redirect step needs a non-empty redirectPrefixes array.");
        continue;
      }
      for (const p of step.redirectPrefixes) {
        if (!isValidRedirectPrefix(p)) {
          errors.push(`Invalid redirect prefix: ${JSON.stringify(p)}`);
        } else {
          redirectPrefixes.push(p);
        }
      }
    }
  }

  let stateRule = "ha-jwt";
  if (raw.state !== undefined) {
    if (!raw.state || typeof raw.state !== "object" || !STATE_RULES.includes(raw.state.rule)) {
      errors.push(`state.rule must be one of: ${STATE_RULES.join(", ")}.`);
    } else {
      stateRule = raw.state.rule;
    }
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    profile: {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      id: raw.id,
      name: raw.name.trim(),
      description: (raw.description || "").trim(),
      loginOrigins: [...raw.loginOrigins],
      capture: [{ type: "redirect", redirectPrefixes }],
      state: { rule: stateRule },
    },
  };
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
    PROFILE_SCHEMA_VERSION,
    isHomeAssistantFlow,
    isValidLoginOrigin,
    isValidRedirectPrefix,
    validateProfile,
    profileRedirectPrefixes,
    loadProfileStore,
  };
}
