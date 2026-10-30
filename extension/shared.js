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
 * Request-header policy. Profiles carry the header VALUES (e.g. a mobile
 * User-Agent for an IdP that rejects desktop browsers), so a provider quirk
 * never needs an extension release. The extension only fixes WHICH headers a
 * profile may touch: browser-identity headers, nothing that carries
 * credentials (Cookie, Authorization) or protects against CSRF (Origin,
 * Referer). Rules always apply to the profile's own loginOrigins.
 */
const HEADER_NAME_PATTERN = /^(user-agent|sec-ch-ua(-[a-z0-9]+)*)$/i;
const HEADER_OPERATIONS = ["set", "remove"];
const HEADER_VALUE_MAX = 512;
const HEADER_OPS_MAX = 16;
const HEADER_RULE_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "xmlhttprequest",
  "script",
  "other",
];

function validateRequestHeaders(raw, errors) {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > HEADER_OPS_MAX) {
    errors.push(`requestHeaders must be an array of 1-${HEADER_OPS_MAX} header operations.`);
    return [];
  }
  const ops = [];
  const seen = new Set();
  for (const op of raw) {
    if (!op || typeof op !== "object" || Array.isArray(op)) {
      errors.push("requestHeaders entry must be an object.");
      continue;
    }
    if (typeof op.header !== "string" || !HEADER_NAME_PATTERN.test(op.header)) {
      errors.push(
        `requestHeaders may only modify User-Agent or Sec-CH-UA* headers, not ${JSON.stringify(op.header)}.`,
      );
      continue;
    }
    const key = op.header.toLowerCase();
    if (seen.has(key)) {
      errors.push(`requestHeaders lists ${op.header} more than once.`);
      continue;
    }
    seen.add(key);
    if (!HEADER_OPERATIONS.includes(op.operation)) {
      errors.push(`requestHeaders operation must be one of: ${HEADER_OPERATIONS.join(", ")}.`);
      continue;
    }
    if (op.operation === "set") {
      // Printable ASCII only: no CR/LF header injection, no control chars.
      if (
        typeof op.value !== "string" ||
        !/^[\x20-\x7e]+$/.test(op.value) ||
        op.value.length > HEADER_VALUE_MAX
      ) {
        errors.push(
          `requestHeaders "set" for ${op.header} needs a printable-ASCII value (max ${HEADER_VALUE_MAX} chars).`,
        );
        continue;
      }
      ops.push({ header: op.header, operation: "set", value: op.value });
    } else {
      if (op.value !== undefined) {
        errors.push(`requestHeaders "remove" for ${op.header} must not have a value.`);
        continue;
      }
      ops.push({ header: op.header, operation: "remove" });
    }
  }
  return ops;
}

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
 *   "state": { "rule": "ha-jwt" },      // optional; "ha-jwt" (default) or "none"
 *   "requestHeaders": [                 // optional; applied to loginOrigins only
 *     { "header": "User-Agent", "operation": "set", "value": "Mozilla/5.0 (iPhone; …)" },
 *     { "header": "Sec-CH-UA", "operation": "remove" }
 *   ]
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

  const requestHeaders =
    raw.requestHeaders === undefined ? null : validateRequestHeaders(raw.requestHeaders, errors);

  if (errors.length) return { ok: false, errors };

  const profile = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    id: raw.id,
    name: raw.name.trim(),
    description: (raw.description || "").trim(),
    loginOrigins: [...raw.loginOrigins],
    capture: [{ type: "redirect", redirectPrefixes }],
    state: { rule: stateRule },
  };
  if (requestHeaders) profile.requestHeaders = requestHeaders;
  return { ok: true, profile };
}

/** All redirect prefixes of a validated profile, flattened. */
function profileRedirectPrefixes(profile) {
  return profile.capture
    .filter((s) => s.type === "redirect")
    .flatMap((s) => s.redirectPrefixes);
}

/**
 * Host of a validated login-origin pattern, for declarativeNetRequest's
 * requestDomains (which already matches subdomains):
 * "https://login.acme-app.com/*" -> "login.acme-app.com",
 * "https://*.acme-app.com/*" -> "acme-app.com".
 */
function loginOriginHost(pattern) {
  const host = pattern.slice("https://".length).split("/")[0].toLowerCase();
  return host.startsWith("*.") ? host.slice(2) : host;
}

/**
 * declarativeNetRequest dynamic rules for the given (enabled) profiles: one
 * modifyHeaders rule per profile that declares requestHeaders, scoped to its
 * login hosts. Used with declarativeNetRequestWithHostAccess, so a rule is
 * inert on any host whose permission the user has not granted.
 */
function buildHeaderRules(profiles) {
  const rules = [];
  for (const profile of profiles) {
    const ops = profile.requestHeaders || [];
    if (!ops.length) continue;
    const hosts = [...new Set(profile.loginOrigins.map(loginOriginHost))];
    if (hosts.includes("*")) continue; // "https://*/*" is not a login site
    rules.push({
      id: rules.length + 1,
      priority: 1,
      action: {
        type: "modifyHeaders",
        requestHeaders: ops.map((op) => ({ ...op })),
      },
      condition: {
        requestDomains: hosts,
        resourceTypes: [...HEADER_RULE_RESOURCE_TYPES],
      },
    });
  }
  return rules;
}

/** Loads the enabled-profiles map from storage: { [id]: { profile, enabled, source, addedAt } } */
async function loadProfileStore() {
  const { profiles } = await chrome.storage.local.get("profiles");
  return profiles || {};
}

/**
 * Bundled presets, loaded from the packaged profiles/ directory.
 * A build may ship without presets (no profiles/index.json) — that's fine;
 * providers are then added via import only.
 */
async function loadPresets() {
  let index;
  try {
    index = await (await fetch(chrome.runtime.getURL("profiles/index.json"))).json();
  } catch (e) {
    return [];
  }
  const presets = [];
  for (const file of index.presets || []) {
    // Per-file guard: one missing or broken preset must not drop the rest.
    try {
      const raw = await (await fetch(chrome.runtime.getURL(`profiles/${file}`))).json();
      const result = validateProfile(raw);
      if (result.ok) presets.push(result.profile);
      else console.error(`Bundled profile ${file} is invalid:`, result.errors);
    } catch (e) {
      console.error(`Could not load bundled profile ${file}:`, e);
    }
  }
  return presets;
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
    loginOriginHost,
    buildHeaderRules,
    loadProfileStore,
    loadPresets,
  };
}
