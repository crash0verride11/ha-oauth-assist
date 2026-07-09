/**
 * OAuth Assist for HA - popup
 *
 * Shows which provider profiles are active and offers a cookie-clear helper
 * (useful to force a fresh login). The "cookies" permission is optional and
 * only requested when the user clicks the clear button.
 */

// Note: no destructuring into top-level const here — shared.js's function
// declarations live in the same global scope as this classic script, so
// `const loadProfileStore = …` would be a duplicate-identifier SyntaxError.
const OA = globalThis.OAuthAssist;

const activeEl = document.getElementById("active");
const cookieStatusEl = document.getElementById("cookie-status");

async function activeProfiles() {
  const store = await OA.loadProfileStore();
  return Object.values(store).filter((e) => e.enabled);
}

async function render() {
  const enabled = await activeProfiles();
  activeEl.textContent = "";
  if (!enabled.length) {
    const none = document.createElement("span");
    none.className = "none";
    none.textContent = "No providers active yet — open “Manage providers” to enable one.";
    activeEl.append(none);
    return;
  }
  activeEl.append(`Active providers (${enabled.length}):`);
  const ul = document.createElement("ul");
  for (const e of enabled) {
    const li = document.createElement("li");
    li.textContent = e.profile.name;
    ul.append(li);
  }
  activeEl.append(ul);
}

document.getElementById("open-options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

/** Hostname (minus wildcard) from a match pattern like "https://*.example.com/*". */
function patternToDomain(pattern) {
  const m = pattern.match(/^https:\/\/(\*\.)?([^/*]+)\//);
  return m ? m[2] : null;
}

document.getElementById("clear-cookies").addEventListener("click", async () => {
  const enabled = await activeProfiles();
  if (!enabled.length) {
    cookieStatusEl.textContent = "No active providers.";
    return;
  }

  const granted = await chrome.permissions.request({ permissions: ["cookies"] });
  if (!granted) {
    cookieStatusEl.textContent = "Cookie permission declined.";
    return;
  }

  const domains = new Set();
  for (const e of enabled) {
    for (const o of e.profile.loginOrigins) {
      const d = patternToDomain(o);
      if (d) domains.add(d);
    }
  }

  cookieStatusEl.textContent = "Clearing…";
  const all = (
    await Promise.all([...domains].map((domain) => chrome.cookies.getAll({ domain })))
  ).flat();

  if (!all.length) {
    cookieStatusEl.textContent = "No cookies found for active providers.";
    return;
  }

  await Promise.all(
    all.map((cookie) =>
      chrome.cookies.remove({
        url:
          "http" +
          (cookie.secure ? "s" : "") +
          "://" +
          cookie.domain.replace(/^\./, "") +
          cookie.path,
        name: cookie.name,
      }),
    ),
  );
  cookieStatusEl.textContent = `Cleared ${all.length} cookie${all.length !== 1 ? "s" : ""}. Ready for a fresh login.`;
});

render();
