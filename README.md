# OAuth Assist for HA

A single, generic browser extension (Chrome/Edge + Firefox, Manifest V3) that
captures mobile-app OAuth redirects — custom-scheme URLs like
`com.acme.app://callback?code=…&state=…` that desktop browsers cannot follow — and hands
the authorization code to **Home Assistant's official redirect service**.

It replaces per-vendor "OAuth helper" extensions with one auditable tool whose
provider support comes from small, loadable **config profiles** instead of
code changes.

## Why this exists

Some cloud integrations (car apps, utility portals, …) register their OAuth
`redirect_uri` as the mobile app's custom URL scheme, and the identity
provider rejects every other reply URL. When you run the login in a desktop
browser for Home Assistant, the flow ends on a URL the browser can't render —
something has to intercept it and route the code back to Home Assistant. This
extension is that something.

## Trust model (read this first)

- **Fixed destination.** Captured codes are only ever forwarded to
  `https://my.home-assistant.io/redirect/oauth`. This is a constant in
  [extension/shared.js](extension/shared.js); no profile, setting, or import
  can change it. Profiles configure *what to watch*, never *where to send*.
- **Empty by default.** The extension ships with no host access. Enabling a
  provider profile triggers a browser permission prompt for that provider's
  login site only (`optional_host_permissions` + `chrome.permissions.request`).
- **No remote code, no analytics, no network calls of its own.** The only
  navigation it initiates is rewriting the current tab to the Home Assistant
  redirect URL (or a local capture page).
- **Auto-forward is gated.** By default a code is forwarded only when the
  OAuth `state` is a Home Assistant flow token (a JWT carrying `flow_id`).
  Anything else lands on a local capture page for manual copy.

## Repository layout

- [extension/](extension/) — the extension itself (load this directory
  unpacked while unsigned; store publication is the goal).
- [extension/profiles/](extension/profiles/) — the
  [profile schema](extension/profiles/profile.schema.json). Provider profiles
  themselves are not part of this repository; they are loaded by the user.
- [tests/](tests/) — Node-based tests for profile validation and the
  capture/forward logic (`node tests/test_shared.js`).

## Provider profiles

A profile is a small JSON file declaring what to watch for one provider:

```json
{
  "schemaVersion": 1,
  "id": "acme-app",
  "name": "Acme App",
  "loginOrigins": ["https://login.acme-app.com/*"],
  "capture": [
    {
      "type": "redirect",
      "redirectPrefixes": ["com.acme.app://", "https://login.acme-app.com/ios/"]
    }
  ],
  "state": { "rule": "ha-jwt" }
}
```

- `loginOrigins` — https match patterns for the provider's login pages;
  enabling the profile requests a runtime host permission for these.
- `capture[].redirectPrefixes` — URL prefixes to intercept: the mobile app's
  custom scheme, and/or an https callback prefix. `http://` prefixes and
  `my.home-assistant.io` itself are rejected by validation.
- `state.rule` — `"ha-jwt"` (default): auto-forward only for Home Assistant
  flows; `"none"`: forward whenever `code` and `state` are present.
- `capture` is an array so future step types (e.g. an *initiation capture*
  earlier in the flow, as some providers require) can be added without a
  schema rewrite. v1 supports only `"redirect"`.

Providers are added by importing a profile JSON on the options page — no code
changes. A packaged build may additionally ship presets via
`profiles/index.json`; the extension works fine without any.

## Install (development)

1. `chrome://extensions` → enable Developer mode → *Load unpacked* → select
   [extension/](extension/). For Firefox, first swap in the Firefox manifest
   (Chrome MV3 requires `background.service_worker`, Firefox MV3 requires
   `background.scripts`, and each rejects the other's key): copy the
   `extension/` folder, replace its `manifest.json` with
   [manifest.firefox.json](extension/manifest.firefox.json), then
   `about:debugging` → *Load Temporary Add-on*.
2. Open the extension's options page, enable a provider, and accept the
   site-permission prompt.
3. Start the integration's login from Home Assistant as usual.

Store publication (Chrome Web Store + Firefox AMO) is the roadmap's top
priority precisely so step 1 stops involving Developer mode.

## How it works

The background worker listens to `webNavigation.onBeforeNavigate` /
`onErrorOccurred` (custom schemes surface in one or the other depending on
browser) and `tabs.onUpdated` (for IdPs that reach the callback via
`history.pushState`). A navigation matching an enabled profile's redirect
prefix is parsed for `code` and `state`; Home Assistant flows are rewritten to
the pinned redirect service, everything else goes to the local capture page.
Captured values pass through `chrome.storage`, never through page URLs.

## Icons

Interim icon set. A Home Assistant–themed set will replace it before store
submission.

## Roadmap

1. Publish signed builds to the Chrome Web Store and Firefox AMO.
2. Reproducible build/packaging script linked from the store listings.
3. Phase 2: an `initiation` capture step type for providers whose flow needs
   an extra handoff before the final redirect.
