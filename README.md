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
  navigations it initiates are rewriting the current tab to the Home
  Assistant redirect URL (or a local capture page) and, for a handoff, to
  the profile's own login site.
- **Auto-forward is gated.** By default a code is forwarded only when the
  OAuth `state` is a Home Assistant flow token (a JWT carrying `flow_id`).
  Anything else lands on a local capture page for manual copy.
- **Header changes are narrow.** A profile may change browser-identity
  request headers (`User-Agent`, `Sec-CH-UA*`) on its own login site, and
  nothing else: no cookies, credentials, or origin headers, and no other
  hosts. The changes are listed on the options page before you enable it.
- **Handoffs are untrusted input.** Any web page can open a handoff link
  ([Handoff](#handoff-schema-v2)), so the extension acts on one only for an
  enabled `stashed` profile, in a top-level tab, with a sign-in URL inside
  that profile's `loginOrigins` and a token shaped like a Home Assistant flow
  token. The stashed token is bound to the tab and profile and expires
  quickly. A planted handoff still ends at your own Home Assistant, where its
  token names no real flow, so the worst case is a failed login.

## Repository layout

- [extension/](extension/) — the extension itself (load this directory
  unpacked for development).
- [extension/profiles/](extension/profiles/) — the
  [profile schema](extension/profiles/profile.schema.json). Provider profiles
  themselves are not part of this repository; they are loaded by the user.
- [scripts/build.js](scripts/build.js) — reproducible store packages (see
  [Packaging](#packaging)).
- [tests/](tests/) — Node-based tests for profile validation and the
  capture/forward logic (`node tests/test_shared.js`) and for the packager
  (`node tests/test_build.js`).

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
  flows; `"none"`: forward whenever `code` and `state` are present;
  `"stashed"` (schema v2): see [Handoff](#handoff-schema-v2).
- `capture` — a list of steps. Schema v1 has only `"redirect"`; v2 adds an
  optional `"initiation"` step before it.
- `requestHeaders` (optional) — header changes for requests to the
  `loginOrigins` hosts, for identity providers that reject desktop browsers:

  ```json
  "requestHeaders": [
    { "header": "User-Agent", "operation": "set",
      "value": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1" },
    { "header": "Sec-CH-UA", "operation": "remove" },
    { "header": "Sec-CH-UA-Mobile", "operation": "remove" },
    { "header": "Sec-CH-UA-Platform", "operation": "remove" }
  ]
  ```

  The values live in the profile, so a provider change needs only a profile
  update, not a new extension release. Only `User-Agent` and
  `Sec-CH-UA` / `Sec-CH-UA-*` may be touched, with `set` or `remove`. This
  changes request headers only; page JavaScript still sees the real
  `navigator.userAgent`.

### Handoff (schema v2)

Some providers feed Home Assistant's `state` into their own encryption and
return ciphertext, so the callback can't be recognized as a Home Assistant
flow. For those, Home Assistant hands the extension its flow token *before*
the login starts:

```json
{
  "schemaVersion": 2,
  "id": "acme-app",
  "name": "Acme App",
  "loginOrigins": ["https://login.acme-app.com/*"],
  "capture": [
    { "type": "initiation", "ttlSeconds": 600 },
    { "type": "redirect", "redirectPrefixes": ["com.acme.app://"] }
  ],
  "state": { "rule": "stashed" }
}
```

1. The integration sends the browser to a handoff link, with the parameters
   in the URL **fragment** so they never leave the machine:

   ```
   https://ha-oauth-assist.example.com/initiate/<profile id>#state_HA=<HA state>&signin_url=<provider sign-in URL>
   ```

   `ha-oauth-assist-initiate://start/<profile id>#…` is accepted too.
   Integrations should prefer the https form: it pastes reliably, while a
   pasted custom-scheme URL may be turned into a web search, fragment and
   all.
2. The extension stores `state_HA` for that tab and profile, then opens
   `signin_url`. It refuses a `signin_url` outside the profile's
   `loginOrigins`.
3. When the provider redirects back, the extension forwards the `code` (or
   `error`) to Home Assistant's redirect service with the stored `state_HA`.
   The provider's own `state` is never forwarded.

If the callback can't be forwarded automatically (for example, it lands in
a different tab), the capture page offers *Send to Home Assistant* until
the flow expires after `ttlSeconds` (60–900, default 600). After that, or
when no handoff happened, it offers the raw callback URL, which is what
Home Assistant's manual sign-in step needs.

The initiation step carries no URLs: the handoff addresses are constants
in the extension, just like the forward destination. `initiation` and
`stashed` require each other.

Providers are added by importing a profile JSON on the options page — no code
changes. A packaged build may additionally ship presets via
`profiles/index.json`; the extension works fine without any.

## Install

- **Chrome / Edge:** [Chrome Web Store](https://chromewebstore.google.com/detail/oauth-assist-for-ha/mdoleppdlojmeeogmmocmjnkemecaofh).
  In Edge, allow extensions from other stores when prompted.
- **Firefox:** coming to Firefox Add-ons (AMO).

Then import the provider profile published with your integration on the
extension's options page, click *Enable*, accept the site-permission prompt,
and start the integration's login from Home Assistant as usual.

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

## Packaging

```sh
node scripts/build.js [git-ref]   # default: HEAD
```

This writes `dist/oauth-assist-for-ha-<version>-chrome.zip` and
`-firefox.zip` and prints their SHA-256 hashes. You need Node and git, and
nothing else.

- **Built from git, not the working directory.** Only files committed under
  `extension/` at the given ref are packaged. Uncommitted edits and
  untracked files (such as locally loaded profiles) are never included.
- **Reproducible.** Entries are sorted, stored uncompressed, and stamped with
  a fixed date. Rebuilding the same commit on any machine gives the same
  bytes, so you can check a store package against its tag by comparing the
  printed hashes.
- **One manifest per browser.** The Firefox package ships
  `manifest.firefox.json` as its `manifest.json`. The build fails if the two
  manifests differ in anything other than `background` and
  `browser_specific_settings`, so bump `version` in both.

### Releasing

Bump `version` in both manifests, commit, then push a matching tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The [release workflow](.github/workflows/release.yml) runs the tests,
checks that the tag matches the manifest version, builds both packages, and
publishes a GitHub release with the zips and their SHA-256 hashes. Uploading
to the Chrome Web Store and Firefox AMO is done by hand from those zips.

## How it works

The background worker listens to `webNavigation.onBeforeNavigate` /
`onErrorOccurred` (custom schemes surface in one or the other depending on
browser) and `tabs.onUpdated` (for IdPs that reach the callback via
`history.pushState`). A navigation matching an enabled profile's redirect
prefix is parsed for `code` and `state`; Home Assistant flows are rewritten to
the pinned redirect service, everything else goes to the local capture page.
Captured values pass through `chrome.storage`, never through page URLs.

Handoff links are caught by the same `webNavigation` listeners. The pending
flow is written to `chrome.storage` before the tab is sent to the sign-in
page, so it survives the service worker being stopped mid-login, and it is
cleared on browser startup.

Profiles with `requestHeaders` become `declarativeNetRequest` dynamic rules,
rebuilt whenever the enabled profiles change. The extension uses
`declarativeNetRequestWithHostAccess`, so a rule has no effect on any host
whose permission you haven't granted.

Enabling a profile stores a copy of it. On extension update, copies of bundled
presets are refreshed from the packaged versions. If a new version needs a
login site you haven't granted, it is switched off until you enable it again.
Re-importing an imported profile replaces it and switches it off, so enabling
it asks for consent to the new version.

## Icons

Interim icon set. The 32 and 96 px sizes are downscaled from the 128 px icon.
A redesigned set may replace it in a later release.

## Roadmap

1. Publish a signed build to Firefox AMO (Chrome Web Store: done).
2. Link the reproducible build ([Packaging](#packaging)) from the store
   listings.
