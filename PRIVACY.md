# Privacy policy — OAuth Assist for HA

OAuth Assist for HA runs entirely in your browser. It has no servers, no
analytics, and makes no network requests of its own.

**What it handles.** When a login flow for a provider profile you enabled
ends on that profile's redirect URL, the extension reads the OAuth
authorization code and state from that URL. If the state belongs to a
Home Assistant login flow, it sends your browser tab to Home Assistant's
official redirect service, `https://my.home-assistant.io/redirect/oauth`,
which passes the code to your own Home Assistant instance. Otherwise it
shows the code on a local page for you to copy. This destination is fixed
in the extension and cannot be changed by a profile.

**What it stores.** Your enabled provider profiles and the most recent
captured code, in the browser's local extension storage on your device.
Nothing is synced or sent to the developer or anyone else.

**Request headers.** A profile may change the User-Agent and related
browser-identity headers on its own login site, only after you enable it.

**Cookies.** If you click "Clear login cookies" in the popup, the
extension deletes cookies for your active providers' login sites. It does
not read or keep their contents.

The developer does not collect, sell, or share any user data.

Questions: use the support link or contact email on the extension's store
listing.
