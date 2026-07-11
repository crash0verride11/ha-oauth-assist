/**
 * OAuth Assist for HA - capture page
 *
 * Fallback shown when a captured redirect could not be auto-forwarded to Home
 * Assistant (no HA flow state, or the provider returned an error). Reads the
 * payload from chrome.storage.local — never from the URL — so tokens don't
 * appear in history and content blockers' anti-redirect filters aren't tripped.
 */

function show(id) {
  document.getElementById(id).hidden = false;
}

function toast() {
  const t = document.getElementById("toast");
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2000);
}

/**
 * Encrypted-state flows. The code is ciphertext and the routing token lives in
 * the pending flow, not with the user — so masking the code and offering "copy"
 * would be theatre, and pasting it anywhere would accomplish nothing. Offer the
 * one action that can work: perform the same pinned forward, on a click.
 *
 * The tab binding enforced in background.js can't be checked from a page, but
 * this path is a deliberate user action on the tab the callback landed in, and
 * the destination is still the HA_FORWARD_URL constant. Nothing is widened.
 */
async function initStashed(lastCapture) {
  const { pendingFlow } = await chrome.storage.local.get("pendingFlow");
  const live =
    pendingFlow &&
    pendingFlow.stateHa &&
    pendingFlow.profileId === lastCapture.profileId &&
    Date.now() - (pendingFlow.time || 0) < (pendingFlow.ttlMs || 0) &&
    !pendingFlow.consumedFor;

  if (!live || (!lastCapture.code && !lastCapture.error)) {
    // No flow to forward into. This is also where HA's MANUAL sign-in path
    // lands (no sentinel ran, so nothing is pending): the user needs the raw
    // callback URL to paste into HA, and we intercepted it. Hand it back.
    const copyRaw = document.getElementById("copyRaw");
    if (lastCapture.raw) {
      copyRaw.addEventListener("click", async () => {
        await navigator.clipboard.writeText(lastCapture.raw);
        toast();
      });
    } else {
      copyRaw.parentElement.hidden = true;
    }
    show("stashedExpired");
    return;
  }

  document.getElementById("stashedProvider").textContent = lastCapture.profileId;
  document.getElementById("sendToHa").addEventListener("click", async () => {
    const haUrl = new URL(OAuthAssist.HA_FORWARD_URL);
    if (lastCapture.code) haUrl.searchParams.set("code", lastCapture.code);
    if (lastCapture.error) {
      haUrl.searchParams.set("error", lastCapture.error);
      if (lastCapture.errorDescription) {
        haUrl.searchParams.set("error_description", lastCapture.errorDescription);
      }
    }
    haUrl.searchParams.set("state", pendingFlow.stateHa);
    await chrome.storage.local.remove("pendingFlow");
    window.location.href = haUrl.toString();
  });
  show("stashed");
}

async function init() {
  const { lastCapture } = await chrome.storage.local.get("lastCapture");

  // Only show a capture from the last 10 minutes; older ones are stale.
  if (!lastCapture || Date.now() - lastCapture.time > 10 * 60 * 1000) {
    show("noCode");
    return;
  }

  if (lastCapture.rule === "stashed") {
    await initStashed(lastCapture);
    return;
  }

  if (lastCapture.error && !lastCapture.code) {
    document.getElementById("errName").textContent = lastCapture.error;
    if (lastCapture.errorDescription) {
      document.getElementById("errDesc").textContent = lastCapture.errorDescription;
      document.getElementById("errDescWrap").hidden = false;
    }
    show("failure");
    return;
  }

  if (!lastCapture.code) {
    show("noCode");
    return;
  }

  document.getElementById("provider").textContent = lastCapture.profileId;
  const code = lastCapture.code;
  const masked = "•".repeat(Math.max(0, code.length - 4)) + code.slice(-4);
  document.getElementById("authCode").textContent = masked;

  document.getElementById("copyCode").addEventListener("click", async () => {
    await navigator.clipboard.writeText(code);
    toast();
  });

  if (lastCapture.state) {
    const btn = document.getElementById("copyState");
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(lastCapture.state);
      toast();
    });
  }

  show("success");
}

init();
