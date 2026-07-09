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

async function init() {
  const { lastCapture } = await chrome.storage.local.get("lastCapture");

  // Only show a capture from the last 10 minutes; older ones are stale.
  if (!lastCapture || Date.now() - lastCapture.time > 10 * 60 * 1000) {
    show("noCode");
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
