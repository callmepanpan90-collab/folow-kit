/**
 * Content script — bridge between background.js and injected.js
 * Injects injected.js into MAIN world to access window.grecaptcha
 */
(function () {
  try {
    const s = document.createElement('script');
    let src = chrome.runtime.getURL('injected.js');
    if (window.trustedTypes && window.trustedTypes.defaultPolicy) {
      src = window.trustedTypes.defaultPolicy.createScriptURL(src);
    }
    s.src = src;
    s.onload = () => s.remove();
    (document.head || document.documentElement).appendChild(s);
  } catch (e) {
    // Expected on Trusted Types pages — injected.js is injected via chrome.scripting in background.js
  }
})();

chrome.runtime.onMessage.addListener((msg, _, reply) => {
  if (msg.type === 'GET_SESSION') {
    (async () => {
      try {
        const endpoints = ['/fx/api/auth/session', '/api/auth/session'];
        for (const ep of endpoints) {
          try {
            const res = await fetch(ep, { credentials: 'include' });
            if (res.ok) {
              const data = await res.json();
              if (data && data.accessToken) {
                reply({ token: data.accessToken, expires: data.expires });
                return;
              }
            }
          } catch {}
        }
        reply({ error: 'NO_SESSION' });
      } catch (err) {
        reply({ error: err?.message || String(err) });
      }
    })();
    return true; // keep channel open for async reply
  }

  if (msg.type === 'TAB_API_REQUEST') {
    const { requestId, url, method, headers, body, captchaAction } = msg;

    const handler = (e) => {
      if (e.detail?.requestId === requestId) {
        window.removeEventListener('TAB_API_RESULT', handler);
        clearTimeout(timer);
        reply({ status: e.detail.status, data: e.detail.data, error: e.detail.error });
      }
    };

    const timer = setTimeout(() => {
      window.removeEventListener('TAB_API_RESULT', handler);
      reply({ error: 'TAB_API_TIMEOUT' });
    }, 120000);

    window.addEventListener('TAB_API_RESULT', handler);

    window.dispatchEvent(new CustomEvent('RUN_TAB_API_REQUEST', {
      detail: { requestId, url, method, headers, body, captchaAction },
    }));

    return true; // keep channel open for async reply
  }

  if (msg.type !== 'GET_CAPTCHA') return;

  const { requestId, pageAction } = msg;

  const handler = (e) => {
    if (e.detail?.requestId === requestId) {
      window.removeEventListener('CAPTCHA_RESULT', handler);
      clearTimeout(timer);
      reply({ token: e.detail.token, error: e.detail.error });
    }
  };

  const timer = setTimeout(() => {
    window.removeEventListener('CAPTCHA_RESULT', handler);
    reply({ error: 'CONTENT_TIMEOUT' });
  }, 45000);

  window.addEventListener('CAPTCHA_RESULT', handler);

  window.dispatchEvent(new CustomEvent('GET_CAPTCHA', {
    detail: { requestId, pageAction },
  }));

  return true; // keep channel open for async reply
});

// ─── TRPC Media URL Monitor ─────────────────────────────────
// Forward intercepted TRPC responses with media URLs to background.js
window.addEventListener('TRPC_MEDIA_URLS', (e) => {
  const { url, body } = e.detail || {};
  if (!body) return;
  chrome.runtime.sendMessage({
    type: 'TRPC_MEDIA_URLS',
    trpcUrl: url,
    body,
  }).catch(() => {});
});

// ─── Auto Sign-in Assistant ──────────────────────────────────
// Automatically scans for "Sign in" or "Đăng nhập" buttons and triggers a click to streamline account switching.

let isAuthClicked = false;

async function tryAutoLogin(observerInstance) {
  if (isAuthClicked) return;

  try {
    const data = await chrome.storage.local.get('quotaErrorState');
    if (data.quotaErrorState === true) {
      console.warn('[FlowAgent] Auto Sign-in suspended: quota error state is active. Please switch accounts manually.');
      
      // Inject a banner to notify the user
      if (document.body) {
        let banner = document.getElementById('flowkit-quota-banner');
        if (!banner) {
          banner = document.createElement('div');
          banner.id = 'flowkit-quota-banner';
          banner.style.cssText = 'position: fixed; top: 12px; left: 50%; transform: translateX(-50%); background-color: #ef4444; color: white; padding: 12px 24px; border-radius: 8px; z-index: 10000; font-family: system-ui, -apple-system, sans-serif; font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.15); border: 2px solid #b91c1c; text-align: center; max-width: 90%;';
          banner.innerHTML = '⚠️ Flowkit: Quota limit reached! Auto Sign-in suspended to allow account switching. Please select/sign in with a different Google account.';
          document.body.appendChild(banner);
        }
      }
      return;
    }
  } catch (err) {
    console.error('[FlowAgent] Error checking quota state:', err);
  }

  const buttons = document.querySelectorAll('button, [role="button"], a');
  for (const btn of buttons) {
    const text = btn.textContent.trim().toLowerCase();
    // Match common Google Labs/Flow login phrases
    if (
      text === 'sign in' || 
      text === 'log in' || 
      text === 'đăng nhập' || 
      text.includes('sign in with google') || 
      text.includes('đăng nhập với google')
    ) {
      console.log('[FlowAgent] Auto Sign-in: found login button, clicking it!', btn);
      isAuthClicked = true;
      btn.click();
      if (observerInstance) observerInstance.disconnect();
      return;
    }
  }
}

// Observe page changes to catch the button dynamically as the page renders
if (window.location.hostname === 'labs.google') {
  console.log('[FlowAgent] Auto Sign-in monitoring active...');
  
  // Try immediately on script load
  tryAutoLogin();

  const observer = new MutationObserver((mutations, obs) => {
    tryAutoLogin(obs);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

  // Fallback try when window is fully loaded
  window.addEventListener('load', () => {
    tryAutoLogin(observer);
  });
}

// Keep service worker alive via port connection
let keepAlivePort = null;
function connectKeepAlive() {
  if (keepAlivePort) return;
  try {
    keepAlivePort = chrome.runtime.connect({ name: 'flowkit-keepalive' });
    keepAlivePort.onDisconnect.addListener(() => {
      keepAlivePort = null;
      setTimeout(connectKeepAlive, 1000);
    });
  } catch (e) {
    // Ignore error
  }
}
connectKeepAlive();

// Periodic ping to keep service worker awake
setInterval(() => {
  try {
    chrome.runtime.sendMessage({ type: 'KEEPALIVE_PING' }).catch(() => {});
  } catch (e) {
    // Ignore error
  }
}, 10000);

