/**
 * Injected into MAIN world on labs.google / flow.google.com — has access to window.grecaptcha
 * Also intercepts TRPC fetch responses to capture fresh signed media URLs.
 */
const SITE_KEY = '6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV';

// ─── TRPC Response Monitor ─────────────────────────────────
if (!window.__flowkit_fetch_patched) {
  window.__flowkit_fetch_patched = true;
  const _originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await _originalFetch.apply(this, args);
    try {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      if (url.includes('/fx/api/trpc/') && response.ok) {
        const clone = response.clone();
        clone.text().then(text => {
          if (text.includes('storage.googleapis.com/ai-sandbox-videofx/')) {
            window.dispatchEvent(new CustomEvent('TRPC_MEDIA_URLS', {
              detail: { url, body: text },
            }));
          }
        }).catch(() => {});
      }
    } catch {}
    return response;
  };
}

// ─── Trusted Types Helper ──────────────────────────────────
let _flowkitPolicy = null;
function getTrustedScriptURL(url) {
  if (!window.trustedTypes || typeof window.trustedTypes.createPolicy !== 'function') {
    return url;
  }
  if (_flowkitPolicy) {
    try { return _flowkitPolicy.createScriptURL(url); } catch (e) {}
  }
  try {
    _flowkitPolicy = window.trustedTypes.createPolicy('flowkit-policy-' + Math.floor(Math.random() * 100000), {
      createScriptURL: (u) => u,
    });
    return _flowkitPolicy.createScriptURL(url);
  } catch (e) {
    if (window.trustedTypes.defaultPolicy) {
      try { return window.trustedTypes.defaultPolicy.createScriptURL(url); } catch (e2) {}
    }
    return url;
  }
}

// ─── Project ID Extractor ──────────────────────────────────
function getActiveProjectId() {
  try {
    const m = window.location.pathname.match(/\/project\/([a-zA-Z0-9_-]+)/);
    if (m && m[1]) return m[1];
  } catch {}
  try {
    const qId = window.__NEXT_DATA__?.query?.projectId;
    if (qId) return qId;
  } catch {}
  try {
    const sId = window.__NEXT_DATA__?.props?.pageProps?.projectDetails?.id;
    if (sId) return sId;
  } catch {}
  return null;
}

// ─── Intercept Original Execute ────────────────────────────
// Flow's React app monkey-patches grecaptcha.enterprise.execute later in the lifecycle.
// By defining property setters at document_start, we intercept the exact moment 
// Google's script defines the original function, BEFORE React can wrap it!
window.__flowkit_original_execute = window.__flowkit_original_execute || null;

if (!window.__flowkit_execute_hooked) {
  window.__flowkit_execute_hooked = true;
  
  let _grecaptcha = window.grecaptcha;
  
  function hookEnterprise(eVal) {
    if (!eVal || eVal.__flowkit_intercepted) return;
    eVal.__flowkit_intercepted = true;
    
    let _execute = eVal.execute;
    
    // If execute is ALREADY defined on the object being assigned, capture it immediately!
    if (_execute && typeof _execute === 'function' && !window.__flowkit_original_execute) {
      window.__flowkit_original_execute = _execute;
      console.log('[FlowAgent] Captured pristine grecaptcha.enterprise.execute on init!');
    }
    
    Object.defineProperty(eVal, 'execute', {
      get: function() { return _execute; },
      set: function(exVal) {
        if (exVal && typeof exVal === 'function' && !window.__flowkit_original_execute) {
          window.__flowkit_original_execute = exVal;
          console.log('[FlowAgent] Captured pristine grecaptcha.enterprise.execute via setter!');
        }
        _execute = exVal;
      },
      enumerable: true,
      configurable: true
    });
  }
  
  function hookGrecaptcha(val) {
    if (!val || val.__flowkit_intercepted) return;
    val.__flowkit_intercepted = true;
    
    let _enterprise = val.enterprise;
    
    // If enterprise is already there, hook it immediately!
    if (_enterprise) {
      hookEnterprise(_enterprise);
    }
    
    Object.defineProperty(val, 'enterprise', {
      get: function() { return _enterprise; },
      set: function(eVal) {
        hookEnterprise(eVal);
        _enterprise = eVal;
      },
      enumerable: true,
      configurable: true
    });
  }

  // If grecaptcha is already defined before this script runs, hook it immediately
  if (_grecaptcha) {
    hookGrecaptcha(_grecaptcha);
  }

  Object.defineProperty(window, 'grecaptcha', {
    get: function() { return _grecaptcha; },
    set: function(val) {
      hookGrecaptcha(val);
      _grecaptcha = val;
    },
    enumerable: true,
    configurable: true
  });
}

// ─── Captcha Solver (Enterprise) ───────────────────────────
async function getEnterpriseToken(action = 'VIDEO_GENERATION') {
  try {
    console.log('[FlowAgent] Requesting token via captured original execute for action:', action);
    
    // Wait for the enterprise to be available
    const start = Date.now();
    while (!window.grecaptcha?.enterprise?.execute && Date.now() - start < 5000) {
      await new Promise(r => setTimeout(r, 100));
    }
    
    if (window.grecaptcha?.enterprise?.execute) {
      await Promise.race([
        new Promise(resolve => {
          try {
            if (typeof window.grecaptcha.enterprise.ready === 'function') {
              window.grecaptcha.enterprise.ready(() => resolve(true));
            } else {
              resolve(true);
            }
          } catch {
            resolve(true);
          }
        }),
        new Promise(resolve => setTimeout(() => resolve(false), 2000))
      ]);
      
      const executeFn = window.__flowkit_original_execute || window.grecaptcha.enterprise.execute;
      
      const token = await Promise.race([
        executeFn.call(window.grecaptcha.enterprise, SITE_KEY, { action }),
        new Promise((_, rej) => setTimeout(() => rej(new Error('execute_timeout')), 4000))
      ]);
      
      if (token) {
        console.log(`[FlowAgent] CLEAN Token obtained for ${action}!`);
        return token;
      }
    }
  } catch (err) {
    console.warn('[FlowAgent] getEnterpriseToken warning:', err?.message || err);
  }
  return 'recaptcha-token-unknown';
}

if (window.__flowkit_captcha_handler) {
  window.removeEventListener('GET_CAPTCHA', window.__flowkit_captcha_handler);
}

window.__flowkit_captcha_handler = async ({ detail }) => {
  const { requestId, pageAction } = detail;
  try {
    const token = await getEnterpriseToken(pageAction || 'VIDEO_GENERATION');
    window.dispatchEvent(new CustomEvent('CAPTCHA_RESULT', {
      detail: { requestId, token },
    }));
  } catch (e) {
    console.error('[FlowAgent] GET_CAPTCHA error:', e);
    window.dispatchEvent(new CustomEvent('CAPTCHA_RESULT', {
      detail: { requestId, token: 'recaptcha-token-unknown' },
    }));
  }
};

window.addEventListener('GET_CAPTCHA', window.__flowkit_captcha_handler);

// ─── Direct Tab Fetch Executor ──────────────────────────────
// Executes requests directly inside labs.google page context so Origin, Referer,
// and session cookies perfectly match Google's requirements.
if (window.__flowkit_tab_api_handler) {
  window.removeEventListener('RUN_TAB_API_REQUEST', window.__flowkit_tab_api_handler);
}

window.__flowkit_tab_api_handler = async ({ detail }) => {
  let { requestId, url, method, headers, body, captchaAction } = detail;
  try {
    const activeProjId = getActiveProjectId();

    // Clean URL: strip ?key= if aisandbox API with Authorization header
    if (url && url.includes('aisandbox-pa.googleapis.com')) {
      url = url.replace(/([?&])key=[^&]+(&|$)/, '$1').replace(/[?&]$/, '');
    }

    // Fix project ID in URL if applicable
    if (activeProjId && url) {
      url = url.replace(/00000000-0000-0000-0000-000000000000/g, activeProjId);
      url = url.replace(/a3c09e15-0571-4e8f-bd17-c19ca7d49fe1/g, activeProjId);
      
      // Fallback: If it somehow still has a wrong project ID in the URL structure
      if (url.includes('/projects/') && url.includes('/flowMedia')) {
        url = url.replace(/\/projects\/[^\/]+\/flowMedia/, `/projects/${activeProjId}/flowMedia`);
      }
      if (url.includes('clientContext.projectId=')) {
        url = url.replace(/clientContext\.projectId=[^&]+/, `clientContext.projectId=${activeProjId}`);
      }
    }

    let finalBody = body;
    let token = null;
    if (captchaAction) {
      token = await getEnterpriseToken(captchaAction);
    }

    if (finalBody) {
      // Aggressively replace the dummy project ID everywhere in the payload string
      let bodyStr = JSON.stringify(finalBody);
      if (activeProjId) {
        // Handle both the all-zeros dummy ID and the hardcoded UUID in python
        bodyStr = bodyStr.replace(/00000000-0000-0000-0000-000000000000/g, activeProjId);
        bodyStr = bodyStr.replace(/a3c09e15-0571-4e8f-bd17-c19ca7d49fe1/g, activeProjId);
      }
      finalBody = JSON.parse(bodyStr);

      if (token) {
        if (finalBody.clientContext?.recaptchaContext) {
          finalBody.clientContext.recaptchaContext.token = token;
        }
      }
      if (finalBody.requests && Array.isArray(finalBody.requests)) {
        for (const req of finalBody.requests) {
          if (token && req.clientContext?.recaptchaContext) {
            req.clientContext.recaptchaContext.token = token;
          }
        }
      }
    }

    const fetchHeaders = { ...(headers || {}) };
    if (method !== 'GET') {
      if (!fetchHeaders['content-type'] && !fetchHeaders['Content-Type']) {
        fetchHeaders['Content-Type'] = 'application/json';
      }
    } else {
      delete fetchHeaders['content-type'];
      delete fetchHeaders['Content-Type'];
    }

    console.log(`[FlowAgent Tab API] Fetching ${method || 'POST'} ${url} (projId: ${activeProjId || 'none'})...`);

    const resp = await window.fetch(url, {
      method: method || 'POST',
      headers: fetchHeaders,
      credentials: 'include',
      body: method === 'GET' ? undefined : (typeof finalBody === 'string' ? finalBody : JSON.stringify(finalBody)),
    });

    let data;
    const text = await resp.text();
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    console.log(`[FlowAgent Tab API] Response ${resp.status} for ${url}`);

    window.dispatchEvent(new CustomEvent('TAB_API_RESULT', {
      detail: { requestId, status: resp.status, data },
    }));
  } catch (err) {
    console.error('[FlowAgent] RUN_TAB_API_REQUEST error:', err);
    window.dispatchEvent(new CustomEvent('TAB_API_RESULT', {
      detail: { requestId, error: err?.message || String(err) },
    }));
  }
};

window.addEventListener('RUN_TAB_API_REQUEST', window.__flowkit_tab_api_handler);
console.log('[FlowAgent] injected.js loaded, listeners active (CAPTCHA + TAB_API)');
