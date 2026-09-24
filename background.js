/**
 * Flow Kit — Chrome Extension Background Service Worker
 *
 * Connects to local Python agent via WebSocket (agent runs WS server).
 * Captures bearer token, solves reCAPTCHA, proxies API calls through browser.
 */

const AGENT_WS_URL = 'ws://127.0.0.1:9888';
// NOTE: This is a browser-restricted public API key — safe to ship in extension bundles.
const API_KEY = 'AIzaSyBtrm0o5ab1c-Ec8ZuLcGt3oJAA5VWt3pY';

let ws = null;
let flowKey = null;
let callbackSecret = null;  // Auth secret for HTTP callback, received from server on WS connect
let state = 'off'; // off | idle | running
let manualDisconnect = false;
let metrics = {
  tokenCapturedAt: null,
  requestCount: 0,   // captcha-consuming requests only (gen image/video/upscale)
  successCount: 0,
  failedCount: 0,
  lastError: null,
};

// Ensure Origin and Referer are always set to https://flow.google.com on outgoing aisandbox
// requests. Đặt labs.google như trước là khai sai nguồn: token reCAPTCHA nay đúc ở
// flow.google.com, lệch hostname thì backend trả 403 PUBLIC_ERROR_UNUSUAL_ACTIVITY.
if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.updateDynamicRules) {
  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [101],
    addRules: [
      {
        id: 101,
        priority: 2,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [
            { header: 'Referer', operation: 'set', value: 'https://flow.google.com/' },
            { header: 'Origin', operation: 'set', value: 'https://flow.google.com' },
          ],
        },
        condition: {
          urlFilter: 'aisandbox-pa.googleapis.com',
          resourceTypes: ['xmlhttprequest', 'other', 'sub_frame', 'main_frame'],
        },
      },
    ],
  }).catch((err) => console.warn('[FlowAgent] DNR update error:', err));
}

// ─── URL → Log Type Classifier ─────────────────────────────

// Visible log types — only these appear in the request log
const _VISIBLE_TYPES = new Set(['GEN_IMG', 'GEN_VID', 'GEN_VID_REF', 'UPSCALE', 'TRACKING', 'URL_REFRESH']);

function _classifyApiUrl(url) {
  if (url.includes('uploadImage'))                     return 'UPLOAD';
  if (url.includes('batchGenerateImages'))              return 'GEN_IMG';
  if (url.includes('UpsampleVideo'))                   return 'UPSCALE';
  if (url.includes('ReferenceImages'))                 return 'GEN_VID_REF';
  if (url.includes('batchAsyncGenerateVideo'))          return 'GEN_VID';
  if (url.includes('batchCheckAsync'))                  return 'POLL';
  if (url.includes('upsampleImage'))                   return 'UPS_IMG';
  if (url.includes('/media/'))                         return 'MEDIA';
  if (url.includes('/credits'))                        return 'CREDITS';
  return 'API';
}

// ─── Request Log ────────────────────────────────────────────

let requestLog = [];

function addRequestLog(entry) {
  requestLog.unshift(entry);
  if (requestLog.length > 100) requestLog.pop();
  broadcastRequestLog();
}

function updateRequestLog(id, updates) {
  const entry = requestLog.find((e) => e.id === id);
  if (entry) Object.assign(entry, updates);
  broadcastRequestLog();
}

function broadcastRequestLog() {
  chrome.runtime.sendMessage({ type: 'REQUEST_LOG_UPDATE', log: requestLog }).catch(() => {});
}

// ─── Startup ────────────────────────────────────────────────

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'reconnect') connectToAgent();
  if (alarm.name === 'keepAlive') keepAlive();
  if (alarm.name === 'token-refresh') {
    await captureTokenFromFlowTab();
  }
});

async function init() {
  const data = await chrome.storage.local.get(['flowKey', 'metrics', 'callbackSecret']);
  if (data.flowKey) flowKey = data.flowKey;
  if (data.metrics) Object.assign(metrics, data.metrics);
  if (data.callbackSecret) callbackSecret = data.callbackSecret;
  connectToAgent();
  chrome.alarms.create('keepAlive', { periodInMinutes: 0.4 });
}

// Call init at top-level to ensure the extension background worker executes and connects
// immediately every time the short-lived Manifest V3 Service Worker wakes up from sleep.
init();

// ─── Token Capture ──────────────────────────────────────────

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    // PREVENT SELF-CAPTURE ECHO LOOP:
    // If request originates from the extension itself (tabId === -1 or chrome-extension://),
    // ignore it so we never re-capture our own outgoing tokens.
    if (details.tabId === -1 || (details.initiator && details.initiator.startsWith('chrome-extension://'))) {
      return;
    }
    if (!details?.requestHeaders?.length) return;
    const authHeader = details.requestHeaders?.find(
      (h) => h.name?.toLowerCase() === 'authorization',
    );
    const value = authHeader?.value || '';
    
    const match = value.match(/(ya29\.[a-zA-Z0-9_\-]+)/);
    if (!match) return;
    const token = match[1];

    // Always update — even if same token string, refresh the timestamp
    flowKey = token;
    metrics.tokenCapturedAt = Date.now();
    chrome.storage.local.set({ flowKey, metrics, quotaErrorState: false });
    console.log('[FlowAgent] Bearer token captured. Reset quotaErrorState.');

    // Notify agent
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
    }
  },
  // NGHE CẢ `flow.google.com`. Từ bản cập nhật 2026-09, Flow chạy ở đó chứ
  // không ở labs.google — nếu giao diện mới gọi thẳng backend nào khác thì
  // danh sách cũ không thấy header nào và `flowKey` mãi rỗng (NO_FLOW_KEY),
  // dù người dùng đang đăng nhập bình thường.
  {
    urls: [
      'https://*.googleapis.com/*',
      'https://*.google.com/*',
      'https://aisandbox-pa.googleapis.com/*',
      'https://labs.google/*',
      'https://flow.google.com/*',
      'https://*.flow.google.com/*',
    ],
  },
  ['requestHeaders', 'extraHeaders'],
);

// Helper to query all Google Flow tabs, including multi-account paths (e.g. /u/1/fx/...)
async function getFlowTabs() {
  try {
    // HỎI HẾT MỌI TAB rồi tự lọc, không lọc sẵn bằng `url:` trong truy vấn.
    // Truy vấn có `url:` chỉ trả tab mà tiện ích ĐƯỢC CẤP QUYỀN host; địa chỉ
    // mới của Flow chưa nằm trong quyền thì tab biến mất khỏi kết quả và không
    // có lỗi nào để nhìn.
    const tabs = await chrome.tabs.query({});
    const laTrangFlow = (u) => u.startsWith('http') && (u.includes('labs.google') || u.includes('flow.google'));
    const khop = tabs.filter((tab) => {
      const u = tab.url || tab.pendingUrl || '';
      // BỎ tab rỗng/`about:blank`. Tiêu chí cũ còn nhận tab theo TIÊU ĐỀ, nên
      // một tab trắng tên "Google Flow" vẫn lọt vào, bị tiêm script, và đúc
      // token bằng `window.grecaptcha` không tồn tại → gửi đi
      // `recaptcha-token-unknown` → 403 (đo được 24/09).
      return laTrangFlow(u);
    });

    // THỨ TỰ ƯU TIÊN (đo 24/09 bằng bộ dò trong trang):
    //   1. `flow.google.com/u/N/project/<uuid>` — CHỈ trang trong dự án mới nạp
    //      `enterprise.js`; token dài ~2450 ký tự, anchor `co=` là
    //      "https://flow.google.com:443" — đúng nơi backend chờ.
    //   2. tab flow.google.com khác (trang chủ: chưa có grecaptcha nhưng còn
    //      chuyển sang dự án được).
    //   3. labs.google — trang Next.js cũ vẫn sống và VẪN đúc được token,
    //      nhưng token đó gắn hostname labs.google và bị API từ chối thẳng
    //      (403 reCAPTCHA evaluation failed). Chỉ dùng khi không còn gì khác.
    const hang = (tab) => {
      const u = tab.url || tab.pendingUrl || '';
      if (/flow\.google\.com\/.*\/project\//.test(u) || /flow\.google\.com\/project\//.test(u)) return 0;
      if (u.includes('flow.google')) return 1;
      return 2;
    };
    khop.sort((a, b) => {
      const d = hang(a) - hang(b);
      if (d) return d;
      return (b.active ? 1 : 0) - (a.active ? 1 : 0);
    });

    if (!khop.length && tabs.length) {
      console.warn('[FlowAgent] Khong thay tab Flow. Dang mo:',
        tabs.slice(0, 10).map((t) => (t.url || t.pendingUrl || '(rong)') + ' | ' + (t.title || '')));
    }
    return khop;
  } catch (e) {
    console.error('[FlowAgent] Failed to query flow tabs:', e);
    return [];
  }
}

// Helper to detect Google account index from active/existing tabs
async function getGoogleUserIndex() {
  try {
    const tabs = await chrome.tabs.query({
      url: ['https://flow.google.com/*', 'https://labs.google/*', '*://*.google.com/*'],
    });
    // Ưu tiên chỉ số tài khoản ĐỌC TỪ TAB FLOW. Quét chung mọi tab google.com
    // thì một tab Gmail /u/0/ mở sẵn cũng cướp mất, rồi tiện ích mở Flow bằng
    // tài khoản không có dự án.
    const uu = [...tabs].sort((a, b) => {
      const diem = (t) => ((t.url || '').includes('flow.google') ? 0 : (t.url || '').includes('labs.google') ? 1 : 2);
      return diem(a) - diem(b);
    });
    for (const tab of uu) {
      if (!tab.url) continue;
      const match = tab.url.match(/\/u\/(\d+)\//);
      if (match) {
        return match[1];
      }
    }
  } catch (e) {
    console.error('[FlowAgent] Failed to detect user index:', e);
  }
  return null;
}

// Helper to get target URL for opening new Flow tab — mở thẳng trang dự án
async function getFlowCreateUrl(projectId) {
  // `labs.google/fx/tools/flow` chỉ còn là địa chỉ chuyển hướng: nó ném người
  // dùng về TRANG CHỦ flow.google.com, nơi KHÔNG có grecaptcha. Mở thẳng trang
  // dự án thì mới có chỗ đúc token.
  const index = await getGoogleUserIndex();
  const goc = index !== null ? `https://flow.google.com/u/${index}` : 'https://flow.google.com';
  return projectId ? `${goc}/project/${projectId}` : `${goc}/`;
}

// Bóc projectId khỏi chính URL yêu cầu (.../v1/projects/<uuid>/flowMedia:...)
function bocProjectId(url) {
  const m = (url || '').match(/\/projects\/([0-9a-zA-Z_-]+)\//);
  return m ? m[1] : null;
}

let _openingFlowTab = false;

async function captureTokenFromFlowTab() {
  const tabs = await getFlowTabs();
  if (!tabs.length) {
    if (_openingFlowTab) {
      console.log('[FlowAgent] Flow tab already opening, skipping');
      return;
    }
    _openingFlowTab = true;
    try {
      console.log('[FlowAgent] No Flow tab found — opening one in background');
      const createUrl = await getFlowCreateUrl();
      await chrome.tabs.create({ url: createUrl, active: false });
      let retryTabs = [];
      for (let i = 0; i < 8; i++) {
        await sleep(2000);
        retryTabs = await getFlowTabs();
        if (retryTabs.length) break;
      }
    } catch (e) {
      console.error('[FlowAgent] Opening tab failed:', e);
    } finally {
      _openingFlowTab = false;
    }
    return;
  }

  // Lấy accessToken trực tiếp qua NextAuth /api/auth/session trong tab mà KHÔNG cần F5 reload
  for (const tab of tabs) {
    try {
      await baoDamDaTiem(tab.id);
      const sessionResp = await chrome.tabs.sendMessage(tab.id, { type: 'GET_SESSION' });
      if (sessionResp?.token) {
        flowKey = sessionResp.token;
        metrics.tokenCapturedAt = Date.now();
        await chrome.storage.local.set({ flowKey, metrics, quotaErrorState: false });
        console.log('[FlowAgent] Captured fresh token via NextAuth GET_SESSION!');
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
        }
        return;
      }
    } catch (e) {
      // Content script may not be ready or tab navigating
    }
  }

  console.log('[FlowAgent] GET_SESSION not ready, token will be captured on next tab activity.');
}

// ─── WebSocket to Agent ─────────────────────────────────────

function connectToAgent() {
  if (manualDisconnect) return;
  if (ws?.readyState === WebSocket.CONNECTING) return;
  if (ws?.readyState === WebSocket.OPEN) return;

  try {
    ws = new WebSocket(AGENT_WS_URL);
  } catch (e) {
    console.error('[FlowAgent] WS connect error:', e);
    scheduleReconnect();
    return;
  }

  ws.onopen = async () => {
    console.log('[FlowAgent] Connected to agent');
    chrome.alarms.clear('reconnect');
    await chrome.storage.local.set({ quotaErrorState: false });
    setState('idle');

    // Token refresh alarm — 45 min gives buffer before ~60 min expiry
    chrome.alarms.create('token-refresh', { periodInMinutes: 45 });

    let hasDashboard = false;
    try {
      const dbTabs = await chrome.tabs.query({
        url: ['*://localhost:5000/*', '*://127.0.0.1:5000/*']
      });
      hasDashboard = dbTabs.length > 0;
    } catch (e) {
      console.error('[FlowAgent] Failed to query dashboard tabs on open:', e);
    }

    // Send current state + resend token if we have one
    ws.send(JSON.stringify({
      type: 'extension_ready',
      flowKeyPresent: !!flowKey,
      hasDashboard,
      tokenAge: flowKey && metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
    }));
    if (flowKey) {
      ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
    }
  };

  ws.onmessage = async ({ data }) => {
    try {
      const msg = JSON.parse(data);

      if (msg.method === 'api_request') {
        console.log("📥 [Extension] Received api_request:", msg.params?.url);
        await handleApiRequest(msg);
      } else if (msg.method === 'trpc_request') {
        console.log("📥 [Extension] Received trpc_request:", msg.params?.url);
        await handleTrpcRequest(msg);
      } else if (msg.method === 'solve_captcha') {
        await handleSolveCaptcha(msg);
      } else if (msg.method === 'clear_cookies') {
        console.log('[FlowAgent] Received explicit clear_cookies command from Python backend.');
        await clearCookiesAndRequestLogin();
        sendToAgent({
          id: msg.id,
          result: { ok: true }
        });
      } else if (msg.method === 'reset_session') {
        console.log('[FlowAgent] Received reset_session command from Python backend (soft reload).');
        flowKey = null;
        await chrome.storage.local.remove('flowKey');
        await captureTokenFromFlowTab();
        sendToAgent({
          id: msg.id,
          result: { ok: true }
        });
      } else if (msg.method === 'get_status') {
        sendToAgent({
          id: msg.id,
          result: {
            state,
            flowKeyPresent: !!flowKey,
            manualDisconnect,
            tokenAge: metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
            metrics,
          },
        });
      } else if (msg.type === 'callback_secret') {
        callbackSecret = msg.secret;
        chrome.storage.local.set({ callbackSecret: msg.secret });
        console.log('[FlowAgent] Received callback secret');
      } else if (msg.type === 'pong') {
        // keepalive response
      }
    } catch (e) {
      console.error('[FlowAgent] Message error:', e);
    }
  };

  ws.onclose = () => {
    setState('off');
    chrome.alarms.clear('token-refresh');
    if (!manualDisconnect) {
      console.log('[FlowAgent] WebSocket closed. Reconnecting in 2s...');
      setTimeout(connectToAgent, 2000);
      scheduleReconnect(); // Fallback alarm
    }
  };

  ws.onerror = (e) => {
    console.error('[FlowAgent] WS error:', e);
    metrics.lastError = 'WS_ERROR';
    chrome.storage.local.set({ metrics });
    try {
      ws.close();
    } catch (err) {
      console.error('[FlowAgent] Error closing socket on error:', err);
    }
  };
}

function scheduleReconnect() {
  chrome.alarms.create('reconnect', { delayInMinutes: 0.083 }); // ~5s
}

function keepAlive() {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'ping' }));
  } else {
    connectToAgent();
  }
}

function sendToAgent(msg) {
  console.log("📤 [Extension] sendToAgent called with ID:", msg.id, "status:", msg.status, "hasError:", !!msg.error);
  // API responses (with msg.id) go via HTTP — immune to WS disconnect
  if (msg.id) {
    fetch('http://127.0.0.1:5000/api/ext/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg),
    }).then(r => {
      console.log("📤 [Extension] HTTP callback success response status:", r.status);
    }).catch((err) => {
      console.warn("📤 [Extension] HTTP callback failed, falling back to WS:", err);
      // HTTP failed — fallback to WS
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
        console.log("📤 [Extension] WS callback fallback sent success!");
      } else {
        console.error("📤 [Extension] WS fallback failed because WS is closed!");
      }
    });
    return;
  }
  // Non-response messages (ping, status) or no secret yet — use WS
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

// ─── reCAPTCHA Solving ──────────────────────────────────────

async function baoDamDaTiem(tabId) {
  // Xem chú thích ở `requestCaptchaFromTab`. Hai lượt tiêm, hai thế giới:
  // content.js ở thế giới cách ly (nói chuyện được với background), injected.js
  // ở MAIN world (chạm được `window.grecaptcha` của trang).
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true }, files: ['content.js'],
    });
  } catch (e) {
    console.warn('[FlowAgent] tiem content.js hong:', e?.message || e);
  }
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true }, world: 'MAIN', files: ['injected.js'],
    });
  } catch (e) {
    console.warn('[FlowAgent] tiem injected.js vao MAIN world hong:', e?.message || e);
  }
}

async function requestCaptchaFromTab(tabId, requestId, pageAction) {
  // TIÊM TRƯỚC KHI HỎI. `content.js` tự chèn `<script src>` vào trang, mà cách
  // đó chịu CSP CỦA TRANG — Flow siết script-src là thẻ bị chặn, injected.js
  // không chạy, không ai phát CAPTCHA_RESULT, content.js hết 25 giây trả
  // CONTENT_TIMEOUT. Không một dòng lỗi nào.
  await baoDamDaTiem(tabId);
  await sleep(300);
  try {
    return await chrome.tabs.sendMessage(tabId, {
      type: 'GET_CAPTCHA',
      requestId,
      pageAction,
    });
  } catch (error) {
    const msg = error?.message || '';
    const shouldInject =
      msg.includes('Receiving end does not exist') ||
      msg.includes('Could not establish connection');
    if (!shouldInject) throw error;

    // Inject content script and retry
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js'],
    });
    await sleep(200);
    return await chrome.tabs.sendMessage(tabId, {
      type: 'GET_CAPTCHA',
      requestId,
      pageAction,
    });
  }
}

async function reloadFlowTab() {
  try {
    const tabs = await getFlowTabs();
    if (tabs.length) {
      console.log('[FlowAgent] Captcha error/timeout detected. Reloading Flow tab (F5)...');
      chrome.tabs.reload(tabs[0].id);
    }
  } catch (e) {
    console.error('[FlowAgent] Failed to reload Flow tab:', e);
  }
}

async function clearCookiesAndRequestLogin() {
  console.log('[FlowAgent] clearCookiesAndRequestLogin disabled to protect user account.');
  await chrome.storage.local.set({ quotaErrorState: false });
}

async function solveCaptcha(requestId, captchaAction) {
  const tabs = await getFlowTabs();

  if (!tabs.length) {
    // Auto-open Flow tab and wait briefly before returning error
    try {
      const createUrl = await getFlowCreateUrl();
      await chrome.tabs.create({ url: createUrl, active: false });
      // HỎI LẠI NHIỀU LẦN, không phải chờ 3 giây rồi hỏi một phát. Tab vừa tạo
      // còn đang tải và có thể qua bước chọn tài khoản; ba giây không đủ, nên
      // tiện ích mở tab ra rồi báo NO_FLOW_TAB ngay trước mắt người dùng.
      let retryTabs = [];
      for (let i = 0; i < 12; i++) {
        await sleep(2000);
        retryTabs = await getFlowTabs();
        if (retryTabs.length) break;
      }
      if (!retryTabs.length) return { error: 'NO_FLOW_TAB' };
      const resp = await Promise.race([
        requestCaptchaFromTab(retryTabs[0].id, requestId, captchaAction),
        new Promise((_, rej) => setTimeout(() => rej(new Error('CAPTCHA_TIMEOUT')), 30000)),
      ]);
      if (resp && resp.error) {
        console.error('[FlowAgent] Captcha error from newly opened tab:', resp.error);
      }
      return resp;
    } catch (e) {
      console.error('[FlowAgent] Captcha exception from newly opened tab:', e);
      return { error: e.message || 'NO_FLOW_TAB' };
    }
  }

  try {
    // Ưu tiên tab ĐANG XEM, rồi mới tới các tab khác: tab người dùng đang mở
    // gần như luôn là trang sinh ảnh thật.
    const uu = [...tabs].sort((a, b) => (b.active ? 1 : 0) - (a.active ? 1 : 0));
    let resp = null;
    let loiCuoi = null;
    for (const tab of uu.slice(0, 6)) {
      try {
        const r = await Promise.race([
          requestCaptchaFromTab(tab.id, requestId, captchaAction),
          new Promise((_, rej) => setTimeout(() => rej(new Error('CAPTCHA_TIMEOUT')), 15000)),
        ]);
        if (r && r.token) { resp = r; break; }
        loiCuoi = (r && r.error) || 'khong co token';
        console.warn('[FlowAgent] tab', tab.id, tab.url || tab.pendingUrl, '->', loiCuoi);
      } catch (e) {
        loiCuoi = e?.message || String(e);
        console.warn('[FlowAgent] tab', tab.id, 'nem loi:', loiCuoi);
      }
    }
    if (!resp || !resp.token) {
      console.warn('[FlowAgent] Captcha token not obtained, using fallback token');
      resp = { token: 'recaptcha-token-unknown' };
    }
    return resp;
  } catch (e) {
    console.error('[FlowAgent] Captcha exception from existing tab:', e);
    return { error: e.message };
  }
}

async function handleSolveCaptcha(msg) {
  const { id, params } = msg;
  const result = await solveCaptcha(id, params?.captchaAction || 'VIDEO_GENERATION');

  // Standalone captcha solve counts as captcha-consuming
  metrics.requestCount++;
  if (result?.token) {
    metrics.successCount++;
  } else {
    metrics.failedCount++;
    metrics.lastError = result?.error || 'NO_TOKEN';
  }
  chrome.storage.local.set({ metrics });

  sendToAgent({ id, result });
}

// ─── API Request Proxy ──────────────────────────────────────

async function handleTrpcRequest(msg) {
  const { id, params } = msg;
  const { url, method = 'POST', headers = {}, body } = params;

  if (!url || !url.startsWith('https://labs.google/')) {
    sendToAgent({ id, error: 'INVALID_TRPC_URL' });
    return;
  }

  setState('running');
  // TRPC calls don't consume captcha — don't count in metrics

  const logId = id;
  const logType = url.includes('createProject') ? 'CREATE_PROJECT' : 'TRPC';
  // TRPC calls are silent — don't show in request log

  const fetchHeaders = { 'Content-Type': 'application/json', ...headers };
  if (flowKey) {
    fetchHeaders['authorization'] = `Bearer ${flowKey}`;
  }

  try {
    const resp = await fetch(url, {
      method,
      headers: fetchHeaders,
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
    const data = await resp.json();
    chrome.storage.local.set({ metrics });
    updateRequestLog(logId, { status: 'success' });
    sendToAgent({ id, status: resp.status, data });
  } catch (e) {
    console.error('[FlowAgent] tRPC request failed:', e);
    chrome.storage.local.set({ metrics });
    updateRequestLog(logId, { status: 'failed', error: e.message || 'TRPC_FETCH_FAILED' });
    sendToAgent({ id, error: e.message || 'TRPC_FETCH_FAILED' });
  } finally {
    setState('idle');
  }
}

async function handleApiRequest(msg) {
  const { id, params } = msg;
  const { url, method, headers, body, captchaAction } = params;

  if (!url) {
    sendToAgent({ id, error: 'MISSING_URL' });
    return;
  }

  if (!url.startsWith('https://aisandbox-pa.googleapis.com/')) {
    sendToAgent({ id, error: 'INVALID_URL' });
    return;
  }

  setState('running');
  const hasCaptcha = !!captchaAction;
  if (hasCaptcha) metrics.requestCount++;

  const logId = id;
  const logType = _classifyApiUrl(url);
  if (_VISIBLE_TYPES.has(logType)) {
    const payloadSummary = body ? JSON.stringify(body).slice(0, 200) : null;
    addRequestLog({ id: logId, type: logType, time: new Date().toISOString(), status: 'processing', error: null, outputUrl: null, url, payloadSummary });
  }

  try {
    // Ưu tiên 1: Thực thi trực tiếp từ ngữ cảnh của Tab Google Labs (MAIN world qua injected.js).
    // Cách này đảm bảo Origin, Referer, TLS fingerprint, IP, và cookies của Tab hoàn toàn
    // đồng nhất với reCAPTCHA Enterprise token, triệt tiêu lỗi PUBLIC_ERROR_UNUSUAL_ACTIVITY.
    let tabs = await getFlowTabs();
    // Không có tab nào đúc được token thì mở thẳng trang DỰ ÁN của chính yêu
    // cầu này rồi chờ, thay vì rơi xuống đường fetch nền (đường đó gửi
    // `recaptcha-token-unknown` và chắc chắn ăn 403).
    // CHỈ mở tab cho yêu cầu cần captcha (sinh ảnh/video). Mở cho cả lượt hỏi
    // trạng thái thì Chrome đẻ ra hàng loạt tab — đúng cái bệnh cũ.
    const coTabDuAn = () => tabs.some((t) => /flow\.google\.com\/.*project\//.test(t.url || t.pendingUrl || ''));
    if (captchaAction && !coTabDuAn() && !_openingFlowTab) {
      _openingFlowTab = true;
      try {
        const createUrl = await getFlowCreateUrl(bocProjectId(url));
        console.log('[FlowAgent] Chua co tab du an Flow — mo', createUrl);
        await chrome.tabs.create({ url: createUrl, active: false });
        for (let i = 0; i < 10; i++) {
          await sleep(2000);
          const lai = await getFlowTabs();
          if (lai.some((t) => /flow\.google\.com\/.*project\//.test(t.url || t.pendingUrl || ''))) { tabs = lai; break; }
          tabs = lai;
        }
      } catch (e) {
        console.warn('[FlowAgent] Mo tab du an that bai:', e?.message || e);
      } finally {
        _openingFlowTab = false;
      }
    }
    if (tabs.length) {
      const targetTab = tabs[0];
      try {
        await baoDamDaTiem(targetTab.id);
        let activeFlowKey = flowKey;
        if (!activeFlowKey && headers && headers['authorization']) {
          const match = headers['authorization'].match(/^Bearer\s+(.+)$/i);
          if (match && match[1]) activeFlowKey = match[1];
        }
        const tabHeaders = { ...(headers || {}) };
        if (activeFlowKey) {
          tabHeaders['authorization'] = `Bearer ${activeFlowKey}`;
        }

        console.log(`[FlowAgent] Delegating API request to tab ${targetTab.id} (${targetTab.url || targetTab.pendingUrl})...`);
        const tabResult = await chrome.tabs.sendMessage(targetTab.id, {
          type: 'TAB_API_REQUEST',
          requestId: id,
          url,
          method: method || 'POST',
          headers: tabHeaders,
          body,
          captchaAction,
        });

        if (tabResult && !tabResult.error && tabResult.status !== undefined) {
          console.log(`[FlowAgent] Tab ${targetTab.id} executed request successfully, status: ${tabResult.status}`);
          sendToAgent({
            id,
            status: tabResult.status,
            data: tabResult.data,
          });
          if (tabResult.status >= 200 && tabResult.status < 300) {
            if (hasCaptcha) { metrics.successCount++; metrics.lastError = null; }
            updateRequestLog(logId, { status: 'success', httpStatus: tabResult.status });
          } else {
            if (hasCaptcha) { metrics.failedCount++; metrics.lastError = `API_${tabResult.status}`; }
            updateRequestLog(logId, { status: 'failed', error: `API_${tabResult.status}`, httpStatus: tabResult.status });
          }
          chrome.storage.local.set({ metrics });
          setState('idle');
          return;
        } else {
          console.warn('[FlowAgent] Tab execution returned error or no status:', tabResult?.error, '— falling back to background fetch');
        }
      } catch (tabErr) {
        console.warn('[FlowAgent] Failed to delegate to tab:', tabErr?.message, '— falling back to background fetch');
      }
    }

    // Step 1: Solve captcha if needed (Fallback background path)
    let captchaToken = null;
    if (captchaAction) {
      const captchaResult = await solveCaptcha(id, captchaAction);
      captchaToken = captchaResult?.token || null;
      if (!captchaToken) {
        console.warn(`[FlowAgent] Khong lay duoc captcha, using fallback token`);
        captchaToken = 'recaptcha-token-unknown';
      }
    }

    // Step 2: Inject captcha token into body
    let finalBody = body;
    if (captchaToken && finalBody) {
      finalBody = JSON.parse(JSON.stringify(finalBody)); // deep clone
      if (finalBody.clientContext?.recaptchaContext) {
        finalBody.clientContext.recaptchaContext.token = captchaToken;
      }
      if (finalBody.requests && Array.isArray(finalBody.requests)) {
        for (const req of finalBody.requests) {
          if (req.clientContext?.recaptchaContext) {
            req.clientContext.recaptchaContext.token = captchaToken;
          }
        }
      }
    }

    // Step 3: Use flowKey for auth
    let activeFlowKey = flowKey;
    if (!activeFlowKey && headers && headers['authorization']) {
      const match = headers['authorization'].match(/^Bearer\s+(.+)$/i);
      if (match && match[1]) {
        activeFlowKey = match[1];
        flowKey = activeFlowKey;
        console.log('[FlowAgent] Recovered flowKey from request headers authorization');
      }
    }
    if (!activeFlowKey) {
      sendToAgent({ id, status: 503, error: 'NO_FLOW_KEY' });
      if (hasCaptcha) { metrics.failedCount++; metrics.lastError = 'NO_FLOW_KEY'; }
      chrome.storage.local.set({ metrics });
      updateRequestLog(logId, { status: 'failed', error: 'NO_FLOW_KEY' });
      setState('idle');
      return;
    }

    const fetchHeaders = { ...(headers || {}) };
    fetchHeaders['authorization'] = `Bearer ${activeFlowKey}`;

    // Step 4: Make the API call from browser context
    const response = await fetch(url, {
      method: method || 'POST',
      headers: fetchHeaders,
      credentials: 'include',
      body: method === 'GET' ? undefined : JSON.stringify(finalBody),
    });

    let responseData;
    const responseText = await response.text();
    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = responseText;
    }

    sendToAgent({
      id,
      status: response.status,
      data: responseData,
    });

    const responseSummary = responseText ? responseText.slice(0, 300) : null;
    if (response.ok) {
      if (hasCaptcha) { metrics.successCount++; metrics.lastError = null; }
      updateRequestLog(logId, { status: 'success', httpStatus: response.status, responseSummary });
    } else {
      if (hasCaptcha) { metrics.failedCount++; metrics.lastError = `API_${response.status}`; }
      updateRequestLog(logId, { status: 'failed', error: `API_${response.status}`, httpStatus: response.status, responseSummary });

      // TUYỆT ĐỐI KHÔNG tự ý xóa cookie hoặc đăng xuất người dùng khi gặp lỗi 403 / captcha / rate limit.
      // Việc xóa cookie làm người dùng bị văng khỏi Google Flow liên tục.
      const lowerText = responseText ? responseText.toLowerCase() : '';
      if (response.status === 429 && (lowerText.includes('quota_exceeded') || lowerText.includes('resource_exhausted'))) {
        console.warn('[FlowAgent] Quota 429 limit reached.');
      }
    }
  } catch (e) {
    sendToAgent({
      id,
      status: 500,
      error: e.message || 'API_REQUEST_FAILED',
    });
    if (hasCaptcha) { metrics.failedCount++; metrics.lastError = e.message; }
    updateRequestLog(logId, { status: 'failed', error: e.message || 'API_REQUEST_FAILED' });
  }

  chrome.storage.local.set({ metrics });
  setState('idle');
}

// ─── State & Popup ──────────────────────────────────────────

function setState(newState) {
  state = newState;
  const badges = { idle: '●', running: '▶', off: '○' };
  const colors = { idle: '#22c55e', running: '#f59e0b', off: '#6b7280' };
  chrome.action.setBadgeText({ text: badges[state] || '' });
  chrome.action.setBadgeBackgroundColor({ color: colors[state] || '#000' });
  broadcastStatus();
}

// Track keep-alive ports
let keepAlivePorts = new Set();
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'flowkit-keepalive') {
    keepAlivePorts.add(port);
    console.log('[FlowAgent] Keep-alive port connected. Total ports:', keepAlivePorts.size);
    port.onDisconnect.addListener(() => {
      keepAlivePorts.delete(port);
      console.log('[FlowAgent] Keep-alive port disconnected. Total ports:', keepAlivePorts.size);
    });
  }
});

function broadcastStatus() {
  chrome.runtime.sendMessage({ type: 'STATUS_PUSH' }).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, _, reply) => {
  if (msg.type === 'KEEPALIVE_PING') {
    reply({ status: 'alive' });
    return true;
  }

  if (msg.type === 'STATUS') {
    reply({
      connected: ws?.readyState === WebSocket.OPEN,
      agentConnected: ws?.readyState === WebSocket.OPEN,
      flowKeyPresent: !!flowKey,
      manualDisconnect,
      tokenAge: metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
      metrics: {
        requestCount: metrics.requestCount,
        successCount: metrics.successCount,
        failedCount: metrics.failedCount,
        lastError: metrics.lastError,
      },
      state,
    });
  }

  if (msg.type === 'DISCONNECT') {
    manualDisconnect = true;
    if (ws) ws.close();
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'RECONNECT') {
    manualDisconnect = false;
    connectToAgent();
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'REQUEST_LOG') {
    reply({ log: requestLog });
    return true;
  }

  if (msg.type === 'OPEN_FLOW_TAB') {
    getFlowTabs().then(async (tabs) => {
      if (tabs.length) {
        chrome.tabs.update(tabs[0].id, { active: true });
        reply({ ok: true, tabId: tabs[0].id });
      } else {
        const createUrl = await getFlowCreateUrl();
        chrome.tabs.create({ url: createUrl })
          .then((tab) => reply({ ok: true, tabId: tab.id }))
          .catch((e) => reply({ error: e.message }));
      }
    }).catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'REFRESH_TOKEN') {
    captureTokenFromFlowTab()
      .then(() => reply({ ok: true }))
      .catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'CLEAR_COOKIES') {
    clearCookiesAndRequestLogin()
      .then(() => reply({ ok: true }))
      .catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'TEST_CAPTCHA') {
    solveCaptcha(`test-${Date.now()}`, msg.pageAction || 'IMAGE_GENERATION')
      .then((r) => reply(r))
      .catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'TRPC_MEDIA_URLS') {
    handleTrpcMediaUrls(msg.trpcUrl, msg.body);
    reply({ ok: true });
    return true;
  }

  return true;
});

// ─── TRPC Media URL Extractor ──────────────────────────────

function handleTrpcMediaUrls(trpcUrl, bodyText) {
  try {
    // Extract all fresh GCS signed URLs
    const urlRegex = /https:\/\/storage\.googleapis\.com\/ai-sandbox-videofx\/(?:image|video)\/[0-9a-f-]{36}\?[^"'\s]+/g;
    const matches = bodyText.match(urlRegex) || [];
    if (!matches.length) return;

    // Deduplicate and parse
    const urlMap = {};
    for (const rawUrl of matches) {
      // Unescape JSON-escaped URLs
      const url = rawUrl.replace(/\\u0026/g, '&').replace(/\\/g, '');
      const mediaMatch = url.match(/\/(image|video)\/([0-9a-f-]{36})\?/);
      if (mediaMatch) {
        const [, mediaType, mediaId] = mediaMatch;
        // Keep last occurrence (freshest)
        urlMap[mediaId] = { mediaType, url, mediaId };
      }
    }

    const entries = Object.values(urlMap);
    if (!entries.length) return;

    console.log(`[FlowAgent] Captured ${entries.length} fresh media URLs from TRPC`);
    // URL refresh is silent — don't show in request log

    // Forward to agent for DB update
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'media_urls_refresh',
        urls: entries,
      }));
    }
  } catch (e) {
    console.error('[FlowAgent] Failed to extract TRPC media URLs:', e);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Human-like Telemetry ──────────────────────────────────
// Periodically send tracking events to Google's analytics endpoints
// to mimic normal browser behavior.

const _UA = navigator.userAgent;
let _telemetrySessionId = `;${Date.now()}`;

function _rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function _buildBatchLogPayload() {
  const events = [];
  const types = ['FLOW_IMAGE_LATENCY', 'FLOW_VIDEO_LATENCY'];
  const count = _rand(1, 3);
  for (let i = 0; i < count; i++) {
    events.push({
      event: types[_rand(0, types.length - 1)],
      eventProperties: [
        { key: 'CURRENT_TIME_MS', doubleValue: Date.now() },
        { key: 'DURATION_MS', doubleValue: _rand(150, 800) },
        { key: 'USER_AGENT', stringValue: _UA },
        { key: 'IS_DESKTOP', booleanValue: true },
      ],
      eventMetadata: { sessionId: _telemetrySessionId },
      eventTime: new Date().toISOString(),
    });
  }
  return { appEvents: events };
}

function _buildFrontendEventsPayload() {
  const eventTypes = [
    'FLOW_IMAGE_LATENCY', 'FLOW_VIDEO_LATENCY', 'GRID_SCROLL_DEPTH',
    'FLOW_PROJECT_OPEN', 'FLOW_SCENE_VIEW',
  ];
  const count = _rand(1, 4);
  const events = [];
  for (let i = 0; i < count; i++) {
    const et = eventTypes[_rand(0, eventTypes.length - 1)];
    const params = {
      USER_AGENT: { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: _UA },
      IS_DESKTOP: { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: 'true' },
    };
    if (et.includes('LATENCY')) {
      params.CURRENT_TIME_MS = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: String(Date.now()) };
      params.DURATION_MS = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: String(_rand(100, 600)) };
    }
    if (et === 'GRID_SCROLL_DEPTH') {
      params.MEDIA_GENERATION_PAYGATE_TIER = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: 'PAYGATE_TIER_TWO' };
    }
    events.push({
      eventType: et,
      metadata: {
        sessionId: _telemetrySessionId,
        createTime: new Date().toISOString(),
        additionalParams: params,
      },
    });
  }
  return { events };
}

async function sendTelemetry() {
  if (!flowKey || state === 'off') return;

  const headers = {
    'Content-Type': 'text/plain;charset=UTF-8',
    'authorization': `Bearer ${flowKey}`,
  };

  // Telemetry is silent — don't show in request log
  try {
    if (Math.random() < 0.5) {
      await fetch(`https://aisandbox-pa.googleapis.com/v1:batchLog`, {
        method: 'POST', headers, credentials: 'include',
        body: JSON.stringify(_buildBatchLogPayload()),
      });
    } else {
      await fetch(`https://aisandbox-pa.googleapis.com/v1/flow:batchLogFrontendEvents`, {
        method: 'POST', headers, credentials: 'include',
        body: JSON.stringify(_buildFrontendEventsPayload()),
      });
    }
  } catch {}
}

// Send telemetry at random intervals (45-120s) to look organic
function scheduleTelemetry() {
  const delay = _rand(45, 120) * 1000;
  setTimeout(async () => {
    await sendTelemetry();
    scheduleTelemetry(); // reschedule with new random interval
  }, delay);
}

// Refresh session ID every ~30min like a real user
setInterval(() => { _telemetrySessionId = `;${Date.now()}`; }, _rand(25, 35) * 60 * 1000);

scheduleTelemetry();

console.log('[FlowAgent] Extension loaded');

// ─── Dashboard Presence Notification ──────────────────────────

async function checkAndNotifyDashboardPresence() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  try {
    const tabs = await chrome.tabs.query({
      url: ['*://localhost:5000/*', '*://127.0.0.1:5000/*']
    });
    const hasDashboard = tabs.length > 0;
    ws.send(JSON.stringify({
      type: 'dashboard_presence',
      hasDashboard,
      flowKeyPresent: !!flowKey
    }));
  } catch (e) {
    console.error('[FlowAgent] Failed to notify dashboard presence:', e);
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    checkAndNotifyDashboardPresence();
  }
});
chrome.tabs.onRemoved.addListener(() => {
  checkAndNotifyDashboardPresence();
});
chrome.tabs.onCreated.addListener(() => {
  checkAndNotifyDashboardPresence();
});
