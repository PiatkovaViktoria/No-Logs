/**
 * TrustGuard - Антифишинг PRO
 * Фоновый сервис: проверка URL по локальной базе, Google Safe Browsing, VirusTotal.
 * Редирект на страницу блокировки, счётчик, хранение последних блокировок и проверок писем.
 */

const BLOCK_PAGE = 'block.html';
const STORAGE_KEYS = {
  blockCount: 'trustguard_block_count',
  lastBlocked: 'trustguard_last_blocked',
  lastEmails: 'trustguard_last_emails',
  apiKeys: 'trustguard_api_keys',
  phishingList: 'trustguard_phishing_domains',
};
const LAST_BLOCKED_MAX = 20;
const LAST_EMAILS_MAX = 15;

// URL, которые пользователь разрешил открыть ("Все равно перейти") — только текущая сессия
const allowedOnce = new Set();
// Кэш локальных фишинговых доменов
let localPhishingSet = new Set();

// ——— Нормализация URL ———
function getHostFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

// ——— Загрузка локальной базы ———
async function loadLocalPhishingList() {
  let list;
  try {
    const res = await fetch(chrome.runtime.getURL('phishing-list.json'));
    if (res.ok) {
      const json = await res.json();
      list = Array.isArray(json) ? json : (json.domains || json.urls || []);
    }
  } catch (_) {}
  if (!list || list.length === 0) {
    list = [
      'phishing-bank.ru', 'secure-login.com', 'account-verify.net',
      'paypal-secure-login.com', 'apple-id-verify.com',
    ];
  }
  localPhishingSet = new Set(
    list.map((d) => String(d).toLowerCase().replace(/^www\./, ''))
  );
}

// ——— Проверка по локальной базе ———
function checkLocal(url) {
  const host = getHostFromUrl(url);
  return host ? localPhishingSet.has(host) : false;
}

// ——— Google Safe Browsing API ———
async function checkGoogleSafeBrowsing(apiKey, url) {
  if (!apiKey || !url) return { safe: true, reason: null };
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'trustguard', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );
    if (!res.ok) return { safe: true, reason: null };
    const data = await res.json();
    const matches = data.matches || [];
    if (matches.length === 0) return { safe: true, reason: null };
    const threatType = matches[0].threatType || 'THREAT';
    return { safe: false, reason: `Google Safe Browsing: ${threatType}` };
  } catch (_) {
    return { safe: true, reason: null };
  }
}

// ——— Проверка API-ключей (для настроек) ———
const TEST_URL = 'https://www.google.com/';

async function validateGoogleKey(apiKey) {
  if (!apiKey || !apiKey.trim()) return { valid: 'empty' };
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey.trim())}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'trustguard', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: TEST_URL }],
          },
        }),
      }
    );
    if (res.ok) return { valid: 'ok' };
    const err = await res.json().catch(() => ({}));
    const msg = err.error?.message || `Ошибка ${res.status}`;
    return { valid: 'invalid', error: msg };
  } catch (e) {
    return { valid: 'invalid', error: e.message || 'Нет сети или ошибка запроса' };
  }
}

async function validateVirusTotalKey(apiKey) {
  if (!apiKey || !apiKey.trim()) return { valid: 'empty' };
  try {
    const id = base64UrlEncode(TEST_URL);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': apiKey.trim() },
    });
    if (res.status === 401) return { valid: 'invalid', error: 'Неверный ключ (401)' };
    if (res.ok || res.status === 404) return { valid: 'ok' };
    const err = await res.json().catch(() => ({}));
    const msg = err.error?.message || `Ошибка ${res.status}`;
    return { valid: 'invalid', error: msg };
  } catch (e) {
    return { valid: 'invalid', error: e.message || 'Нет сети или ошибка запроса' };
  }
}

// ——— VirusTotal API v3 (репутация по отчёту) ———
function base64UrlEncode(str) {
  const base64 = btoa(unescape(encodeURIComponent(str)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkVirusTotal(apiKey, url) {
  if (!apiKey || !url) return { safe: true, riskPercent: 0, reason: null };
  try {
    const id = base64UrlEncode(url);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': apiKey },
    });
    if (!res.ok) {
      if (res.status === 404) return { safe: true, riskPercent: 0, reason: null };
      return { safe: true, riskPercent: 0, reason: null };
    }
    const data = await res.json();
    const attr = data.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const total = malicious + suspicious + (Number(stats.harmless) || 0) + (Number(stats.undetected) || 0);
    const riskPercent = total > 0 ? Math.round(((malicious + suspicious * 0.5) / total) * 100) : 0;
    if (riskPercent > 70) {
      return { safe: false, riskPercent, reason: `VirusTotal: риск ${riskPercent}% (вредоносных: ${malicious})` };
    }
    return { safe: true, riskPercent, reason: null };
  } catch (_) {
    return { safe: true, riskPercent: 0, reason: null };
  }
}

// ——— Комплексная проверка URL ———
async function checkUrl(url) {
  if (allowedOnce.has(url)) return { block: false, reason: null };

  // 1) Локальная база
  if (checkLocal(url)) {
    return { block: true, reason: 'Локальная база фишинговых сайтов' };
  }

  const { apiKeys = {} } = await chrome.storage.local.get([STORAGE_KEYS.apiKeys]);
  const googleKey = apiKeys.googleSafeBrowsing || '';
  const vtKey = apiKeys.virusTotal || '';

  // 2) Google Safe Browsing
  if (googleKey) {
    const g = await checkGoogleSafeBrowsing(googleKey, url);
    if (!g.safe) return { block: true, reason: g.reason };
  }

  // 3) VirusTotal (риск > 70%)
  if (vtKey) {
    const vt = await checkVirusTotal(vtKey, url);
    if (!vt.safe) return { block: true, reason: vt.reason };
  }

  return { block: false, reason: null };
}

// ——— Счётчик и список последних блокировок ———
async function addBlockedAndRedirect(url, reason) {
  const data = await chrome.storage.local.get([STORAGE_KEYS.blockCount, STORAGE_KEYS.lastBlocked]);
  const count = (Number(data[STORAGE_KEYS.blockCount]) || 0) + 1;
  const last = Array.isArray(data[STORAGE_KEYS.lastBlocked]) ? data[STORAGE_KEYS.lastBlocked] : [];
  const entry = { url, reason, time: Date.now() };
  const newLast = [entry, ...last].slice(0, LAST_BLOCKED_MAX);
  await chrome.storage.local.set({
    [STORAGE_KEYS.blockCount]: count,
    [STORAGE_KEYS.lastBlocked]: newLast,
  });
  const blockPageUrl = chrome.runtime.getURL(BLOCK_PAGE) +
    '?blocked=' + encodeURIComponent(url) +
    '&reason=' + encodeURIComponent(reason || 'Опасный сайт');
  return blockPageUrl;
}

// ——— Разрешить один раз ("Все равно перейти") ———
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'TRUSTGUARD_ALLOW_ONCE' && msg.url) {
    allowedOnce.add(msg.url);
    sendResponse({ ok: true });
  } else if (msg.type === 'TRUSTGUARD_VALIDATE_KEYS') {
    (async () => {
      const google = await validateGoogleKey(msg.googleKey || '');
      const vt = await validateVirusTotalKey(msg.vtKey || '');
      return { google, vt };
    })().then(sendResponse);
    return true;
  } else if (msg.type === 'TRUSTGUARD_CHECK_URL') {
    checkUrl(msg.url).then(sendResponse);
    return true;
  } else if (msg.type === 'TRUSTGUARD_CHECK_EMAIL') {
    // Проверка письма: отправитель, тема, текст, ссылки — считаем риск по ссылкам
    (async () => {
      const links = msg.links || [];
      let maxRisk = 0;
      let worstReason = null;
      for (const link of links.slice(0, 10)) {
        const r = await checkUrl(link);
        if (r.block && !worstReason) worstReason = r.reason;
        if (r.block) maxRisk = Math.max(maxRisk, 100);
      }
      const risk = links.length === 0 ? 0 : maxRisk;
      const level = risk >= 70 ? 'danger' : risk >= 30 ? 'warning' : 'safe';
      const emailEntry = {
        from: msg.from || '',
        subject: msg.subject || '',
        risk: level,
        reason: worstReason,
        time: Date.now(),
      };
      const data = await chrome.storage.local.get([STORAGE_KEYS.lastEmails]);
      const last = Array.isArray(data[STORAGE_KEYS.lastEmails]) ? data[STORAGE_KEYS.lastEmails] : [];
      const newLast = [emailEntry, ...last].slice(0, LAST_EMAILS_MAX);
      await chrome.storage.local.set({ [STORAGE_KEYS.lastEmails]: newLast });
      return { level, reason: worstReason };
    })().then(sendResponse);
    return true;
  }
  return false;
});

// ——— Перехват навигации (без blocking: в MV3 он только для корпоративной установки) ———
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.type !== 'main_frame' || details.tabId < 0) return;
    const url = details.url;
    const result = await checkUrl(url);
    if (!result.block) return;
    const redirectUrl = await addBlockedAndRedirect(url, result.reason);
    try {
      await chrome.tabs.update(details.tabId, { url: redirectUrl });
    } catch (_) {}
  },
  { urls: ['<all_urls>'] }
);

chrome.runtime.onStartup.addListener(loadLocalPhishingList);
chrome.runtime.onInstalled.addListener(loadLocalPhishingList);
loadLocalPhishingList();
