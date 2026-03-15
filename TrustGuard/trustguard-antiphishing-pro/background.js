/**
 * TrustGuard - Антифишинг PRO
 * Фоновый сервис: проверка URL по локальной базе, Google Safe Browsing, VirusTotal.
 * Редирект на страницу блокировки, счётчик, хранение последних блокировок и проверок писем.
 */

const BLOCK_PAGE = 'block.html';
const STORAGE_KEYS = {
  blockCount: 'trustguard_block_count',
  lastBlocked: 'trustguard_last_blocked',
  blockCountMonth: 'trustguard_block_count_month',
  monthKey: 'trustguard_month_key',
  lastEmails: 'trustguard_last_emails',
  apiKeys: 'trustguard_api_keys',
  phishingList: 'trustguard_phishing_domains',
  phishingEmailsCount: 'trustguard_phishing_emails_count',
  emailsScannedTotal: 'trustguard_emails_scanned_total',
  exceptions: 'trustguard_exceptions',
};

/** Рейтинг по числу переходов на фишинг за месяц: при >20 снижается. 0–20→5, 21–50→4, 51–80→3, 81–150→2, 151+→1. */
function getRatingByMonthCount(monthCount) {
  if (monthCount <= 20) return 5;
  if (monthCount <= 50) return 4;
  if (monthCount <= 80) return 3;
  if (monthCount <= 150) return 2;
  return 1;
}
const LAST_BLOCKED_MAX = 20;
const LAST_EMAILS_MAX = 15;
const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta';
const GEMINI_MODEL = 'gemini-2.0-flash';

// Фразы-маркеры фишинга в тексте письма
const PHISHING_PHRASES = [
  'срочно', 'пароль', 'заблокирован', 'подтвердите', 'аккаунт', 'войдите', 'банк', 'карта', 'перевод',
  'подтверждение', 'проверка', 'безопасность', 'заблокируем', 'подозрительн', 'вход в аккаунт',
  'восстановите', 'измените пароль', 'подтвердите личность', 'оплатите', 'счёт', 'платёж'
];
// Домены известных сервисов (отправитель не должен их имитировать с другого домена)
const KNOWN_SENDER_DOMAINS = [
  'gmail.com', 'google.com', 'mail.ru', 'bk.ru', 'inbox.ru', 'list.ru', 'yandex.ru', 'ya.ru',
  'sberbank.ru', 'vtb.ru', 'tinkoff.ru', 'alfabank.ru', 'raiffeisen.ru', 'mail.google.com'
];

// URL, которые пользователь разрешил открыть ("Все равно перейти") — только текущая сессия
const allowedOnce = new Set();
// Кэш локальных фишинговых доменов
let localPhishingSet = new Set();
// Кэш API-ключей (чтобы не читать storage при каждой навигации)
let cachedApiKeys = null;

// ——— Нормализация URL ———
function getHostFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

const DNR_MAX_RULES = 4500; // лимит Chrome ~5000
const EXTERNAL_FEED_URL = 'https://openphish.com/feed.txt'; // опционально, может быть недоступен

// ——— Загрузка локальной базы + внешний фид (домены для DNR) ———
async function loadLocalPhishingList() {
  let list = [];
  try {
    const res = await fetch(chrome.runtime.getURL('phishing-list.json'));
    if (res.ok) {
      const json = await res.json();
      list = Array.isArray(json) ? json : (json.domains || json.urls || []);
    }
  } catch (_) {}
  const hostSet = new Set(
    list.map((d) => String(d).toLowerCase().replace(/^www\./, '').trim()).filter(Boolean)
  );
  // Подтягиваем домены из открытого фида (без ключа), чтобы блокировать больше
  try {
    const feedRes = await fetch(EXTERNAL_FEED_URL, { cache: 'no-store' });
    if (feedRes.ok) {
      const text = await feedRes.text();
      const lines = text.split(/\s+/).filter(Boolean);
      for (const line of lines) {
        if (hostSet.size >= DNR_MAX_RULES) break;
        try {
          const u = new URL(line.startsWith('http') ? line : 'https://' + line);
          const host = u.hostname.toLowerCase().replace(/^www\./, '');
          if (host && host.length < 200) hostSet.add(host);
        } catch (_) {}
      }
    }
  } catch (_) {}
  if (hostSet.size === 0) {
    ['phishing-bank.ru', 'secure-login.com', 'account-verify.net', 'paypal-secure-login.com', 'apple-id-verify.com'].forEach((h) => hostSet.add(h));
  }
  // Домены из исключений не блокируем через DNR — пользователь внёс их в «исключения»
  const prefs = await chrome.storage.local.get([STORAGE_KEYS.exceptions]);
  const exceptions = Array.isArray(prefs[STORAGE_KEYS.exceptions]) ? prefs[STORAGE_KEYS.exceptions] : [];
  const exceptionSet = new Set(exceptions.map((d) => (d || '').toLowerCase().replace(/^www\./, '').trim()).filter(Boolean));
  const toBlock = [...hostSet].filter((host) => {
    for (const exc of exceptionSet) {
      if (!exc) continue;
      if (host === exc || host.endsWith('.' + exc)) return false;
    }
    return true;
  });
  localPhishingSet = new Set(toBlock);
  await updateDnrRules(toBlock);
}

// ——— Правила DNR: редирект на страницу блокировки до отправки запроса ———
async function updateDnrRules(domains) {
  const rules = domains.slice(0, DNR_MAX_RULES).map((host, i) => ({
    id: i + 1,
    priority: 1,
    action: { type: 'redirect', redirect: { extensionPath: '/' + BLOCK_PAGE } },
    condition: {
      urlFilter: '||' + host + '^',
      resourceTypes: ['main_frame'],
    },
  }));
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (existing.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id) });
  }
  if (rules.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: rules });
  }
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

function isGeminiUrl(url) {
  return (url || '').indexOf('generativelanguage.googleapis.com') !== -1;
}

function isGeminiKey(key) {
  return (key || '').trim().indexOf('AIza') === 0;
}

/** Один тестовый запрос к AI API (OpenAI-формат). */
async function validateAiKeyRequestOpenAI(endpoint, headers, body) {
  return fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
}

/** Один тестовый запрос к Gemini API. */
async function validateAiKeyRequestGemini(apiKey) {
  const url = GEMINI_BASE_URL + '/models/' + GEMINI_MODEL + ':generateContent?key=' + encodeURIComponent(apiKey.trim());
  const body = {
    contents: [{ parts: [{ text: 'Ответь одним словом: ок.' }] }],
    generationConfig: { maxOutputTokens: 50, temperature: 0.2 },
  };
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** Проверка, что ИИ API доступен и готов анализировать письма (тестовый запрос). */
async function validateAiKey(apiKey, baseUrl) {
  const key = (apiKey || '').trim();
  let rawUrl = (baseUrl || '').trim();
  if (!key && !rawUrl) return { valid: 'empty' };
  if (!rawUrl && isGeminiKey(key)) rawUrl = GEMINI_BASE_URL;
  if (!rawUrl) rawUrl = 'https://api.openai.com/v1';
  if (/dashboard\.ngrok\.com|ngrok\.com\/billing/i.test(rawUrl)) {
    return { valid: 'invalid', error: 'Укажите URL туннеля ngrok или для Gemini оставьте пустым.' };
  }
  const url = rawUrl.replace(/\/$/, '');
  const useGemini = isGeminiUrl(url) || isGeminiKey(key);
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  };
  try {
    let res;
    if (useGemini) {
      res = await validateAiKeyRequestGemini(key || '');
    } else {
      const endpoint = url + '/chat/completions';
      const model = 'gpt-4o-mini';
      res = await validateAiKeyRequestOpenAI(endpoint, { ...headers, 'Authorization': 'Bearer ' + key }, { model, max_tokens: 50, messages: [{ role: 'user', content: 'Ответь одним словом: ок.' }] });
    }
    if (res.status === 429) {
      await new Promise((r) => setTimeout(r, 2500));
      res = useGemini ? await validateAiKeyRequestGemini(key || '') : await validateAiKeyRequestOpenAI(url + '/chat/completions', { ...headers, 'Authorization': 'Bearer ' + key }, { model: 'gpt-4o-mini', max_tokens: 50, messages: [{ role: 'user', content: 'Ответь одним словом: ок.' }] });
    }
    if (res.status === 401) return { valid: 'invalid', error: 'Неверный ключ (401).' };
    if (res.status === 403) {
      const err = await res.json().catch(() => ({}));
      const msg = err.error?.message || err.message || err.error?.code;
      return { valid: 'invalid', error: 'Доступ запрещён (403). ' + (msg ? String(msg) : 'Проверьте ключ в Google AI Studio.') };
    }
    if (res.status === 429) {
      return { valid: 'invalid', error: 'Лимит запросов (429). Подождите минуту и нажмите «Сохранить» снова.' };
    }
    if (res.status === 404) return { valid: 'invalid', error: 'Endpoint не найден (404). Для Gemini URL оставьте пустым или укажите ' + GEMINI_BASE_URL };
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = err.error?.message || err.error?.code || 'Ошибка ' + res.status;
      return { valid: 'invalid', error: msg };
    }
    const data = await res.json();
    if (useGemini) {
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text != null) return { valid: 'ok', okMessage: 'ИИ готов к анализу' };
    } else {
      if (data.choices?.[0]?.message != null || data.message != null) return { valid: 'ok', okMessage: 'ИИ готов к анализу' };
    }
    return { valid: 'invalid', error: 'Неожиданный ответ API' };
  } catch (e) {
    const msg = e.message || 'Нет сети или ошибка запроса';
    return { valid: 'invalid', error: msg };
  }
}

// ——— VirusTotal API v3: проверка файла (вложение письма) ———
const VT_FILE_MAX_SIZE = 32 * 1024 * 1024; // 32 MB лимит API

async function scanFileWithVirusTotal(apiKey, arrayBuffer, fileName) {
  if (!apiKey || !arrayBuffer || arrayBuffer.byteLength > VT_FILE_MAX_SIZE) {
    return { safe: true, reason: null };
  }
  try {
    const form = new FormData();
    const blob = new Blob([arrayBuffer], { type: 'application/octet-stream' });
    form.append('file', blob, fileName || 'file');
    const uploadRes = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey.trim() },
      body: form,
    });
    if (!uploadRes.ok) return { safe: true, reason: null };
    const uploadData = await uploadRes.json();
    const fileId = uploadData.data?.id;
    if (!fileId) return { safe: true, reason: null };
    await new Promise((r) => setTimeout(r, 3000));
    const fileRes = await fetch('https://www.virustotal.com/api/v3/files/' + fileId, {
      headers: { 'x-apikey': apiKey.trim() },
    });
    if (!fileRes.ok) return { safe: true, reason: null };
    const fileData = await fileRes.json();
    const attr = fileData.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    if (malicious > 0 || suspicious > 0) {
      return { safe: false, reason: 'VirusTotal: файл «' + (fileName || 'вложение') + '» — вредоносных: ' + malicious + ', подозрительных: ' + suspicious };
    }
    return { safe: true, reason: null };
  } catch (_) {
    return { safe: true, reason: null };
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
    const results = attr.last_analysis_results || {};
    const stats = attr.last_analysis_stats || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const total = malicious + suspicious + (Number(stats.harmless) || 0) + (Number(stats.undetected) || 0);
    const riskPercent = total > 0 ? Math.round(((malicious + suspicious * 0.5) / total) * 100) : 0;
    if (riskPercent > 0) {
      const reasons = [];
      for (const [engine, info] of Object.entries(results)) {
        if (!info || (info.category !== 'malicious' && info.category !== 'suspicious')) continue;
        const verdict = (info.result || info.category || 'Malicious').trim();
        if (verdict) reasons.push(`${engine}: ${verdict}`);
      }
      const reason = reasons.length > 0 ? reasons.join('\n') : `VirusTotal: вредоносных ${malicious}`;
      return { safe: false, riskPercent, reason };
    }
    return { safe: true, riskPercent, reason: null };
  } catch (_) {
    return { safe: true, riskPercent: 0, reason: null };
  }
}

// ——— Комплексная проверка URL ———
async function checkUrl(url) {
  if (allowedOnce.has(url)) return { block: false, reason: null };

  const prefs = await chrome.storage.local.get(['trustguard_enabled', 'trustguard_exceptions']);
  if (prefs.trustguard_enabled === false) return { block: false, reason: null };
  const exceptions = Array.isArray(prefs.trustguard_exceptions) ? prefs.trustguard_exceptions : [];
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch (_) {}
  for (const exc of exceptions) {
    const d = (exc || '').toLowerCase().replace(/^www\./, '');
    if (!d) continue;
    if (host === d || host.endsWith('.' + d)) return { block: false, reason: null };
  }

  // 1) Локальная база (мгновенно)
  if (checkLocal(url)) {
    return { block: true, reason: 'Локальная база фишинговых сайтов' };
  }

  if (!cachedApiKeys) {
    const data = await chrome.storage.local.get([STORAGE_KEYS.apiKeys]);
    cachedApiKeys = data[STORAGE_KEYS.apiKeys] || {};
  }
  const googleKey = cachedApiKeys.googleSafeBrowsing || '';
  const vtKey = cachedApiKeys.virusTotal || '';

  // 2) Каждая ссылка проверяется в VirusTotal и/или Google — запросы параллельно
  const checks = [];
  if (googleKey) checks.push(checkGoogleSafeBrowsing(googleKey, url).then((g) => ({ source: 'google', ...g })));
  if (vtKey) checks.push(checkVirusTotal(vtKey, url).then((vt) => ({ source: 'vt', ...vt })));

  if (checks.length === 0) return { block: false, reason: null };

  const results = await Promise.all(checks);
  const bad = results.find((r) => !r.safe);
  if (bad) return { block: true, reason: bad.reason };

  return { block: false, reason: null };
}

// ——— URL страницы блокировки (rating 1–5, mode: smart/strict для кнопки «Всё равно перейти») ———
function buildBlockPageUrl(url, reason, tabId, rating, mode) {
  let u = chrome.runtime.getURL(BLOCK_PAGE) +
    '?blocked=' + encodeURIComponent(url) +
    '&reason=' + encodeURIComponent(reason || 'Опасный сайт');
  if (tabId >= 0) u += '&tabId=' + tabId;
  if (rating >= 1 && rating <= 5) u += '&rating=' + rating;
  if (mode === 'strict' || mode === 'smart') u += '&mode=' + mode;
  return u;
}

// ——— Разворот редирект-ссылок (Gmail: google.com/url?q=..., Mail.ru и др.) ———
function unwrapRedirectUrl(href) {
  if (!href || typeof href !== 'string') return href;
  try {
    const u = new URL(href);
    // Gmail / Google: ?q= реальный URL
    if (/^(www\.)?google\.(com|ru)$/i.test(u.hostname) && u.pathname === '/url' && u.searchParams.has('q')) {
      const q = u.searchParams.get('q');
      if (q && q.startsWith('http')) return q;
    }
    // Другие типичные обёртки: url=, u=, destination=
    const urlParam = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('destination') || u.searchParams.get('q');
    if (urlParam && urlParam.startsWith('http')) return urlParam;
  } catch (_) {}
  return href;
}

// ——— Эвристика: подозрительный ли URL (без API) ———
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'icu', 'cam', 'rest', 'surf',
  'monster', 'click', 'link', 'fit', 'work', 'fun', 'site', 'online', 'space', 'life',
  'pw', 'cc', 'ws', 'cn', 'su', 'bid', 'trade', 'win', 'download', 'stream', 'racing',
  'review', 'country', 'cricket', 'science', 'party', 'date', 'faith', 'accountant',
]);
const BRAND_KEYWORDS = [
  'sberbank', 'tinkoff', 'vtb', 'alfa-bank', 'alfabank', 'raiffeisen', 'gazprom',
  'paypal', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp',
  'amazon', 'netflix', 'steam', 'telegram', 'yandex', 'gosuslugi', 'nalog',
  'bank', 'login', 'signin', 'secure', 'verify', 'account', 'confirm', 'update',
  'password', 'credential', 'восстановл', 'подтвержд', 'безопасност',
];
const LEGITIMATE_DOMAINS = new Set([
  'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com',
  'apple.com', 'microsoft.com', 'github.com', 'amazon.com', 'netflix.com',
  'sberbank.ru', 'tinkoff.ru', 'vtb.ru', 'alfabank.ru', 'gosuslugi.ru',
  'nalog.ru', 'yandex.ru', 'mail.ru', 'vk.com', 'ok.ru', 'whatsapp.com',
  'telegram.org', 't.me', 'paypal.com', 'steam.com', 'steampowered.com',
  'wikipedia.org', 'twitter.com', 'x.com', 'linkedin.com',
]);

function isUrlSuspicious(urlStr) {
  if (!urlStr) return { suspicious: false, reasons: [] };
  const reasons = [];
  let host, tld, fullUrl;
  try {
    fullUrl = new URL(urlStr);
    host = fullUrl.hostname.toLowerCase().replace(/^www\./, '');
  } catch (_) {
    return { suspicious: true, reasons: ['Некорректный URL'] };
  }

  // 1) Пропускаем заведомо легитимные домены
  const hostParts = host.split('.');
  const baseDomain = hostParts.slice(-2).join('.');
  if (LEGITIMATE_DOMAINS.has(baseDomain) || LEGITIMATE_DOMAINS.has(host)) {
    return { suspicious: false, reasons: [] };
  }

  tld = hostParts[hostParts.length - 1] || '';

  // 2) IP-адрес вместо домена
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || host.startsWith('[')) {
    reasons.push('IP-адрес вместо домена');
  }

  // 3) Подозрительный TLD
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push('Подозрительная доменная зона (.' + tld + ')');
  }

  // 4) Много поддоменов (>3 уровня: sub.sub.domain.com)
  if (hostParts.length > 3) {
    reasons.push('Много поддоменов (' + host + ')');
  }

  // 5) Бренд в домене — но сам домен не легитимный (phishing-sberbank.xyz)
  for (const brand of BRAND_KEYWORDS) {
    if (host.includes(brand) && !LEGITIMATE_DOMAINS.has(baseDomain)) {
      reasons.push('Имитация бренда «' + brand + '» в домене ' + host);
      break;
    }
  }

  // 6) Дефисы в домене (secure-login-bank.com) — более 2
  if ((host.match(/-/g) || []).length >= 2) {
    reasons.push('Множественные дефисы в домене');
  }

  // 7) Нестандартный порт
  if (fullUrl.port && fullUrl.port !== '80' && fullUrl.port !== '443') {
    reasons.push('Нестандартный порт :' + fullUrl.port);
  }

  // 8) HTTP (не HTTPS)
  if (fullUrl.protocol === 'http:') {
    reasons.push('Нет шифрования (HTTP)');
  }

  // 9) Очень длинный URL (>200 символов) — часто используется для маскировки
  if (urlStr.length > 200) {
    reasons.push('Очень длинный URL (маскировка)');
  }

  return { suspicious: reasons.length > 0, reasons };
}

// ——— Анализ письма: ссылки (с разворотом редиректов), локальная база + API, эвристики по тексту, вложения. ———
async function analyzeEmail(emailData) {
  const reasons = [];
  let score = 0;
  const rawLinks = emailData.links || [];
  const text = (emailData.text || '').toLowerCase();
  const mismatchedLinks = Number(emailData.mismatchedLinks) || 0;

  const links = rawLinks.map((href) => unwrapRedirectUrl(href)).filter(Boolean);

  // 1) Ссылки — проверяем по локальной базе и API (Google / VirusTotal)
  let dangerousLinks = 0;
  const linkReasons = [];
  for (const link of links.slice(0, 15)) {
    const r = await checkUrl(link);
    if (r.block) {
      dangerousLinks++;
      if (linkReasons.length < 3) linkReasons.push(r.reason || 'Опасная ссылка');
    }
  }
  if (dangerousLinks > 0) {
    score = 100;
    reasons.push('Опасные ссылки в письме: ' + linkReasons.join('; '));
  }

  // 2) Эвристика URL: даже без API-ключей проверяем подозрительные паттерны
  if (score < 100 && links.length > 0) {
    let suspiciousLinkCount = 0;
    const heuristicReasons = [];
    for (const link of links.slice(0, 15)) {
      const h = isUrlSuspicious(link);
      if (h.suspicious) {
        suspiciousLinkCount++;
        if (heuristicReasons.length < 3) {
          heuristicReasons.push(h.reasons[0] || 'Подозрительный URL');
        }
      }
    }
    if (suspiciousLinkCount > 0) {
      const heuristicScore = suspiciousLinkCount >= 3 ? 100 : suspiciousLinkCount >= 2 ? 85 : 70;
      score = Math.max(score, heuristicScore);
      reasons.push('Подозрительные ссылки (' + suspiciousLinkCount + '): ' + heuristicReasons.join('; '));
    }
  }

  // 3) Подмена текста ссылки (текст = один домен, href = другой) — классический фишинг
  if (mismatchedLinks > 0) {
    score = Math.max(score, 100);
    reasons.push('Подмена ссылок: текст (' + mismatchedLinks + ' шт.) показывает один домен, а ведёт на другой');
  }

  // 4) Фразы фишинга + наличие ссылок → поднимаем риск
  if (links.length > 0 && score < 100) {
    const matchedPhrases = PHISHING_PHRASES.filter((p) => text.includes(p.toLowerCase()));
    if (matchedPhrases.length >= 3) {
      score = Math.max(score, 100);
      reasons.push('Типичные фразы фишинга в тексте: «' + matchedPhrases.slice(0, 3).join('», «') + '»');
    } else if (matchedPhrases.length >= 1) {
      score = Math.max(score, 70);
      if (!reasons.some((r) => r.includes('фраз'))) {
        reasons.push('Подозрительные фразы: «' + matchedPhrases.join('», «') + '»');
      }
    }
  }

  // 5) Комбинация: подозрительная ссылка + фразы фишинга = однозначно опасно
  const hasSuspiciousLinks = reasons.some((r) => r.includes('Подозрительные ссылки'));
  const hasPhishingPhrases = reasons.some((r) => r.includes('фраз'));
  if (hasSuspiciousLinks && hasPhishingPhrases && score < 100) {
    score = 100;
  }

  // 6) Вложения — VirusTotal
  const attachmentResults = emailData.attachmentResults || [];
  const badFile = attachmentResults.find((r) => r && r.safe === false);
  if (badFile) {
    score = 100;
    reasons.push('Опасное вложение (VirusTotal): ' + (badFile.reason || 'вредоносный файл'));
  }

  // 7) ИИ: при наличии ключа — дополнительная проверка по тексту
  if (score < 100) {
    if (!cachedApiKeys) {
      const d = await chrome.storage.local.get([STORAGE_KEYS.apiKeys]);
      cachedApiKeys = d[STORAGE_KEYS.apiKeys] || {};
    }
    const aiKey = cachedApiKeys.aiApiKey || '';
    const aiUrl = (cachedApiKeys.aiApiUrl || '').trim() || (isGeminiKey(aiKey) ? GEMINI_BASE_URL : '');
    if (aiKey || aiUrl) {
      const aiResult = await callAiEmailScan(aiKey, aiUrl, {
        from: emailData.from,
        subject: emailData.subject,
        text: emailData.text,
        linksCount: links.length,
      });
      if (aiResult && (aiResult.verdict === 'phishing' || aiResult.verdict === 'scam')) {
        score = 100;
        reasons.push('ИИ-анализ: ' + (aiResult.reason || aiResult.verdict));
      }
    }
  }

  score = Math.min(100, score);
  const isPhishing = score >= 31;

  return {
    score,
    isPhishing,
    reasons,
    checkedLinks: links.length,
    level: score <= 30 ? 'safe' : score <= 70 ? 'warning' : 'danger',
  };
}

// ——— Вызов ИИ API для классификации письма (Gemini или OpenAI-совместимый) ———
const AI_DEFAULT_URL = 'https://api.openai.com/v1';
const AI_SYSTEM_PROMPT = 'Ты — эксперт по безопасности. Главное правило: письма с ПРОСЬБОЙ ДЕНЕГ помечай как опасные (verdict: scam). К просьбам денег относятся: перевести деньги, займи/одолжи, срочно нужны деньги, отправь средства, закинь на карту/кошелёк, нужна финансовая помощь, пополни (если не счёт от известного магазина), просьбы от "друга/родственника" перевести или одолжить. Исключение: легитимный счёт или оплата за известный заказ — safe. Анализируй ТЕКСТ даже без ссылок. Другие признаки скама: обещания вернуть больше ("закинь 5000 получишь 10000000"), "это не обман", наследство/выигрыш за предоплату. phishing — выманивание паролей, поддельные банки. Отвечай ТОЛЬКО JSON: {"verdict": "safe" | "spam" | "scam" | "phishing", "reason": "одна короткая фраза на русском"}.';

async function callAiEmailScanGemini(apiKey, emailData) {
  const key = (apiKey || '').trim();
  if (!key) return null;
  const url = GEMINI_BASE_URL + '/models/' + GEMINI_MODEL + ':generateContent?key=' + encodeURIComponent(key);
  const userText = 'Письмо (оцени текст даже без ссылок).\nОт: ' + (emailData.from || '') + '\nТема: ' + (emailData.subject || '') + '\nТекст: ' + (emailData.text || '').slice(0, 3000) + '\nСсылок в письме: ' + (emailData.linksCount || 0) + '. Обман или фишинг? Верни только JSON.';
  const body = {
    systemInstruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
    contents: [{ parts: [{ text: userText }] }],
    generationConfig: { maxOutputTokens: 200, temperature: 0.2 },
  };
  try {
    let res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res.status === 429) {
      await new Promise((r) => setTimeout(r, 3000));
      res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    }
    if (!res.ok) return null;
    const data = await res.json();
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!content) return null;
    const jsonStr = content.replace(/^```\w*\n?|\n?```$/g, '').trim();
    return JSON.parse(jsonStr);
  } catch (_) {
    return null;
  }
}

async function callAiEmailScanOpenAI(apiKey, baseUrl, emailData) {
  const base = (baseUrl || AI_DEFAULT_URL).replace(/\/$/, '');
  const url = base + '/chat/completions';
  const body = {
    model: 'gpt-4o-mini',
    max_tokens: 200,
    temperature: 0.2,
    messages: [
      { role: 'system', content: AI_SYSTEM_PROMPT },
      { role: 'user', content: 'Письмо (оцени текст даже без ссылок).\nОт: ' + (emailData.from || '') + '\nТема: ' + (emailData.subject || '') + '\nТекст: ' + (emailData.text || '').slice(0, 3000) + '\nСсылок в письме: ' + (emailData.linksCount || 0) + '. Обман или фишинг? Верни только JSON.' },
    ],
  };
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey && (apiKey = apiKey.trim())) headers['Authorization'] = 'Bearer ' + apiKey;
    let res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    if (res.status === 429) {
      await new Promise((r) => setTimeout(r, 3000));
      res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    }
    if (!res.ok) return null;
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content?.trim();
    if (!content) return null;
    const jsonStr = content.replace(/^```\w*\n?|\n?```$/g, '').trim();
    return JSON.parse(jsonStr);
  } catch (_) {
    return null;
  }
}

async function callAiEmailScan(apiKey, baseUrl, emailData) {
  const key = (apiKey || '').trim();
  const base = (baseUrl || '').replace(/\/$/, '');
  if (isGeminiUrl(base) || isGeminiKey(key)) return callAiEmailScanGemini(key, emailData);
  return callAiEmailScanOpenAI(key, base, emailData);
}

// ——— Обновить счётчик и список блокировок; вернуть Promise с новым числом блокировок за месяц ———
function updateBlockedStorage(url, reason) {
  return new Promise((resolve) => {
    const now = new Date();
    const currentMonthKey = now.toISOString().slice(0, 7);
    chrome.storage.local.get(
      [STORAGE_KEYS.blockCount, STORAGE_KEYS.lastBlocked, STORAGE_KEYS.blockCountMonth, STORAGE_KEYS.monthKey],
      (data) => {
        const count = (Number(data[STORAGE_KEYS.blockCount]) || 0) + 1;
        const last = Array.isArray(data[STORAGE_KEYS.lastBlocked]) ? data[STORAGE_KEYS.lastBlocked] : [];
        const storedMonth = data[STORAGE_KEYS.monthKey] || '';
        const monthCount = storedMonth === currentMonthKey
          ? (Number(data[STORAGE_KEYS.blockCountMonth]) || 0) + 1
          : 1;
        const entry = { url, reason, time: Date.now() };
        const newLast = [entry, ...last].slice(0, LAST_BLOCKED_MAX);
        chrome.storage.local.set(
          {
            [STORAGE_KEYS.blockCount]: count,
            [STORAGE_KEYS.lastBlocked]: newLast,
            [STORAGE_KEYS.blockCountMonth]: monthCount,
            [STORAGE_KEYS.monthKey]: currentMonthKey,
          },
          () => resolve(monthCount)
        );
      }
    );
  });
}

// ——— Разрешить один раз ("Все равно перейти") ———
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'TRUSTGUARD_ALLOW_ONCE' && msg.url) {
    allowedOnce.add(msg.url);
    sendResponse({ ok: true });
  } else if (msg.type === 'TRUSTGUARD_NAVIGATE' && msg.tabId >= 0) {
    if (msg.url) {
      chrome.tabs.update(msg.tabId, { url: msg.url }, () => sendResponse({ ok: true }));
    } else {
      chrome.tabs.update(msg.tabId, { url: 'chrome://newtab/' }, () => sendResponse({ ok: true }));
    }
    return true;
  } else if (msg.type === 'TRUSTGUARD_RECORD_BLOCK' && msg.url) {
    updateBlockedStorage(msg.url, msg.reason || 'Локальная база фишинговых сайтов').then(() => sendResponse({ ok: true }));
    return true;
  } else if (msg.type === 'TRUSTGUARD_REBUILD_DNR') {
    (async () => {
      await loadLocalPhishingList();
      // Удалённые из исключений снова блокируются: убираем их из «разрешённых один раз»
      const data = await chrome.storage.local.get([STORAGE_KEYS.exceptions]);
      const exceptions = Array.isArray(data[STORAGE_KEYS.exceptions]) ? data[STORAGE_KEYS.exceptions] : [];
      const excSet = new Set(exceptions.map((d) => (d || '').toLowerCase().replace(/^www\./, '').trim()).filter(Boolean));
      for (const url of allowedOnce) {
        try {
          const host = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
          const inExc = excSet.has(host) || [...excSet].some((e) => host.endsWith('.' + e));
          if (!inExc) allowedOnce.delete(url);
        } catch (_) {}
      }
    })().then(() => sendResponse({ ok: true }));
    return true;
  } else if (msg.type === 'TRUSTGUARD_VALIDATE_KEYS') {
    (async () => {
      const google = await validateGoogleKey(msg.googleKey || '');
      const vt = await validateVirusTotalKey(msg.vtKey || '');
      const ai = await validateAiKey(msg.aiKey || '', msg.aiUrl || '');
      return { google, vt, ai };
    })().then(sendResponse);
    return true;
  } else if (msg.type === 'TRUSTGUARD_CHECK_URL') {
    checkUrl(msg.url).then(sendResponse);
    return true;
  } else if (msg.action === 'scanFile' && msg.fileData) {
    (async () => {
      if (!cachedApiKeys) {
        const d = await chrome.storage.local.get([STORAGE_KEYS.apiKeys]);
        cachedApiKeys = d[STORAGE_KEYS.apiKeys] || {};
      }
      const vtKey = cachedApiKeys.virusTotal || '';
      const buf = msg.fileData instanceof ArrayBuffer ? msg.fileData : (msg.fileData.buffer || msg.fileData);
      return await scanFileWithVirusTotal(vtKey, buf, msg.fileName || '');
    })().then(sendResponse);
    return true;
  } else if (msg.action === 'analyzeEmail' && msg.email) {
    (async () => {
      let result = { score: 0, isPhishing: false, reasons: [], checkedLinks: 0, level: 'safe' };
      try {
        result = await analyzeEmail(msg.email);
      } catch (e) {
        result = { ...result, reasons: ['Ошибка проверки'] };
      }
      try {
        const emailEntry = {
          from: msg.email.from || '',
          subject: msg.email.subject || '',
          risk: result.level,
          reason: result.reasons[0] || null,
          reasons: result.reasons,
          score: result.score,
          isPhishing: result.isPhishing,
          checkedLinks: result.checkedLinks,
          time: Date.now(),
        };
        const data = await chrome.storage.local.get([STORAGE_KEYS.lastEmails, STORAGE_KEYS.phishingEmailsCount, STORAGE_KEYS.emailsScannedTotal]);
        const last = Array.isArray(data[STORAGE_KEYS.lastEmails]) ? data[STORAGE_KEYS.lastEmails] : [];
        const newLast = [emailEntry, ...last].slice(0, LAST_EMAILS_MAX);
        let phishingCount = Number(data[STORAGE_KEYS.phishingEmailsCount]) || 0;
        let scannedTotal = Number(data[STORAGE_KEYS.emailsScannedTotal]) || 0;
        if (result.isPhishing) phishingCount += 1;
        scannedTotal += 1;
        await chrome.storage.local.set({
          [STORAGE_KEYS.lastEmails]: newLast,
          [STORAGE_KEYS.phishingEmailsCount]: phishingCount,
          [STORAGE_KEYS.emailsScannedTotal]: scannedTotal,
        });
      } catch (_) {}
      return result;
    })().then(sendResponse).catch(() => sendResponse({ level: 'safe', reasons: [] }));
    return true;
  } else if (msg.type === 'TRUSTGUARD_CHECK_EMAIL') {
    // Обратная совместимость: старый формат — прогоняем через analyzeEmail
    (async () => {
      const result = await analyzeEmail({
        from: msg.from,
        subject: msg.subject,
        text: msg.text,
        links: msg.links || [],
      });
      const emailEntry = {
        from: msg.from || '',
        subject: msg.subject || '',
        risk: result.level,
        reason: result.reasons[0] || null,
        reasons: result.reasons,
        score: result.score,
        isPhishing: result.isPhishing,
        checkedLinks: result.checkedLinks,
        time: Date.now(),
      };
      const data = await chrome.storage.local.get([STORAGE_KEYS.lastEmails, STORAGE_KEYS.phishingEmailsCount, STORAGE_KEYS.emailsScannedTotal]);
      const last = Array.isArray(data[STORAGE_KEYS.lastEmails]) ? data[STORAGE_KEYS.lastEmails] : [];
      const newLast = [emailEntry, ...last].slice(0, LAST_EMAILS_MAX);
      let phishingCount = Number(data[STORAGE_KEYS.phishingEmailsCount]) || 0;
      let scannedTotal = Number(data[STORAGE_KEYS.emailsScannedTotal]) || 0;
      if (result.isPhishing) phishingCount += 1;
      scannedTotal += 1;
      await chrome.storage.local.set({
        [STORAGE_KEYS.lastEmails]: newLast,
        [STORAGE_KEYS.phishingEmailsCount]: phishingCount,
        [STORAGE_KEYS.emailsScannedTotal]: scannedTotal,
      });
      return { level: result.level, reason: result.reasons[0] || '', score: result.score, reasons: result.reasons };
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
    const monthCount = await updateBlockedStorage(url, result.reason);
    const rating = getRatingByMonthCount(monthCount);
    const prefs = await chrome.storage.local.get(['trustguard_mode']);
    const mode = prefs.trustguard_mode || 'smart';
    const redirectUrl = buildBlockPageUrl(url, result.reason, details.tabId, rating, mode);
    try {
      await chrome.tabs.update(details.tabId, { url: redirectUrl });
    } catch (_) {}
  },
  { urls: ['<all_urls>'] }
);

// Сброс кэша ключей при изменении настроек
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[STORAGE_KEYS.apiKeys]) cachedApiKeys = null;
});

// При установке: ключи и URL (в т.ч. ngrok) пользователь вводит вручную в настройках
chrome.runtime.onInstalled.addListener(() => {
  loadLocalPhishingList();
});
chrome.runtime.onStartup.addListener(loadLocalPhishingList);
loadLocalPhishingList();
