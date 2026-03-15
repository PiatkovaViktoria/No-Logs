/**
 * Страница блокировки: причина, URL, рейтинг, кнопки «Назад», «Всё равно перейти» (5–4) или «Ознакомиться с безопасностью» (3–1).
 * При редиректе через DNR параметров нет — URL берём из referrer; рейтинг из storage.
 */
(function () {
  const SAFETY_ARTICLES_URL = 'https://www.kaspersky.ru/resource-center/threats/phishing';
  const STORAGE_KEYS = {
    blockCount: 'trustguard_block_count',
    blockCountMonth: 'trustguard_block_count_month',
    monthKey: 'trustguard_month_key',
  };

  function getRatingByMonthCount(monthCount) {
    if (monthCount <= 20) return 5;
    if (monthCount <= 50) return 4;
    if (monthCount <= 80) return 3;
    if (monthCount <= 150) return 2;
    return 1;
  }

  const STORAGE_MODE_KEY = 'trustguard_mode';
  const params = new URLSearchParams(window.location.search);
  let blocked = params.get('blocked') || '';
  let reason = params.get('reason') || 'Обнаружена угроза';
  const tabId = parseInt(params.get('tabId'), 10);
  const hasTabId = !isNaN(tabId) && tabId >= 0;
  let ratingFromUrl = parseInt(params.get('rating'), 10);
  let modeFromUrl = params.get('mode') || ''; // 'smart' | 'strict': в жёстком режиме кнопки «Всё равно перейти» нет
  if (!blocked && document.referrer) {
    blocked = document.referrer;
    reason = 'Локальная база фишинговых сайтов';
    chrome.runtime.sendMessage({ type: 'TRUSTGUARD_RECORD_BLOCK', url: blocked, reason: reason });
  }

  const elUrl = document.getElementById('blocked-url');
  const elReason = document.getElementById('reason');
  const elCount = document.getElementById('total-count');
  const elMonthCount = document.getElementById('month-count');
  const elRating = document.getElementById('rating-text');
  const btnBack = document.getElementById('btn-back');
  const btnGo = document.getElementById('btn-go');
  const btnSafety = document.getElementById('btn-safety');

  elReason.textContent = decodeURIComponent(reason);
  if (blocked) {
    try {
      elUrl.textContent = new URL(blocked).href;
    } catch (_) {
      elUrl.textContent = blocked;
    }
  } else {
    elUrl.textContent = '—';
    btnGo.style.display = 'none';
  }

  function applyRating(rating, mode) {
    const r = rating >= 1 && rating <= 5 ? rating : 5;
    elRating.textContent = r + ' из 5';
    const isStrict = mode === 'strict';
    // В жёстком режиме кнопки «Всё равно перейти» нет; в умном — показываем при рейтинге 5–4
    const showProceed = !isStrict && (r === 5 || r === 4);
    btnGo.style.display = showProceed ? '' : 'none';
    if (r === 3 || r === 2 || r === 1) {
      btnSafety.style.display = '';
    } else {
      btnSafety.style.display = 'none';
    }
  }

  function applyRatingWithMode(rating, mode) {
    applyRating(rating, mode || 'smart');
  }
  if (ratingFromUrl >= 1 && ratingFromUrl <= 5 && modeFromUrl) {
    applyRatingWithMode(ratingFromUrl, modeFromUrl);
  } else if (ratingFromUrl >= 1 && ratingFromUrl <= 5) {
    chrome.storage.local.get([STORAGE_MODE_KEY], function (data) {
      applyRatingWithMode(ratingFromUrl, data[STORAGE_MODE_KEY] || 'smart');
    });
  } else {
    chrome.storage.local.get([STORAGE_KEYS.blockCountMonth, STORAGE_KEYS.monthKey, STORAGE_MODE_KEY], function (data) {
      const currentMonth = new Date().toISOString().slice(0, 7);
      const monthKey = data[STORAGE_KEYS.monthKey] || '';
      const monthCount = monthKey === currentMonth ? (Number(data[STORAGE_KEYS.blockCountMonth]) || 0) : 0;
      applyRatingWithMode(getRatingByMonthCount(monthCount), data[STORAGE_MODE_KEY] || 'smart');
    });
  }

  chrome.storage.local.get([STORAGE_KEYS.blockCount, STORAGE_KEYS.blockCountMonth, STORAGE_KEYS.monthKey], function (data) {
    const total = Number(data[STORAGE_KEYS.blockCount]) || 0;
    elCount.textContent = String(total);
    const currentMonth = new Date().toISOString().slice(0, 7);
    const monthKey = data[STORAGE_KEYS.monthKey] || '';
    const monthCount = monthKey === currentMonth ? (Number(data[STORAGE_KEYS.blockCountMonth]) || 0) : 0;
    elMonthCount.textContent = String(monthCount);
  });

  function getThisTab(cb) {
    if (hasTabId) return cb({ id: tabId });
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0] && tabs[0].id >= 0) return cb(tabs[0]);
      chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
        cb(tabs[0] && tabs[0].id >= 0 ? tabs[0] : null);
      });
    });
  }

  btnBack.addEventListener('click', function () {
    getThisTab(function (tab) {
      if (tab && tab.id >= 0) {
        chrome.runtime.sendMessage({ type: 'TRUSTGUARD_NAVIGATE', tabId: tab.id }, function () {});
      } else {
        window.location.replace('about:blank');
      }
    });
  });

  btnGo.addEventListener('click', function () {
    if (!blocked) return;
    chrome.runtime.sendMessage({ type: 'TRUSTGUARD_ALLOW_ONCE', url: blocked }, function () {
      getThisTab(function (tab) {
        if (tab && tab.id >= 0) {
          chrome.runtime.sendMessage({ type: 'TRUSTGUARD_NAVIGATE', tabId: tab.id, url: blocked }, function () {});
        } else {
          window.location.href = blocked;
        }
      });
    });
  });

  btnSafety.addEventListener('click', function () {
    window.open(SAFETY_ARTICLES_URL, '_blank', 'noopener');
  });
})();
