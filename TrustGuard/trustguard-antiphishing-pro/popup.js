/**
 * TrustGuard — попап из фронта extension: Главная, О расширении, Проверить, Обучение, Настройки, Логи.
 * Данные и логика PRO: trustguard_* storage, проверка URL через background, API-ключи.
 */
(function () {
  const STORAGE_KEYS = {
    blockCount: 'trustguard_block_count',
    lastBlocked: 'trustguard_last_blocked',
    blockCountMonth: 'trustguard_block_count_month',
    monthKey: 'trustguard_month_key',
    enabled: 'trustguard_enabled',
    mode: 'trustguard_mode',
    exceptions: 'trustguard_exceptions',
    apiKeys: 'trustguard_api_keys',
    emailsScannedTotal: 'trustguard_emails_scanned_total',
    phishingEmailsCount: 'trustguard_phishing_emails_count',
  };

  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.panel');
  const extensionToggle = document.getElementById('extension-enabled');
  const extensionEnabledBtn = document.getElementById('extension-enabled-btn');
  const mainPowerImageWrap = document.getElementById('main-power-image-wrap');
  const mainPowerImg = document.getElementById('main-power-img');
  const IMAGES = 'extension/images/';
  if (mainPowerImg) mainPowerImg.src = chrome.runtime.getURL(IMAGES + 'robotwhite.png');
  const modeImgStrict = document.getElementById('mode-img-strict');
  const modeImgSmart = document.getElementById('mode-img-smart');
  if (modeImgStrict) modeImgStrict.src = chrome.runtime.getURL(IMAGES + 'robotred.png');
  if (modeImgSmart) modeImgSmart.src = chrome.runtime.getURL(IMAGES + 'robotyellow.png');
  const blockedCountEl = document.getElementById('blocked-count');
  const blockedLogsEl = document.getElementById('blocked-logs');
  const checkBtn = document.getElementById('check-current');
  const checkResult = document.getElementById('check-result');
  const exceptionInput = document.getElementById('exception-input');
  const addExceptionBtn = document.getElementById('add-exception');
  const exceptionsListEl = document.getElementById('exceptions-list');

  function showPanel(panelId) {
    panels.forEach(p => p.classList.remove('active'));
    tabs.forEach(t => t.classList.remove('active'));
    const panel = document.getElementById('panel-' + panelId);
    const tab = document.querySelector('[data-tab="' + panelId + '"]');
    if (panel) panel.classList.add('active');
    if (tab) tab.classList.add('active');
    if (panelId === 'main') loadMain();
    if (panelId === 'logs') loadLogs();
    if (panelId === 'settings') loadSettings();
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => showPanel(tab.dataset.tab));
  });

  function getRatingFromMonthCount(monthCount) {
    if (monthCount <= 20) return 5;
    if (monthCount <= 50) return 4;
    if (monthCount <= 80) return 3;
    if (monthCount <= 150) return 2;
    return 1;
  }

  function loadMain() {
    chrome.storage.local.get(
      [STORAGE_KEYS.blockCount, STORAGE_KEYS.lastBlocked, STORAGE_KEYS.blockCountMonth, STORAGE_KEYS.monthKey, STORAGE_KEYS.enabled, STORAGE_KEYS.emailsScannedTotal, STORAGE_KEYS.phishingEmailsCount],
      (data) => {
        const enabled = data[STORAGE_KEYS.enabled] !== false;
        extensionToggle.checked = enabled;
        extensionEnabledBtn.textContent = enabled ? 'Вкл' : 'Выкл';
        extensionEnabledBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        extensionEnabledBtn.classList.toggle('pressed', enabled);
        if (mainPowerImageWrap) mainPowerImageWrap.classList.toggle('power-on', enabled);

        const count = Number(data[STORAGE_KEYS.blockCount]) || 0;
        if (blockedCountEl) blockedCountEl.textContent = count;

        const totalEl = document.getElementById('emails-total');
        const phishingEl = document.getElementById('emails-phishing');
        if (totalEl) totalEl.textContent = String(Number(data[STORAGE_KEYS.emailsScannedTotal]) || 0);
        if (phishingEl) phishingEl.textContent = String(Number(data[STORAGE_KEYS.phishingEmailsCount]) || 0);

        const currentMonth = new Date().toISOString().slice(0, 7);
        const monthKey = data[STORAGE_KEYS.monthKey] || '';
        const monthCount = monthKey === currentMonth ? (Number(data[STORAGE_KEYS.blockCountMonth]) || 0) : 0;
        const rating = getRatingFromMonthCount(monthCount);

        const starsRow = document.getElementById('main-stars');
        if (starsRow) {
          starsRow.querySelectorAll('.star').forEach((star, i) => {
            star.classList.toggle('filled', i < rating);
          });
        }
        const ratingDescEl = document.getElementById('rating-desc');
        if (ratingDescEl) {
          ratingDescEl.className = 'rating-desc';
          if (rating <= 2) {
            ratingDescEl.classList.add('rating-desc--red');
            ratingDescEl.textContent = 'Будьте осторожны! Не переходите по подозрительным ссылкам. Фишинговые страницы имитируют дизайн банков и сервисов.';
          } else if (rating === 3 || rating === 4) {
            ratingDescEl.classList.add('rating-desc--yellow');
            ratingDescEl.textContent = 'Внимательнее в интернете. Проверяйте адрес и сертификат безопасности на сайтах.';
          } else {
            ratingDescEl.classList.add('rating-desc--green');
            ratingDescEl.textContent = 'Отлично! Ваша бдительность — залог безопасности. Так держать!';
          }
        }
      }
    );
  }

  function loadLogs() {
    chrome.storage.local.get([STORAGE_KEYS.lastBlocked], (data) => {
      const list = Array.isArray(data[STORAGE_KEYS.lastBlocked]) ? data[STORAGE_KEYS.lastBlocked] : [];
      blockedLogsEl.innerHTML = '';
      list.slice(0, 30).forEach((entry) => {
        const li = document.createElement('li');
        li.textContent = entry.url || entry;
        if (entry.time) {
          const time = document.createElement('span');
          time.style.cssText = 'display:block;font-size:11px;color:#8b8f97;margin-top:2px;';
          time.textContent = new Date(entry.time).toLocaleString('ru');
          li.appendChild(time);
        }
        blockedLogsEl.appendChild(li);
      });
    });
  }

  function loadSettings() {
    chrome.storage.local.get(
      [STORAGE_KEYS.mode, STORAGE_KEYS.exceptions, STORAGE_KEYS.apiKeys, STORAGE_KEYS.blockCountMonth, STORAGE_KEYS.monthKey],
      (data) => {
        const mode = data[STORAGE_KEYS.mode] || 'smart';
        const exceptions = Array.isArray(data[STORAGE_KEYS.exceptions]) ? data[STORAGE_KEYS.exceptions] : [];
        document.getElementById('mode-strict').checked = mode === 'strict';
        document.getElementById('mode-smart').checked = mode === 'smart';

        const monthCount = (data[STORAGE_KEYS.monthKey] === new Date().toISOString().slice(0, 7))
          ? (Number(data[STORAGE_KEYS.blockCountMonth]) || 0) : 0;
        const rating = getRatingFromMonthCount(monthCount);
        const smartDisabled = rating <= 2;
        const smartRadio = document.getElementById('mode-smart');
        const smartCard = document.getElementById('mode-card-smart');
        if (smartDisabled) {
          smartRadio.disabled = true;
          smartRadio.checked = false;
          document.getElementById('mode-strict').checked = true;
          if (smartCard) smartCard.classList.add('mode-card-disabled');
        } else {
          smartRadio.disabled = false;
          smartRadio.checked = mode === 'smart';
          document.getElementById('mode-strict').checked = mode === 'strict';
          if (smartCard) smartCard.classList.remove('mode-card-disabled');
        }

        exceptionsListEl.innerHTML = '';
        exceptions.forEach((domain, i) => {
          const li = document.createElement('li');
          li.innerHTML = '<span>' + escapeHtml(domain) + '</span><button type="button" class="remove-btn" data-index="' + i + '">Удалить</button>';
          li.querySelector('.remove-btn').addEventListener('click', () => {
            const next = exceptions.filter((_, j) => j !== i);
            chrome.storage.local.set({ [STORAGE_KEYS.exceptions]: next }, () => {
              chrome.runtime.sendMessage({ type: 'TRUSTGUARD_REBUILD_DNR' });
              loadSettings();
            });
          });
          exceptionsListEl.appendChild(li);
        });

        const keys = data[STORAGE_KEYS.apiKeys] || {};
        const g = document.getElementById('api-google');
        const v = document.getElementById('api-vt');
        const ai = document.getElementById('api-ai');
        const aiUrl = document.getElementById('api-ai-url');
        if (g) g.value = keys.googleSafeBrowsing || '';
        if (v) v.value = keys.virusTotal || '';
        if (ai) ai.value = keys.aiApiKey || '';
        if (aiUrl) aiUrl.value = keys.aiApiUrl || '';
      }
    );
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  extensionEnabledBtn.addEventListener('click', () => {
    chrome.storage.local.get([STORAGE_KEYS.enabled], (data) => {
      const next = data[STORAGE_KEYS.enabled] !== false ? false : true;
      chrome.storage.local.set({ [STORAGE_KEYS.enabled]: next });
      loadMain();
    });
  });

  document.querySelectorAll('input[name="mode"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      const mode = document.querySelector('input[name="mode"]:checked').value;
      chrome.storage.local.set({ [STORAGE_KEYS.mode]: mode });
    });
  });

  addExceptionBtn.addEventListener('click', () => {
    const value = (exceptionInput.value || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!value) return;
    chrome.storage.local.get([STORAGE_KEYS.exceptions], (data) => {
      const list = Array.isArray(data[STORAGE_KEYS.exceptions]) ? data[STORAGE_KEYS.exceptions] : [];
      if (list.includes(value)) return;
      list.push(value);
      chrome.storage.local.set({ [STORAGE_KEYS.exceptions]: list }, () => {
        chrome.runtime.sendMessage({ type: 'TRUSTGUARD_REBUILD_DNR' });
        exceptionInput.value = '';
        loadSettings();
      });
    });
  });

  exceptionInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addExceptionBtn.click();
  });

  document.getElementById('check-url-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') checkBtn.click();
  });

  checkBtn.addEventListener('click', () => {
    checkResult.classList.remove('visible', 'warning', 'safe');
    let urlRaw = (document.getElementById('check-url-input').value || '').trim();
    if (!urlRaw) {
      checkResult.textContent = 'Введите или вставьте URL для проверки.';
      checkResult.className = 'check-result visible warning';
      return;
    }
    if (!/^https?:\/\//i.test(urlRaw)) urlRaw = 'https://' + urlRaw;
    try {
      new URL(urlRaw);
    } catch {
      checkResult.textContent = 'Некорректный URL.';
      checkResult.className = 'check-result visible warning';
      return;
    }
    checkResult.textContent = 'Проверка…';
    checkResult.className = 'check-result visible';
    chrome.runtime.sendMessage({ type: 'TRUSTGUARD_CHECK_URL', url: urlRaw }, (result) => {
      if (chrome.runtime.lastError) {
        checkResult.textContent = 'Ошибка: ' + (chrome.runtime.lastError.message || 'нет ответа');
        checkResult.className = 'check-result visible warning';
        return;
      }
      if (result && result.block) {
        checkResult.textContent = 'Опасный сайт. ' + (result.reason || '');
        checkResult.className = 'check-result visible warning';
      } else {
        checkResult.textContent = 'Явных признаков фишинга не обнаружено. Всё равно проверяйте адрес.';
        checkResult.className = 'check-result visible safe';
      }
    });
  });

  function showKeyStatus(id, result, okMessage) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'api-status ' + (result.valid || 'empty');
    if (result.valid === 'ok') el.textContent = '✓ ' + (okMessage || result.okMessage || 'Ключ действителен');
    else if (result.valid === 'invalid') el.textContent = '✗ ' + (result.error || 'Неверный ключ');
    else el.textContent = '';
  }

  document.getElementById('btn-save').addEventListener('click', () => {
    const google = document.getElementById('api-google').value.trim();
    const vt = document.getElementById('api-vt').value.trim();
    const aiKey = document.getElementById('api-ai').value.trim();
    const aiUrl = document.getElementById('api-ai-url').value.trim();
    const aiUrlResolved = aiUrl || (aiKey.startsWith('AIza') ? 'https://generativelanguage.googleapis.com/v1beta' : 'https://api.openai.com/v1');
    const btn = document.getElementById('btn-save');
    btn.disabled = true;
    btn.textContent = 'Проверка…';
    ['api-google-status', 'api-vt-status', 'api-ai-status'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '';
    });
    chrome.runtime.sendMessage(
      { type: 'TRUSTGUARD_VALIDATE_KEYS', googleKey: google, vtKey: vt, aiKey: aiKey, aiUrl: aiUrlResolved },
      (result) => {
        if (result && result.google) showKeyStatus('api-google-status', result.google);
        if (result && result.vt) showKeyStatus('api-vt-status', result.vt);
        if (result && result.ai) showKeyStatus('api-ai-status', result.ai, result.ai.okMessage);
    chrome.storage.local.set({
      [STORAGE_KEYS.apiKeys]: {
        googleSafeBrowsing: google,
        virusTotal: vt,
            aiApiKey: aiKey,
            aiApiUrl: aiUrlResolved,
      },
    }, () => {
          btn.disabled = false;
          btn.textContent = 'Сохранить и проверить ключи';
        });
      }
    );
  });

  loadMain();
})();
