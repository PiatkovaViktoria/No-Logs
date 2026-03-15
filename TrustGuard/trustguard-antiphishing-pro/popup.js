/**
 * TrustGuard — попап: счётчик, статус, последние блокировки, письма, настройки API.
 */
(function () {
  const STORAGE_KEYS = {
    blockCount: 'trustguard_block_count',
    lastBlocked: 'trustguard_last_blocked',
    lastEmails: 'trustguard_last_emails',
    apiKeys: 'trustguard_api_keys',
  };

  function renderCounter(count) {
    const el = document.getElementById('counter');
    if (el) el.textContent = String(count);
  }

  function renderLastBlocked(list) {
    const container = document.getElementById('last-blocked');
    if (!container) return;
    if (!list || list.length === 0) {
      container.innerHTML = '<div class="empty">Пока нет</div>';
      return;
    }
    container.innerHTML = list.slice(0, 10).map((item) => `
      <div class="list-item">
        <div>${escapeHtml(shortUrl(item.url))}</div>
        <div class="reason">${escapeHtml(item.reason || '')}</div>
      </div>
    `).join('');
  }

  function renderLastEmails(list) {
    const container = document.getElementById('last-emails');
    if (!container) return;
    if (!list || list.length === 0) {
      container.innerHTML = '<div class="empty">Пока нет</div>';
      return;
    }
    container.innerHTML = list.slice(0, 8).map((item) => {
      const riskClass = item.risk || 'safe';
      const subject = (item.subject || '—').slice(0, 40);
      return `
        <div class="list-item">
          <span class="risk ${riskClass}"></span>
          ${escapeHtml(subject)}
        </div>
      `;
    }).join('');
  }

  function shortUrl(url) {
    try {
      const u = new URL(url);
      return u.hostname + (u.pathname !== '/' ? u.pathname.slice(0, 20) : '');
    } catch (_) {
      return String(url).slice(0, 50);
    }
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function loadMain() {
    chrome.storage.local.get(
      [STORAGE_KEYS.blockCount, STORAGE_KEYS.lastBlocked, STORAGE_KEYS.lastEmails],
      (data) => {
        const count = Number(data[STORAGE_KEYS.blockCount]) || 0;
        renderCounter(count);
        renderLastBlocked(data[STORAGE_KEYS.lastBlocked] || []);
        renderLastEmails(data[STORAGE_KEYS.lastEmails] || []);
      }
    );
  }

  function showKeyStatus(id, result) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'api-status ' + (result.valid || 'empty');
    if (result.valid === 'ok') {
      el.textContent = '✓ Ключ действителен';
    } else if (result.valid === 'invalid') {
      el.textContent = '✗ ' + (result.error || 'Неверный ключ');
    } else {
      el.textContent = '';
    }
  }

  function loadSettings() {
    chrome.storage.local.get([STORAGE_KEYS.apiKeys], (data) => {
      const keys = data[STORAGE_KEYS.apiKeys] || {};
      const g = document.getElementById('api-google');
      const v = document.getElementById('api-vt');
      if (g) g.value = keys.googleSafeBrowsing || '';
      if (v) v.value = keys.virusTotal || '';
      showKeyStatus('api-google-status', { valid: 'empty' });
      showKeyStatus('api-vt-status', { valid: 'empty' });
    });
  }

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      const id = 'panel-' + tab.getAttribute('data-tab');
      const panel = document.getElementById(id);
      if (panel) panel.classList.add('active');
      if (tab.getAttribute('data-tab') === 'settings') loadSettings();
    });
  });

  document.getElementById('btn-save')?.addEventListener('click', () => {
    const google = document.getElementById('api-google')?.value?.trim() || '';
    const vt = document.getElementById('api-vt')?.value?.trim() || '';
    const btn = document.getElementById('btn-save');
    const statusGoogle = document.getElementById('api-google-status');
    const statusVt = document.getElementById('api-vt-status');

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Проверка…';
    }
    if (statusGoogle) statusGoogle.textContent = '';
    if (statusVt) statusVt.textContent = '';

    chrome.runtime.sendMessage(
      { type: 'TRUSTGUARD_VALIDATE_KEYS', googleKey: google, vtKey: vt },
      (result) => {
        if (result && result.google) showKeyStatus('api-google-status', result.google);
        if (result && result.vt) showKeyStatus('api-vt-status', result.vt);
        chrome.storage.local.set({
          [STORAGE_KEYS.apiKeys]: {
            googleSafeBrowsing: google,
            virusTotal: vt,
          },
        }, () => {
          if (btn) {
            btn.disabled = false;
            btn.textContent = 'Сохранено';
            setTimeout(() => { btn.textContent = 'Сохранить и проверить ключи'; }, 2000);
          }
        });
      }
    );
  });

  loadMain();
})();
