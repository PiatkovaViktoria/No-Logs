(function () {
  const DEFAULT_STATE = {
    enabled: true,
    blockedLogs: [],
    mode: 'smart',
    exceptions: []
  };

  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.panel');
  const extensionToggle = document.getElementById('extension-enabled');
  const extensionEnabledBtn = document.getElementById('extension-enabled-btn');
  const mainPowerImageWrap = document.getElementById('main-power-image-wrap');
  const mainPowerImage = document.getElementById('main-power-image');
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
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      showPanel(tab.dataset.tab);
      if (tab.dataset.tab === 'logs' || tab.dataset.tab === 'main') loadState(renderMain);
      if (tab.dataset.tab === 'settings') loadState(renderSettings);
    });
  });

  function loadState(cb) {
    chrome.storage.local.get(DEFAULT_STATE, (data) => {
      const state = { ...DEFAULT_STATE, ...data };
      if (Array.isArray(data.blockedLogs)) state.blockedLogs = data.blockedLogs;
      if (Array.isArray(data.exceptions)) state.exceptions = data.exceptions;
      cb(state);
    });
  }

  function saveState(state) {
    chrome.storage.local.set(state);
  }

  function updatePowerButton(enabled) {
    extensionToggle.checked = enabled;
    extensionEnabledBtn.textContent = enabled ? 'Вкл' : 'Выкл';
    extensionEnabledBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    extensionEnabledBtn.classList.toggle('pressed', enabled);
    if (mainPowerImageWrap) mainPowerImageWrap.classList.toggle('power-on', enabled);
  }

  function getRatingFromCount(count) {
    if (count < 20) return 5;
    if (count < 50) return 4;
    if (count < 80) return 3;
    if (count < 150) return 2;
    return 1;
  }

  function renderMain(state) {
    extensionToggle.checked = state.enabled;
    updatePowerButton(state.enabled);
    const count = state.blockedLogs.length;
    if (blockedCountEl) blockedCountEl.textContent = count;
    const rating = getRatingFromCount(count);
    const starsRow = document.getElementById('main-stars');
    if (starsRow) {
      starsRow.querySelectorAll('.star').forEach((star, i) => {
        star.classList.toggle('filled', i < rating);
      });
    }
    const ratingDescEl = document.getElementById('rating-desc');
    if (ratingDescEl) {
      ratingDescEl.classList.remove('rating-desc--red', 'rating-desc--yellow', 'rating-desc--green');
      if (rating <= 2) {
        ratingDescEl.className = 'rating-desc rating-desc--red';
        ratingDescEl.textContent = "Будьте осторожны! Никогда не переходите по подозрительным ссылкам в письмах. Фишинговые страницы могут имитировать дизайн, но не смогут подделать SSL-сертификат, если только это не фейковый gov.ru с окончанием .com.ах.";
        if (state.mode === 'smart') {
          state.mode = 'strict';
          saveState(state);
        }
      } else if (rating === 3 || rating === 4) {
        ratingDescEl.className = 'rating-desc rating-desc--yellow';
        ratingDescEl.textContent = "Внимательнее используйте Интернет пространство. Даже на знакомых сайтах проверяйте сертификат безопасности.";
      } else {
        ratingDescEl.className = 'rating-desc rating-desc--green';
        ratingDescEl.textContent = "Отлично! Ваша бдительность — залог безопасности. Вы умеете распознавать угрозы и не ведетесь на уловки фишеров. Так держать!";
      }
    }
    if (rating <= 2) renderSettings(state);
    blockedLogsEl.innerHTML = '';
    const logs = state.blockedLogs.slice(-20).reverse();
    logs.forEach(entry => {
      const li = document.createElement('li');
      li.textContent = entry.url || entry;
      if (entry.time) {
        const time = document.createElement('span');
        time.style.cssText = 'display:block;font-size:12px;color:#8e8e93;margin-top:2px;';
        time.textContent = new Date(entry.time).toLocaleString('ru');
        li.appendChild(time);
      }
      blockedLogsEl.appendChild(li);
    });
  }

  function renderSettings(state) {
    const strict = document.getElementById('mode-strict');
    const smart = document.getElementById('mode-smart');
    const rating = getRatingFromCount(state.blockedLogs.length);
    const smartDisabled = rating <= 2;
    if (smartDisabled) {
      if (state.mode === 'smart') {
        state.mode = 'strict';
        saveState(state);
      }
      strict.checked = true;
      smart.checked = false;
    } else {
      strict.checked = state.mode === 'strict';
      smart.checked = state.mode === 'smart';
    }
    if (smart) smart.disabled = smartDisabled;
    const smartCard = document.getElementById('mode-card-smart');
    if (smartCard) smartCard.classList.toggle('mode-card-disabled', smartDisabled);

    exceptionsListEl.innerHTML = '';
    (state.exceptions || []).forEach((domain, i) => {
      const li = document.createElement('li');
      li.innerHTML = '<span>' + escapeHtml(domain) + '</span><button type="button" class="remove-btn" data-index="' + i + '">Удалить</button>';
      li.querySelector('.remove-btn').addEventListener('click', () => {
        const exc = state.exceptions.filter((_, j) => j !== i);
        state.exceptions = exc;
        saveState(state);
        renderSettings(state);
      });
      exceptionsListEl.appendChild(li);
    });
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  extensionEnabledBtn.addEventListener('click', () => {
    loadState(state => {
      state.enabled = !state.enabled;
      saveState(state);
      updatePowerButton(state.enabled);
    });
  });

  document.querySelectorAll('input[name="mode"]').forEach(radio => {
    radio.addEventListener('change', () => {
      loadState(state => {
        state.mode = document.querySelector('input[name="mode"]:checked').value;
        saveState(state);
      });
    });
  });

  addExceptionBtn.addEventListener('click', () => {
    const value = (exceptionInput.value || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!value) return;
    if (!confirm('Вы уверены, что хотите добавить «' + value + '» в исключения? Этот сайт не будет блокироваться.')) return;
    loadState(state => {
      state.exceptions = state.exceptions || [];
      if (!state.exceptions.includes(value)) {
        state.exceptions.push(value);
        saveState(state);
        exceptionInput.value = '';
        renderSettings(state);
      }
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
    let url;
    try {
      url = new URL(urlRaw);
    } catch {
      checkResult.textContent = 'Некорректный URL. Введите адрес вида https://example.com';
      checkResult.className = 'check-result visible warning';
      return;
    }
    const host = url.hostname;
    const suspicious = /^\d+\.\d+\.\d+\.\d+$/.test(host) ||
      host.includes('login') || (host.includes('secure') && host.split('.').length > 3);
    checkResult.classList.add('visible');
    if (suspicious) {
      checkResult.className = 'check-result visible warning';
      checkResult.textContent = 'У этого адреса есть признаки, требующие внимания. Проверьте URL и не вводите пароли, если не уверены.';
    } else {
      checkResult.className = 'check-result visible safe';
      checkResult.textContent = 'Явных признаков фишинга не обнаружено. Всё равно проверяйте адрес и не вводите данные на незнакомых сайтах.';
    }
  });

  loadState(state => {
    renderMain(state);
    renderSettings(state);
  });
})();
