/**
 * Страница блокировки: причина, URL, кнопки «Назад» и «Всё равно перейти».
 */
(function () {
  const params = new URLSearchParams(window.location.search);
  const blocked = params.get('blocked') || '';
  const reason = params.get('reason') || 'Обнаружена угроза';

  const elUrl = document.getElementById('blocked-url');
  const elReason = document.getElementById('reason');
  const elCount = document.getElementById('total-count');
  const btnBack = document.getElementById('btn-back');
  const btnGo = document.getElementById('btn-go');

  elReason.textContent = decodeURIComponent(reason);
  if (blocked) {
    try {
      elUrl.textContent = new URL(blocked).href;
    } catch (_) {
      elUrl.textContent = blocked;
    }
  } else {
    elUrl.textContent = '—';
  }

  chrome.storage.local.get(['trustguard_block_count'], function (data) {
    const total = Number(data.trustguard_block_count) || 0;
    elCount.textContent = String(total);
  });

  btnBack.addEventListener('click', function () {
    window.history.back();
  });

  btnGo.addEventListener('click', function () {
    if (!blocked) return;
    chrome.runtime.sendMessage({ type: 'TRUSTGUARD_ALLOW_ONCE', url: blocked }, function () {
      window.location.href = blocked;
    });
  });
})();
