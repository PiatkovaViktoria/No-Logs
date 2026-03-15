/**
 * TrustGuard — проверка писем в Gmail и Mail.ru.
 * Извлекает отправителя, тему, текст и ссылки, отправляет в background, показывает метку (зелёная/жёлтая/красная).
 */
(function () {
  const HOST = window.location.hostname;
  const isGmail = HOST === 'mail.google.com';
  const isMailRu = HOST.includes('e.mail.ru');
  if (!isGmail && !isMailRu) return;

  const BADGE_ID = 'trustguard-email-badge';
  const DEBOUNCE_MS = 800;
  let checkTimeout = null;
  let lastCheckedContent = '';

  function getLinksFromContainer(container) {
    if (!container) return [];
    const links = container.querySelectorAll('a[href^="http"]');
    const out = [];
    const seen = new Set();
    links.forEach((a) => {
      const href = (a.getAttribute('href') || '').trim();
      if (!href) return;
      // Пропускаем внутренние переходы Gmail/Mail
      if (isGmail && href.startsWith('https://mail.google.com')) return;
      if (isMailRu && href.includes('mail.ru')) return;
      if (seen.has(href)) return;
      seen.add(href);
      out.push(href);
    });
    return out;
  }

  function getGmailContent() {
    // Gmail: область письма — ищем контейнер с текстом письма (могут быть разные разметки)
    const main = document.querySelector('[role="main"]') || document.body;
    const contentArea = main.querySelector('.a3s') || main.querySelector('[data-message-id]') || main.querySelector('.ii.gt');
    const container = contentArea || main;
    const links = getLinksFromContainer(container);
    const subject = document.querySelector('h2.hP')?.textContent?.trim()
      || document.querySelector('[data-thread-perm-id] h2')?.textContent?.trim()
      || document.title?.split('-').slice(0, -1).join('-').trim()
      || '—';
    const from = document.querySelector('.gD')?.getAttribute('email')
      || document.querySelector('.go')?.textContent?.trim()
      || document.querySelector('[email]')?.getAttribute('email')
      || '—';
    const text = (container.innerText || '').slice(0, 500);
    return { from, subject, text, links, container };
  }

  function getMailRuContent() {
    const letter = document.querySelector('.letter__body') || document.querySelector('.letter-body') || document.querySelector('.b-letter__body');
    const container = letter || document.querySelector('.layout__main') || document.body;
    const links = getLinksFromContainer(container);
    const subject = document.querySelector('.letter__subject')?.textContent?.trim()
      || document.querySelector('.b-letter__subject')?.textContent?.trim()
      || document.title?.trim()
      || '—';
    const from = document.querySelector('.letter__author__email')?.textContent?.trim()
      || document.querySelector('.letter__author')?.textContent?.trim()
      || '—';
    const text = (container.innerText || '').slice(0, 500);
    return { from, subject, text, links, container };
  }

  function getEmailContent() {
    if (isGmail) return getGmailContent();
    if (isMailRu) return getMailRuContent();
    return { from: '—', subject: '—', text: '', links: [], container: null };
  }

  function showBadge(container, level, reason) {
    let badge = document.getElementById(BADGE_ID);
    if (badge) badge.remove();
    if (!container) return;
    const colors = { safe: '#28a745', warning: '#ffc107', danger: '#dc3545' };
    const labels = { safe: 'Проверено: безопасно', warning: 'Проверено: осторожно', danger: 'Опасные ссылки' };
    const color = colors[level] || colors.safe;
    badge = document.createElement('div');
    badge.id = BADGE_ID;
    badge.style.cssText = `
      margin: 8px 0; padding: 8px 12px; border-radius: 8px; font-size: 13px;
      background: ${color}22; color: ${color}; border: 1px solid ${color};
      font-family: inherit;
    `;
    badge.textContent = reason ? `${labels[level]} — ${reason}` : labels[level];
    container.insertBefore(badge, container.firstChild);
  }

  function runCheck() {
    const { from, subject, text, links, container } = getEmailContent();
    const contentKey = `${from}|${subject}|${links.length}|${links.slice(0, 3).join('|')}`;
    if (contentKey === lastCheckedContent) return;
    lastCheckedContent = contentKey;

    chrome.runtime.sendMessage(
      {
        type: 'TRUSTGUARD_CHECK_EMAIL',
        from,
        subject,
        text,
        links,
      },
      (response) => {
        if (chrome.runtime.lastError) return;
        const level = (response && response.level) ? response.level : 'safe';
        const reason = (response && response.reason) || '';
        showBadge(container, level, reason);
      }
    );
  }

  function scheduleCheck() {
    if (checkTimeout) clearTimeout(checkTimeout);
    checkTimeout = setTimeout(runCheck, DEBOUNCE_MS);
  }

  // Наблюдаем за изменением контента (открытие другого письма)
  const observer = new MutationObserver(scheduleCheck);
  observer.observe(document.body, { childList: true, subtree: true });

  // Первая проверка с задержкой (страница могла ещё не отрисоваться)
  setTimeout(scheduleCheck, 1500);
})();
