/**
 * TrustGuard — проверка писем в Gmail.
 * Определяет открытое письмо, извлекает данные, отправляет в background (analyzeEmail),
 * показывает цветной индикатор; по клику — подробности (почему подозрительно).
 */
(function () {
  const BADGE_ID = 'trustguard-email-badge';
  const TOOLTIP_ID = 'trustguard-email-tooltip';
  const DEBOUNCE_MS = 350;
  let checkTimeout = null;
  let lastCheckedKey = '';
  let lastResult = null;

  // Стили индикаторов подключаются через manifest (css: ["email-styles.css"])

  /** Разворачивает редирект (Gmail часто оборачивает в google.com/url?q=...) для проверки реального URL. */
  function unwrapLink(href) {
    if (!href || !href.startsWith('http')) return href;
    try {
      const u = new URL(href);
      if (/^(www\.)?google\.(com|ru)$/i.test(u.hostname) && u.pathname === '/url' && u.searchParams.has('q')) {
        const q = u.searchParams.get('q');
        if (q && q.startsWith('http')) return q;
      }
      const q = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('q');
      if (q && q.startsWith('http')) return q;
    } catch (_) {}
    return href;
  }

  /** Проверяет, выглядит ли видимый текст ссылки как URL другого домена (подмена). */
  function isTextHrefMismatch(text, href) {
    const t = (text || '').trim().toLowerCase();
    if (!t || t.length < 4) return false;
    const urlPattern = /^https?:\/\/[^\s]+$|^[a-z0-9][-a-z0-9]*\.[a-z]{2,}/;
    if (!urlPattern.test(t)) return false;
    try {
      const textUrl = t.startsWith('http') ? t : 'https://' + t;
      const textHost = new URL(textUrl).hostname.replace(/^www\./, '');
      const hrefHost = new URL(href).hostname.replace(/^www\./, '');
      if (textHost !== hrefHost && !hrefHost.endsWith('.' + textHost) && !textHost.endsWith('.' + hrefHost)) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  function getLinksFromContainer(container) {
    if (!container) return [];
    const links = container.querySelectorAll('a[href^="http"]');
    const out = [];
    const seen = new Set();
    links.forEach((a) => {
      let href = (a.getAttribute('href') || '').trim();
      if (!href || href.startsWith('https://mail.google.com')) return;
      href = unwrapLink(href);
      if (seen.has(href)) return;
      seen.add(href);
      out.push(href);
    });
    return out;
  }

  function getMismatchedLinksCount(container) {
    if (!container) return 0;
    let count = 0;
    const links = container.querySelectorAll('a[href^="http"]');
    links.forEach((a) => {
      let href = (a.getAttribute('href') || '').trim();
      if (!href) return;
      href = unwrapLink(href);
      const text = (a.textContent || '').trim();
      if (isTextHrefMismatch(text, href)) count++;
    });
    return count;
  }

  /** Определяет, когда пользователь открыл письмо, и извлекает отправителя, тему, текст, ссылки */
  function getGmailContent() {
    const main = document.querySelector('[role="main"]') || document.body;
    const contentArea = main.querySelector('.a3s') || main.querySelector('[data-message-id]') || main.querySelector('.ii.gt') || main.querySelector('[role="listitem"]');
    const container = contentArea || main;
    const links = getLinksFromContainer(container);
    const subject = document.querySelector('h2.hP')?.textContent?.trim()
      || document.querySelector('[data-thread-perm-id] h2')?.textContent?.trim()
      || document.querySelector('h2[data-legacy-message-id]')?.textContent?.trim()
      || document.querySelector('.ha h2')?.textContent?.trim()
      || document.title?.split('-').slice(0, -1).join('-').trim()
      || '';
    const from = document.querySelector('.gD')?.getAttribute('email')
      || document.querySelector('.go')?.textContent?.trim()
      || document.querySelector('[email]')?.getAttribute('email')
      || document.querySelector('.gE .gD')?.textContent?.trim()
      || document.querySelector('.sender')?.textContent?.trim()
      || '';
    const text = (container.innerText || '').slice(0, 2000);
    const attachments = getGmailAttachmentUrls(main);
    return { from, subject, text, links, container, attachmentUrls: attachments };
  }

  /** Ссылки на скачивание вложений в Gmail (view=att, attid) */
  function getGmailAttachmentUrls(main) {
    if (!main) return [];
    const links = main.querySelectorAll('a[href*="view=att"], a[href*="attid="], a[download]');
    const out = [];
    const seen = new Set();
    const MAX_ATTACHMENTS = 5;
    const MAX_SIZE = 15 * 1024 * 1024;
    links.forEach((a) => {
      if (out.length >= MAX_ATTACHMENTS) return;
      const href = (a.getAttribute('href') || '').trim();
      if (!href || href === '#' || seen.has(href)) return;
      if (!href.startsWith('http') && !href.startsWith('//')) return;
      const name = (a.getAttribute('aria-label') || a.textContent || a.getAttribute('download') || 'file').trim().slice(0, 80);
      seen.add(href);
      out.push({ url: href.startsWith('//') ? 'https:' + href : href, name: name || 'вложение' });
    });
    return out;
  }

  /** Скачать вложение и отправить на проверку VirusTotal, вернуть результат */
  function scanOneAttachment(url, name) {
    return fetch(url, { credentials: 'include', method: 'GET' })
      .then((r) => r.ok ? r.arrayBuffer() : null)
      .then((buf) => {
        if (!buf || buf.byteLength > 15 * 1024 * 1024) return { safe: true };
        return new Promise((resolve) => {
          chrome.runtime.sendMessage({ action: 'scanFile', fileData: buf, fileName: name }, (res) => {
            resolve(res && typeof res.safe !== 'undefined' ? res : { safe: true });
          });
        });
      })
      .catch(() => ({ safe: true }));
  }

  /** Контейнер для бейджа: тело письма или главная область (актуальный на момент вставки). */
  function getBadgeContainer() {
    const main = document.querySelector('[role="main"]');
    const body = main && (main.querySelector('.a3s') || main.querySelector('[data-message-id]') || main.querySelector('.ii.gt') || main.querySelector('.nH.ar.z'));
    if (body && document.body.contains(body)) return body;
    if (main && document.body.contains(main)) return main;
    return document.body;
  }

  function showBadge(container, result) {
    let badge = document.getElementById(BADGE_ID);
    if (badge) badge.remove();
    const target = (container && document.body.contains(container)) ? container : getBadgeContainer();
    if (!target) return;
    const level = result.level || 'safe';
    const labels = { safe: 'Безопасно', warning: 'Не безопасно', danger: 'Опасно' };
    badge = document.createElement('div');
    badge.id = BADGE_ID;
    badge.className = 'trustguard-email-badge trustguard-' + level;
    badge.innerHTML = '<span class="trustguard-dot"></span><span>' + (labels[level] || 'Проверено') + '</span>';
    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      showTooltip(e, result);
    });
    target.insertBefore(badge, target.firstChild);
  }

  function showTooltip(e, result) {
    let tooltip = document.getElementById(TOOLTIP_ID);
    if (tooltip) {
      tooltip.remove();
      if (lastResult === result) return;
    }
    lastResult = result;
    tooltip = document.createElement('div');
    tooltip.id = TOOLTIP_ID;
    const reasons = (result.reasons && result.reasons.length) ? result.reasons : ['Причин не найдено'];
    tooltip.innerHTML =
      '<div class="trustguard-tooltip-title">Подробности проверки</div>' +
      '<ul class="trustguard-tooltip-reasons">' +
      reasons.map((r) => '<li>' + escapeHtml(r) + '</li>').join('') +
      '</ul>';
    document.body.appendChild(tooltip);
    const rect = e.target.getBoundingClientRect();
    tooltip.style.left = Math.min(rect.left, window.innerWidth - 370) + 'px';
    tooltip.style.top = (rect.bottom + 8) + 'px';
    const close = () => {
      tooltip.remove();
      document.removeEventListener('click', close);
    };
    setTimeout(() => document.addEventListener('click', close), 100);
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function runCheck() {
    const email = getGmailContent();
    const viewKey = (window.location.hash || window.location.pathname || '').slice(0, 80);
    const contentKey = viewKey + '|' + (email.from || '') + '|' + (email.subject || '') + '|' + (email.text || '').slice(0, 80);
    if (contentKey === lastCheckedKey) return;
    lastCheckedKey = contentKey;
    const attachmentUrls = email.attachmentUrls || [];
    const mismatchedLinks = getMismatchedLinksCount(email.container);
    const emailForSend = { from: email.from, subject: email.subject, text: email.text, links: email.links, mismatchedLinks };
    if (attachmentUrls.length === 0) {
      emailForSend.attachmentResults = [];
      chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onAnalyzeResponse);
      return;
    }
    Promise.all(attachmentUrls.map((a) => scanOneAttachment(a.url, a.name)))
      .then((attachmentResults) => {
        emailForSend.attachmentResults = attachmentResults;
        chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onAnalyzeResponse);
      })
      .catch(() => {
        emailForSend.attachmentResults = [];
        chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onAnalyzeResponse);
      });

    function onAnalyzeResponse(response) {
      if (chrome.runtime.lastError) return;
      const res = response || { level: 'safe', reasons: [] };
      lastResult = res;
      showBadge(email.container, res);
    }
  }

  function scheduleCheck() {
    if (checkTimeout) clearTimeout(checkTimeout);
    checkTimeout = setTimeout(runCheck, DEBOUNCE_MS);
  }

  const observer = new MutationObserver(scheduleCheck);
  observer.observe(document.body, { childList: true, subtree: true });
  // Один запуск через 1.2 с после загрузки: контент письма в Gmail успевает подгрузиться
  setTimeout(scheduleCheck, 1200);
})();
