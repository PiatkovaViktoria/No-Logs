/**
 * TrustGuard — проверка писем на Mail.ru (e.mail.ru, mail.ru).
 * Определяет структуру письма, извлекает отправителя, тему, текст, ссылки,
 * отправляет в background (analyzeEmail), показывает индикатор; по клику — подробности.
 */
(function () {
  const BADGE_ID = 'trustguard-email-badge';
  const TOOLTIP_ID = 'trustguard-email-tooltip';
  const DEBOUNCE_MS = 350;
  let checkTimeout = null;
  let lastCheckedKey = '';
  let lastResult = null;

  // Стили подключаются через manifest (css: ["email-styles.css"])

  function unwrapLink(href) {
    if (!href || !href.startsWith('http')) return href;
    try {
      const u = new URL(href);
      const q = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('destination') || u.searchParams.get('q');
      if (q && q.startsWith('http')) return q;
    } catch (_) {}
    return href;
  }

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
      if (!href) return;
      href = unwrapLink(href);
      if (href.includes('mail.ru')) return;
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

  /** Извлечение данных письма на Mail.ru */
  function getMailRuContent() {
    const letter = document.querySelector('.letter__body') || document.querySelector('.letter-body') || document.querySelector('.b-letter__body');
    const container = letter || document.querySelector('.layout__main') || document.body;
    const links = getLinksFromContainer(container);
    const subject = document.querySelector('.letter__subject')?.textContent?.trim()
      || document.querySelector('.b-letter__subject')?.textContent?.trim()
      || document.title?.trim()
      || '';
    const from = document.querySelector('.letter__author__email')?.textContent?.trim()
      || document.querySelector('.letter__author')?.textContent?.trim()
      || '';
    const text = (container.innerText || '').slice(0, 2000);
    const attachments = getMailRuAttachmentUrls();
    return { from, subject, text, links, container, attachmentUrls: attachments };
  }

  function getMailRuAttachmentUrls() {
    const container = document.querySelector('.letter__body') || document.querySelector('.layout__main') || document.body;
    if (!container) return [];
    const links = container.querySelectorAll('.letter__attachment a[href], .b-letter__attachment a[href], a[href*="attachment"], a[href*="get/"]');
    const out = [];
    const seen = new Set();
    links.forEach((a) => {
      if (out.length >= 5) return;
      const href = (a.getAttribute('href') || '').trim();
      if (!href || seen.has(href) || !href.startsWith('http')) return;
      const name = (a.textContent || a.getAttribute('title') || 'вложение').trim().slice(0, 80);
      seen.add(href);
      out.push({ url: href, name: name || 'вложение' });
    });
    return out;
  }

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

  /** Контейнер для бейджа: тело письма или главная область. */
  function getBadgeContainer() {
    const letter = document.querySelector('.letter__body') || document.querySelector('.b-letter__body') || document.querySelector('.letter-body');
    if (letter && document.body.contains(letter)) return letter;
    const main = document.querySelector('.layout__main');
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
    const email = getMailRuContent();
    const contentKey = email.from + '|' + email.subject + '|' + email.links.length + '|' + (email.text || '').slice(0, 80);
    if (contentKey === lastCheckedKey) return;
    lastCheckedKey = contentKey;
    const attachmentUrls = email.attachmentUrls || [];
    const mismatchedLinks = getMismatchedLinksCount(email.container);
    const emailForSend = { from: email.from, subject: email.subject, text: email.text, links: email.links, mismatchedLinks };
    if (attachmentUrls.length === 0) {
      emailForSend.attachmentResults = [];
      chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onResponse);
      return;
    }
    Promise.all(attachmentUrls.map((a) => scanOneAttachment(a.url, a.name)))
      .then((attachmentResults) => {
        emailForSend.attachmentResults = attachmentResults;
        chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onResponse);
      })
      .catch(() => {
        emailForSend.attachmentResults = [];
        chrome.runtime.sendMessage({ action: 'analyzeEmail', email: emailForSend }, onResponse);
      });

    function onResponse(response) {
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
  setTimeout(scheduleCheck, 600);
})();
