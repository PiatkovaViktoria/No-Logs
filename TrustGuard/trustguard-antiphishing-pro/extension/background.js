function getSimulatedBlockedLogs() {
  const base = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const templates = [
    'https://fake-bank-login.com/secure',
    'https://paypa1-secure.com/account',
    'https://amaz0n-deals.net/login',
    'https://apple-id.verify-now.com',
    'https://microsoft-account.secure.ru',
    'https://vk-com.login.secure-page.com',
    'https://sberbank-online.verify.ru',
    'https://tinkoff-secure.login.net',
    'https://gosuslugi-verify.ru',
    'https://mail-ru.password-reset.com',
    'https://yandex-id.secure.verify.net',
    'https://instagram-login.secure.com',
    'https://telegram-verify.secure.org',
    'https://whatsapp-web.secure-login.com',
    'https://netflix-account.verify-now.net',
    'https://steam-login.secure.com',
    'https://google-account.verify.secure.ru',
    'https://dropbox-files.secure-login.com',
    'https://spotify-account.verify.net',
    'https://twitter-password.secure.com',
    'https://linkedin-verify.secure.org',
    'https://github-login.secure.com',
    'https://discord-verify.secure.net',
    'https://zoom-meeting.secure-login.com',
    'https://webinar-fake.secure.ru',
    'https://tax-refund.irs-verify.com',
    'https://prize-winner.claim-now.net',
    'https://crypto-wallet.secure-connect.com',
    'https://support-apple.verify-id.com',
    'https://security-alert.urgent-fix.net'
  ];
  const total = 170;
  const result = [];
  for (let i = 0; i < total; i++) {
    const url = i < templates.length
      ? templates[i]
      : 'https://phishing-' + (i + 1) + '.suspect-site.com';
    result.push({ url, time: base + i * 3600000 });
  }
  return result;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['blockedLogs', 'exceptions', 'enabled', 'mode'], (data) => {
    if (data.blockedLogs === undefined) {
      chrome.storage.local.set({ blockedLogs: getSimulatedBlockedLogs() });
    }
    if (data.exceptions === undefined) chrome.storage.local.set({ exceptions: [] });
    if (data.enabled === undefined) chrome.storage.local.set({ enabled: true });
    if (data.mode === undefined) chrome.storage.local.set({ mode: 'strict' });
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'LOG_BLOCKED') {
    chrome.storage.local.get(['blockedLogs'], (data) => {
      const logs = Array.isArray(data.blockedLogs) ? data.blockedLogs : [];
      logs.push({ url: msg.url, time: Date.now() });
      chrome.storage.local.set({ blockedLogs: logs });
      sendResponse({ ok: true });
    });
    return true;
  }
});
