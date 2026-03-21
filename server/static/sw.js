/**
 * Discoverykastle — Service Worker
 *
 * Handles Web Push events and notification clicks.
 * Must be served from the root path (/sw.js) to cover the entire app scope.
 */

const APP_NAME = 'Discoverykastle';

// Severity → icon colour mapping
const SEVERITY_ICON = {
  critical: '🔴',
  high:     '🟠',
  medium:   '🟡',
  low:      '🔵',
  info:     '⚪',
};

// ── Push event ─────────────────────────────────────────────────────────────
self.addEventListener('push', (event) => {
  let data = { title: APP_NAME, body: 'New alert', severity: 'info', url: '/' };

  if (event.data) {
    try {
      data = { ...data, ...event.data.json() };
    } catch {
      data.body = event.data.text();
    }
  }

  const icon   = SEVERITY_ICON[data.severity] ?? '⚪';
  const title  = `${icon} ${data.title}`;
  const options = {
    body:    data.body,
    icon:    '/static/icon-192.png',
    badge:   '/static/badge-72.png',
    tag:     `dkastle-${data.type ?? 'alert'}`,       // collapse same-type notifications
    renotify: data.severity === 'critical',            // re-notify even if tag matches
    requireInteraction: data.severity === 'critical',  // stay until dismissed
    data:    { url: data.url ?? '/' },
    actions: [
      { action: 'open',    title: 'Open' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Notification click ─────────────────────────────────────────────────────
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const target = event.notification.data?.url ?? '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      // If the app is already open, focus it and navigate
      for (const win of wins) {
        if (win.url.startsWith(self.location.origin)) {
          win.focus();
          win.navigate(target);
          return;
        }
      }
      // Otherwise open a new window
      return clients.openWindow(target);
    })
  );
});

// ── Push subscription change ──────────────────────────────────────────────
// Fired when the browser rotates the subscription automatically.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil(
    self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: event.oldSubscription?.options?.applicationServerKey,
    }).then((newSub) => {
      return fetch('/api/v1/webpush/subscribe', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(newSub.toJSON()),
      });
    }).catch(() => { /* silent — next page load will re-subscribe */ })
  );
});
