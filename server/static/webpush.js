/**
 * Discoverykastle — Web Push client helper
 *
 * Include this script in any page that should show the push subscription banner.
 * It handles the full lifecycle:
 *   1. Check browser support
 *   2. Register service worker
 *   3. Request permission (with a dismissible banner)
 *   4. Subscribe and send subscription to server
 *   5. Handle unsubscribe
 *
 * Usage:
 *   <script src="/static/webpush.js" defer></script>
 *
 * The script looks for optional mount points in the DOM:
 *   #dkastle-notif-banner  — injected automatically if not present
 *   #dkastle-notif-btn     — toggle button to subscribe/unsubscribe
 */

(function () {
  'use strict';

  const API_KEY    = '/api/v1/webpush/vapid-key';
  const API_SUB    = '/api/v1/webpush/subscribe';
  const API_UNSUB  = '/api/v1/webpush/unsubscribe';
  const API_STATUS = '/api/v1/webpush/status';
  const SW_PATH    = '/sw.js';

  // ── Helpers ──────────────────────────────────────────────────────────────

  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw     = atob(base64);
    return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
  }

  async function getVapidKey() {
    const r = await fetch(API_KEY);
    if (!r.ok) return null;
    const d = await r.json();
    return d.public_key;
  }

  // ── Service worker registration ──────────────────────────────────────────

  async function registerSW() {
    if (!('serviceWorker' in navigator)) return null;
    try {
      return await navigator.serviceWorker.register(SW_PATH, { scope: '/' });
    } catch (err) {
      console.warn('[dkastle/push] SW registration failed:', err);
      return null;
    }
  }

  // ── Subscribe ────────────────────────────────────────────────────────────

  async function subscribe(reg) {
    const publicKey = await getVapidKey();
    if (!publicKey) return null; // web push not enabled server-side

    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      try {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });
      } catch (err) {
        console.warn('[dkastle/push] Subscribe failed:', err);
        return null;
      }
    }

    // Send to server
    await fetch(API_SUB, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(sub.toJSON()),
    });

    return sub;
  }

  // ── Unsubscribe ───────────────────────────────────────────────────────────

  async function unsubscribe(reg) {
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return;

    await fetch(API_UNSUB, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ endpoint: sub.endpoint }),
    });

    await sub.unsubscribe();
  }

  // ── Banner ────────────────────────────────────────────────────────────────

  function injectBanner() {
    if (document.getElementById('dkastle-notif-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'dkastle-notif-banner';
    banner.setAttribute('role', 'alert');
    banner.style.cssText = [
      'position:fixed', 'bottom:20px', 'right:20px', 'z-index:9999',
      'background:#1a1d27', 'border:1px solid #2a2d3e', 'border-left:4px solid #5b6af0',
      'border-radius:8px', 'padding:16px 20px', 'max-width:360px', 'box-shadow:0 4px 24px #0006',
      'font-family:system-ui,sans-serif', 'font-size:13px', 'color:#e2e4f0',
      'display:flex', 'flex-direction:column', 'gap:10px',
    ].join(';');

    banner.innerHTML = `
      <div style="font-weight:600">🔔 Enable browser notifications</div>
      <div style="color:#7a7f9a;line-height:1.4">
        Get instant alerts when critical vulnerabilities or security events are detected.
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button id="_dkastle_allow" style="
          background:#5b6af0;color:#fff;border:none;padding:7px 16px;
          border-radius:5px;font-size:12px;cursor:pointer;font-weight:600">
          Allow notifications
        </button>
        <button id="_dkastle_later" style="
          background:transparent;color:#7a7f9a;border:1px solid #2a2d3e;
          padding:7px 14px;border-radius:5px;font-size:12px;cursor:pointer">
          Not now
        </button>
      </div>`;

    document.body.appendChild(banner);
    return banner;
  }

  function removeBanner() {
    const b = document.getElementById('dkastle-notif-banner');
    if (b) b.remove();
  }

  // ── Toggle button state ──────────────────────────────────────────────────

  function updateToggleBtn(subscribed) {
    const btn = document.getElementById('dkastle-notif-btn');
    if (!btn) return;
    btn.textContent    = subscribed ? '🔔 Notifications on' : '🔕 Notifications off';
    btn.dataset.active = subscribed ? 'true' : 'false';
  }

  // ── Main ──────────────────────────────────────────────────────────────────

  async function init() {
    // Quick check — is web push supported AND enabled on this server?
    if (!('PushManager' in window)) return; // browser doesn't support it

    const statusRes = await fetch(API_STATUS).catch(() => null);
    if (!statusRes?.ok) return;
    const status = await statusRes.json();
    if (!status.enabled) return;

    const reg = await registerSW();
    if (!reg) return;

    const permission = Notification.permission;

    // Already granted — quietly subscribe/refresh
    if (permission === 'granted') {
      const sub = await subscribe(reg);
      updateToggleBtn(!!sub);
      return;
    }

    // Denied — nothing we can do
    if (permission === 'denied') return;

    // Default — show banner
    const banner = injectBanner();

    document.getElementById('_dkastle_allow')?.addEventListener('click', async () => {
      removeBanner();
      const granted = await Notification.requestPermission();
      if (granted === 'granted') {
        const sub = await subscribe(reg);
        updateToggleBtn(!!sub);
      }
    });

    document.getElementById('_dkastle_later')?.addEventListener('click', () => {
      removeBanner();
      // Remember dismissal for this session
      sessionStorage.setItem('dkastle_push_dismissed', '1');
    });

    // Don't re-show if dismissed in this session
    if (sessionStorage.getItem('dkastle_push_dismissed')) {
      if (banner) banner.remove();
    }
  }

  // ── Public API (window.DkastlePush) ──────────────────────────────────────

  window.DkastlePush = {
    /** Manually trigger the subscribe flow (call from a settings button). */
    async enable() {
      const reg = await registerSW();
      if (!reg) return;
      const granted = Notification.permission === 'granted'
        ? 'granted'
        : await Notification.requestPermission();
      if (granted !== 'granted') return;
      removeBanner();
      const sub = await subscribe(reg);
      updateToggleBtn(!!sub);
    },

    /** Unsubscribe this browser. */
    async disable() {
      const reg = await navigator.serviceWorker?.getRegistration(SW_PATH);
      if (!reg) return;
      await unsubscribe(reg);
      updateToggleBtn(false);
    },

    /** Returns "granted" | "denied" | "default" */
    get permission() { return Notification.permission; },
  };

  // Auto-init when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
