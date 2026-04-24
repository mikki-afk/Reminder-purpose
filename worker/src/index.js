// Language Reminder – Cloudflare Worker
// Handles push subscriptions (KV) and sends Web Push at 10 AM / 10 PM UTC+8.
//
// Required environment bindings (set in Cloudflare Dashboard):
//   SUBSCRIPTIONS   – KV namespace
//   VAPID_PUBLIC_KEY  – base64url string (from vapid-keygen step)
//   VAPID_PRIVATE_KEY – base64url string (from vapid-keygen step)

const ENGLISH_CRON = '0 2 * * *';  // 10:00 AM UTC+8
const CHINESE_CRON = '0 14 * * *'; // 10:00 PM UTC+8

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // GET /vapid-public-key  →  return public key for browser subscription
    if (url.pathname === '/vapid-public-key' && request.method === 'GET') {
      return new Response(env.VAPID_PUBLIC_KEY, {
        headers: { 'Content-Type': 'text/plain', ...cors },
      });
    }

    // POST /subscribe  →  save push subscription to KV
    if (url.pathname === '/subscribe' && request.method === 'POST') {
      try {
        const sub = await request.json();
        if (!sub?.endpoint) return new Response('Bad request', { status: 400, headers: cors });
        const key = await digest(sub.endpoint);
        await env.SUBSCRIPTIONS.put(key, JSON.stringify(sub), {
          expirationTtl: 60 * 60 * 24 * 60, // 60 days
        });
        return new Response('subscribed', { status: 201, headers: cors });
      } catch (e) {
        return new Response(e.message, { status: 400, headers: cors });
      }
    }

    // POST /unsubscribe  →  remove subscription
    if (url.pathname === '/unsubscribe' && request.method === 'POST') {
      try {
        const { endpoint } = await request.json();
        await env.SUBSCRIPTIONS.delete(await digest(endpoint));
        return new Response('unsubscribed', { headers: cors });
      } catch (e) {
        return new Response(e.message, { status: 400, headers: cors });
      }
    }

    // POST /test?lang=en|zh  →  send a test push immediately
    if (url.pathname === '/test' && request.method === 'POST') {
      const isEnglish = url.searchParams.get('lang') !== 'zh';
      await sendAll(env, isEnglish);
      return new Response('test sent', { headers: cors });
    }

    return new Response('Language Reminder Push Service', { headers: cors });
  },

  async scheduled(event, env, ctx) {
    const isEnglish = event.cron === ENGLISH_CRON;
    ctx.waitUntil(sendAll(env, isEnglish));
  },
};

// ── Send to all subscribers ───────────────────────────────────────────────────

async function sendAll(env, isEnglish) {
  const { keys } = await env.SUBSCRIPTIONS.list();
  const payload  = JSON.stringify({
    title: isEnglish ? 'English time! 📝' : '中文时间! 💕',
    body:  isEnglish
      ? '10 AM – 10 PM  •  Chat with Claude in English'
      : '晚上10点 – 早上10点  •  用中文和 Claude 聊天',
  });

  await Promise.allSettled(keys.map(async ({ name }) => {
    const raw = await env.SUBSCRIPTIONS.get(name);
    if (!raw) return;
    const sub = JSON.parse(raw);
    try {
      await sendWebPush(sub, payload, env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
    } catch (e) {
      if (e.status === 410 || e.status === 404) {
        await env.SUBSCRIPTIONS.delete(name);
      }
    }
  }));
}

// ── Web Push (VAPID + RFC 8291, no external libraries) ───────────────────────

async function sendWebPush(subscription, payload, vapidPublicKey, vapidPrivateKey) {
  const { endpoint, keys: subKeys } = subscription;
  const audience = new URL(endpoint).origin;

  const jwt       = await createVapidJWT(audience, vapidPublicKey, vapidPrivateKey);
  const encrypted = await encryptPayload(payload, subKeys.p256dh, subKeys.auth);

  const res = await fetch(endpoint, {
    method:  'POST',
    headers: {
      'Authorization':   `vapid t=${jwt},k=${vapidPublicKey}`,
      'Content-Type':    'application/octet-stream',
      'Content-Encoding':'aes128gcm',
      'TTL':             '86400',
    },
    body: encrypted,
  });

  if (!res.ok && res.status !== 201) {
    const err = new Error(`Push failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
}

// ── VAPID JWT (ES256) ─────────────────────────────────────────────────────────

async function createVapidJWT(audience, publicKey, privateKeyB64) {
  const header  = b64url(te('{"typ":"JWT","alg":"ES256"}'));
  const payload = b64url(te(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,
    sub: 'mailto:noreply@language-reminder.app',
  })));

  const data    = `${header}.${payload}`;
  const privKey = await importECPrivateKey(privateKeyB64);
  const sig     = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, te(data));

  return `${data}.${b64url(sig)}`;
}

// Wraps a raw 32-byte P-256 private key in PKCS8 DER so Web Crypto can import it.
async function importECPrivateKey(base64UrlKey) {
  const raw   = b64urlDecode(base64UrlKey);
  const pkcs8 = new Uint8Array([
    0x30, 0x41,
    0x02, 0x01, 0x00,
    0x30, 0x13,
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x04, 0x27,
      0x30, 0x25,
      0x02, 0x01, 0x01,
      0x04, 0x20,
      ...raw,
  ]);
  return crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign'],
  );
}

// ── RFC 8291 payload encryption (aes128gcm) ───────────────────────────────────

async function encryptPayload(payloadStr, p256dhB64, authB64) {
  const clientPub = b64urlDecode(p256dhB64);
  const authSecret = b64urlDecode(authB64);
  const plaintext  = te(payloadStr);

  // Ephemeral server EC key pair
  const serverKP = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
  );
  const serverPub = new Uint8Array(await crypto.subtle.exportKey('raw', serverKP.publicKey));

  // ECDH shared secret
  const clientKey = await crypto.subtle.importKey(
    'raw', clientPub, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: clientKey }, serverKP.privateKey, 256),
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));

  // RFC 8291 key derivation
  const info = cat(te('WebPush: info\0'), clientPub, serverPub);
  const ikm  = await hkdf(authSecret, sharedSecret, info, 32);
  const cek   = await hkdf(salt, ikm, te('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te('Content-Encoding: nonce\0'), 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);

  // Pad with 0x02 delimiter (single last record)
  const padded = new Uint8Array(plaintext.length + 1);
  padded.set(plaintext);
  padded[plaintext.length] = 0x02;

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded),
  );

  // RFC 8291 header: salt(16) + rs(4) + keylen(1) + server_pub(65)
  const header = new Uint8Array(21 + serverPub.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = serverPub.length;
  header.set(serverPub, 21);

  return cat(header, ciphertext);
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function hkdf(salt, ikm, info, len) {
  const key  = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8);
  return new Uint8Array(bits);
}

async function digest(str) {
  const buf = await crypto.subtle.digest('SHA-256', te(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

const te = s => new TextEncoder().encode(s);

function b64url(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function cat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
