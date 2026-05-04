// WeCom (企业微信) self-built app <-> Claude bridge.
// Receives encrypted callbacks, decrypts (AES-CBC), async-calls Claude,
// pushes the reply via the WeCom active send API (no 5s / 48h limits).
//
// Required secrets (wrangler secret put ...):
//   WECOM_TOKEN          – custom string set in WeCom callback config
//   WECOM_AES_KEY        – 43-char EncodingAESKey from WeCom callback config
//   WECOM_CORP_ID        – Corp ID
//   WECOM_SECRET         – self-built app Secret
//   WECOM_AGENT_ID       – self-built app AgentID (number)
//   ANTHROPIC_API_KEY    – Claude API key

const QYAPI = 'https://qyapi.weixin.qq.com/cgi-bin';
const TOKEN_KEY = 'wecom:access_token';
const HISTORY_PREFIX = 'wecom:history:';
const HISTORY_TURNS = 10;
const SYSTEM_PROMPT =
  "You are Claude, chatting with the user through WeCom. Match the user's language. Keep replies concise (under ~400 Chinese chars unless asked for detail).";

export async function handleWecom(request, env, ctx) {
  const url = new URL(request.url);
  const msgSig = url.searchParams.get('msg_signature') || '';
  const timestamp = url.searchParams.get('timestamp') || '';
  const nonce = url.searchParams.get('nonce') || '';
  const aesKey = decodeAesKey(env.WECOM_AES_KEY);

  if (request.method === 'GET') {
    const echostr = url.searchParams.get('echostr') || '';
    if (!(await verifySig(env.WECOM_TOKEN, timestamp, nonce, echostr, msgSig))) {
      return new Response('invalid signature', { status: 403 });
    }
    const { plain } = await aesDecrypt(echostr, aesKey);
    return new Response(plain, { status: 200 });
  }
  if (request.method !== 'POST') {
    return new Response('method not allowed', { status: 405 });
  }

  const encrypt = extractTag(await request.text(), 'Encrypt');
  if (!encrypt) return new Response('missing Encrypt', { status: 400 });

  if (!(await verifySig(env.WECOM_TOKEN, timestamp, nonce, encrypt, msgSig))) {
    return new Response('invalid signature', { status: 403 });
  }

  const { plain } = await aesDecrypt(encrypt, aesKey);
  const msg = parseXml(plain);

  if (msg.MsgType === 'text' && msg.Content) {
    ctx.waitUntil(processMessage(env, msg.FromUserName, msg.Content));
  }
  return new Response('', { status: 200 });
}

async function verifySig(token, timestamp, nonce, encrypt, expected) {
  const joined = [token, timestamp, nonce, encrypt].sort().join('');
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(joined));
  const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex === expected;
}

function decodeAesKey(encodingAesKey) {
  return base64ToBytes(encodingAesKey + '=');
}

async function aesDecrypt(encryptedB64, aesKey) {
  const cipher = base64ToBytes(encryptedB64);
  const iv = aesKey.slice(0, 16);
  const key = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-CBC' }, false, ['decrypt']);
  const padded = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, cipher));
  // Plaintext layout: [16 random][4 BE msg_len][msg][receiver_id]
  const msgLen = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(16, false);
  const msgBytes = padded.slice(20, 20 + msgLen);
  const receiver = new TextDecoder().decode(padded.slice(20 + msgLen));
  return { plain: new TextDecoder().decode(msgBytes), receiver };
}

function base64ToBytes(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function extractTag(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`));
  return m ? m[1] : '';
}

function parseXml(xml) {
  const fields = ['ToUserName', 'FromUserName', 'CreateTime', 'MsgType', 'Content', 'MsgId', 'AgentID', 'Event'];
  const out = {};
  for (const f of fields) {
    const v = extractTag(xml, f);
    if (v) out[f] = v;
  }
  return out;
}

async function processMessage(env, userId, userText) {
  try {
    const history = await loadHistory(env, userId);
    const messages = [...history, { role: 'user', content: userText }];
    const reply = await callClaude(env, messages);
    const next = [...messages, { role: 'assistant', content: reply }].slice(-HISTORY_TURNS * 2);
    await saveHistory(env, userId, next);
    await sendWecomMessage(env, userId, reply);
  } catch (e) {
    await sendWecomMessage(env, userId, `❌ ${e.message}`).catch(() => {});
  }
}

async function callClaude(env, messages) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5',
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages,
    }),
  });
  if (!res.ok) throw new Error(`Claude ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  return data.content?.[0]?.text?.trim() || '(空回复)';
}

async function sendWecomMessage(env, userId, content) {
  const token = await getAccessToken(env);
  for (const piece of chunkText(content, 2000)) {
    const res = await fetch(`${QYAPI}/message/send?access_token=${token}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        touser: userId,
        msgtype: 'text',
        agentid: Number(env.WECOM_AGENT_ID),
        text: { content: piece },
      }),
    });
    const data = await res.json();
    if (data.errcode) throw new Error(`WeCom ${data.errcode}: ${data.errmsg}`);
  }
}

function chunkText(text, size) {
  if (text.length <= size) return [text];
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}

async function getAccessToken(env) {
  const cached = await env.SUBSCRIPTIONS.get(TOKEN_KEY, 'json');
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

  const res = await fetch(`${QYAPI}/gettoken?corpid=${env.WECOM_CORP_ID}&corpsecret=${env.WECOM_SECRET}`);
  const data = await res.json();
  if (!data.access_token) throw new Error(`token: ${JSON.stringify(data)}`);

  const expiresAt = Date.now() + (data.expires_in - 300) * 1000;
  await env.SUBSCRIPTIONS.put(
    TOKEN_KEY,
    JSON.stringify({ token: data.access_token, expiresAt }),
    { expirationTtl: data.expires_in },
  );
  return data.access_token;
}

async function loadHistory(env, userId) {
  const raw = await env.SUBSCRIPTIONS.get(HISTORY_PREFIX + userId, 'json');
  return Array.isArray(raw) ? raw : [];
}

async function saveHistory(env, userId, history) {
  await env.SUBSCRIPTIONS.put(HISTORY_PREFIX + userId, JSON.stringify(history), {
    expirationTtl: 60 * 60 * 24,
  });
}
