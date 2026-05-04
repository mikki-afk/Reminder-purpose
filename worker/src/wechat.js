// WeChat Official Account (公众号) <-> Claude bridge.
// Receives user messages on /wechat, returns "success" within 5s, then
// asynchronously calls Claude and pushes the answer via the customer service
// message API (works for any account inside the 48h window after a user msg).

const WECHAT_API = 'https://api.weixin.qq.com/cgi-bin';
const TOKEN_KEY = 'wechat:access_token';
const HISTORY_PREFIX = 'wechat:history:';
const HISTORY_TURNS = 10;
const SYSTEM_PROMPT =
  'You are Claude, chatting with the user through WeChat. Match the user\'s language. Keep replies concise (under ~400 Chinese chars unless asked for detail).';

export async function handleWechat(request, env, ctx) {
  const url = new URL(request.url);
  const signature = url.searchParams.get('signature') || '';
  const timestamp = url.searchParams.get('timestamp') || '';
  const nonce = url.searchParams.get('nonce') || '';

  if (!(await verifySignature(env.WECHAT_TOKEN, timestamp, nonce, signature))) {
    return new Response('invalid signature', { status: 403 });
  }

  if (request.method === 'GET') {
    return new Response(url.searchParams.get('echostr') || '', { status: 200 });
  }
  if (request.method !== 'POST') {
    return new Response('method not allowed', { status: 405 });
  }

  const msg = parseWechatXml(await request.text());

  if (msg.MsgType === 'event' && msg.Event === 'subscribe') {
    return new Response(buildXmlReply(msg, '你好,我是 Claude。直接发消息给我就行,支持多轮对话。'), {
      headers: { 'Content-Type': 'application/xml' },
    });
  }

  if (msg.MsgType === 'text' && msg.Content) {
    ctx.waitUntil(processMessage(env, msg.FromUserName, msg.Content));
  }

  return new Response('success', { status: 200 });
}

async function verifySignature(token, timestamp, nonce, signature) {
  const joined = [token, timestamp, nonce].sort().join('');
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(joined));
  const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex === signature;
}

function parseWechatXml(xml) {
  const fields = ['ToUserName', 'FromUserName', 'CreateTime', 'MsgType', 'Content', 'MsgId', 'Event'];
  const out = {};
  for (const f of fields) {
    const m = xml.match(new RegExp(`<${f}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${f}>`));
    if (m) out[f] = m[1];
  }
  return out;
}

function buildXmlReply(incoming, content) {
  return `<xml>
<ToUserName><![CDATA[${incoming.FromUserName}]]></ToUserName>
<FromUserName><![CDATA[${incoming.ToUserName}]]></FromUserName>
<CreateTime>${Math.floor(Date.now() / 1000)}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[${content}]]></Content>
</xml>`;
}

async function processMessage(env, openid, userText) {
  try {
    const history = await loadHistory(env, openid);
    const messages = [...history, { role: 'user', content: userText }];

    const reply = await callClaude(env, messages);

    const next = [...messages, { role: 'assistant', content: reply }].slice(-HISTORY_TURNS * 2);
    await saveHistory(env, openid, next);

    await sendCustomerMessage(env, openid, reply);
  } catch (e) {
    await sendCustomerMessage(env, openid, `❌ ${e.message}`).catch(() => {});
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
      model: 'claude-opus-4-7',
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages,
    }),
  });
  if (!res.ok) {
    throw new Error(`Claude ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  const data = await res.json();
  return data.content?.[0]?.text?.trim() || '(空回复)';
}

async function sendCustomerMessage(env, openid, content) {
  const token = await getAccessToken(env);
  for (const chunk of chunkText(content, 600)) {
    const res = await fetch(`${WECHAT_API}/message/custom/send?access_token=${token}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ touser: openid, msgtype: 'text', text: { content: chunk } }),
    });
    const data = await res.json();
    if (data.errcode) {
      throw new Error(`WeChat ${data.errcode}: ${data.errmsg}`);
    }
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

  const res = await fetch(
    `${WECHAT_API}/token?grant_type=client_credential&appid=${env.WECHAT_APP_ID}&secret=${env.WECHAT_APP_SECRET}`,
  );
  const data = await res.json();
  if (!data.access_token) throw new Error(`token fetch: ${JSON.stringify(data)}`);

  const expiresAt = Date.now() + (data.expires_in - 300) * 1000;
  await env.SUBSCRIPTIONS.put(
    TOKEN_KEY,
    JSON.stringify({ token: data.access_token, expiresAt }),
    { expirationTtl: data.expires_in },
  );
  return data.access_token;
}

async function loadHistory(env, openid) {
  const raw = await env.SUBSCRIPTIONS.get(HISTORY_PREFIX + openid, 'json');
  return Array.isArray(raw) ? raw : [];
}

async function saveHistory(env, openid, history) {
  await env.SUBSCRIPTIONS.put(HISTORY_PREFIX + openid, JSON.stringify(history), {
    expirationTtl: 60 * 60 * 24,
  });
}
