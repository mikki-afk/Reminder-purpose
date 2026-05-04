// JSON chat endpoint for the Mini Program (and any other frontend).
// POST /chat   body: { message: string, sessionId?: string }
// returns:     { reply: string }
//
// Uses sessionId to scope per-user history in the SUBSCRIPTIONS KV.
// Note: this endpoint is open. Add auth (CHAT_SHARED_SECRET header check
// or wx.login + code2Session) before exposing publicly.

const HISTORY_PREFIX = 'chat:history:';
const HISTORY_TURNS = 10;
const SYSTEM_PROMPT =
  "You are Claude, chatting with the user. Match the user's language. Be concise unless asked for detail.";

export async function handleChat(request, env) {
  if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'invalid JSON' }, 400); }

  const message = typeof body?.message === 'string' ? body.message.trim() : '';
  const sessionId = typeof body?.sessionId === 'string' ? body.sessionId.slice(0, 64) : '';
  if (!message) return json({ error: 'message required' }, 400);

  const history = sessionId ? await loadHistory(env, sessionId) : [];
  const messages = [...history, { role: 'user', content: message }];

  const reply = await callClaude(env, messages);

  if (sessionId) {
    const next = [...messages, { role: 'assistant', content: reply }].slice(-HISTORY_TURNS * 2);
    await saveHistory(env, sessionId, next);
  }
  return json({ reply });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
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
  if (!res.ok) throw new Error(`Claude ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  return data.content?.[0]?.text?.trim() || '(空回复)';
}

async function loadHistory(env, sessionId) {
  const raw = await env.SUBSCRIPTIONS.get(HISTORY_PREFIX + sessionId, 'json');
  return Array.isArray(raw) ? raw : [];
}

async function saveHistory(env, sessionId, history) {
  await env.SUBSCRIPTIONS.put(HISTORY_PREFIX + sessionId, JSON.stringify(history), {
    expirationTtl: 60 * 60 * 24,
  });
}
