// ── CONFIGURATION ────────────────────────────────────────────────────────────
const ALLOWED_ORIGIN   = 'https://steady-otter-138034.netlify.app';
const ALLOWED_MODEL    = 'claude-sonnet-4-20250514';   // modèle autorisé — jamais Opus
const MAX_TOKENS_LIMIT = 2000;                          // plafond absolu tokens
const MAX_MESSAGES     = 4;                             // max messages dans un appel
const MAX_CONTENT_LEN  = 8000;                          // max caractères par message

// Rate limiting en mémoire (reset à chaque cold start Netlify)
// Pour une protection plus robuste en prod, utiliser Upstash Redis ou Netlify Blobs
const rateLimitMap = new Map();
const RATE_WINDOW_MS = 60_000;  // fenêtre 1 minute
const RATE_MAX_CALLS = 15;       // max 15 appels par minute par IP

function getRateKey(event) {
  return event.headers['x-forwarded-for']?.split(',')[0]?.trim()
      || event.headers['client-ip']
      || 'unknown';
}

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW_MS) {
    rateLimitMap.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count++;
  return entry.count > RATE_MAX_CALLS;
}

// ── HANDLER ───────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  const origin = event.headers.origin || event.headers.Origin || '';

  // CORS — preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age':       '86400',
      },
      body: '',
    };
  }

  // Méthode
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  // CORS — bloque les appels depuis d'autres domaines
  // En dev local (pas de CONTEXT), on est permissif
  const isDev = !process.env.CONTEXT || process.env.CONTEXT === 'dev';
  if (!isDev && origin && origin !== ALLOWED_ORIGIN) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Origin non autorisée' }),
    };
  }

  // Rate limiting par IP
  const ip = getRateKey(event);
  if (isRateLimited(ip)) {
    return {
      statusCode: 429,
      headers: { 'Retry-After': '60', 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
      body: JSON.stringify({ error: 'Trop de requêtes. Réessayez dans 1 minute.' }),
    };
  }

  // Parsing body
  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'Body JSON invalide' }) };
  }

  // ── VALIDATION STRICTE DU PAYLOAD ────────────────────────────────────────
  const { messages, max_tokens, system } = body;

  // max_tokens : plafonné — un attaquant ne peut jamais forcer de gros tokens
  const safeMaxTokens = Math.min(
    Number.isInteger(max_tokens) && max_tokens > 0 ? max_tokens : 1000,
    MAX_TOKENS_LIMIT
  );

  // Messages : structure et longueur
  if (!Array.isArray(messages) || messages.length === 0) {
    return { statusCode: 400, body: JSON.stringify({ error: 'messages requis' }) };
  }
  if (messages.length > MAX_MESSAGES) {
    return { statusCode: 400, body: JSON.stringify({ error: `Max ${MAX_MESSAGES} messages autorisés` }) };
  }

  const safeMessages = [];
  for (const msg of messages) {
    if (!msg || typeof msg !== 'object') continue;
    if (!['user', 'assistant'].includes(msg.role)) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Role invalide' }) };
    }

    if (typeof msg.content === 'string') {
      if (msg.content.length > MAX_CONTENT_LEN) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Message trop long' }) };
      }
      safeMessages.push({ role: msg.role, content: msg.content });

    } else if (Array.isArray(msg.content)) {
      // Blocs vision (text + image) — on valide chaque bloc
      const safeBlocks = [];
      for (const block of msg.content) {
        if (block.type === 'text') {
          if (typeof block.text !== 'string' || block.text.length > MAX_CONTENT_LEN) {
            return { statusCode: 400, body: JSON.stringify({ error: 'Bloc texte invalide ou trop long' }) };
          }
          safeBlocks.push({ type: 'text', text: block.text });
        } else if (block.type === 'image') {
          // Uniquement base64 — pas d'URL externe (SSRF)
          if (block.source?.type !== 'base64') {
            return { statusCode: 400, body: JSON.stringify({ error: 'Source image : base64 requis' }) };
          }
          const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
          if (!allowed.includes(block.source.media_type)) {
            return { statusCode: 400, body: JSON.stringify({ error: 'Type image non autorisé' }) };
          }
          safeBlocks.push(block);
        } else {
          return { statusCode: 400, body: JSON.stringify({ error: `Type de bloc non autorisé: ${block.type}` }) };
        }
      }
      safeMessages.push({ role: msg.role, content: safeBlocks });
    } else {
      return { statusCode: 400, body: JSON.stringify({ error: 'Format message invalide' }) };
    }
  }

  // system prompt : autorisé mais longueur limitée
  const safeSystem = typeof system === 'string' && system.length <= MAX_CONTENT_LEN
    ? system
    : undefined;

  // ── PAYLOAD RECONSTRUIT PROPREMENT — aucune propriété non validée ne passe ──
  const safePayload = {
    model:      ALLOWED_MODEL,     // toujours Sonnet, jamais Opus
    max_tokens: safeMaxTokens,     // toujours plafonné à 2000
    messages:   safeMessages,
    ...(safeSystem ? { system: safeSystem } : {}),
  };

  // ── APPEL API ─────────────────────────────────────────────────────────────
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(safePayload),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`Anthropic API error ${response.status}:`, errText);
      return {
        statusCode: response.status,
        headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
        body: JSON.stringify({ error: `Erreur API: ${response.status}` }),
      };
    }

    const data = await response.json();
    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
      body: JSON.stringify(data),
    };

  } catch (err) {
    console.error('Erreur réseau vers Anthropic:', err.message);
    return {
      statusCode: 502,
      headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
      body: JSON.stringify({ error: 'Erreur réseau. Réessayez.' }),
    };
  }
};
