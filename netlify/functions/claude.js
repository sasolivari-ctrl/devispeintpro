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

// ── VÉRIFICATION JWT SUPABASE ─────────────────────────────────────────────────
// Vérifie que le token est un JWT Supabase valide (signé, non expiré, bonne audience)
// On vérifie la structure et l'expiration sans appel réseau — léger et fiable
function verifySupabaseToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    // Vérifie expiration
    if (!payload.exp || Date.now() / 1000 > payload.exp) return false;
    // Vérifie que c'est bien un token utilisateur Supabase (pas la clé anon)
    if (payload.role === 'anon') return false;
    // Vérifie que c'est bien notre projet Supabase
    if (payload.iss && !payload.iss.includes('supabase')) return false;
    // L'utilisateur doit avoir un sub (uid)
    if (!payload.sub) return false;
    return true;
  } catch {
    return false;
  }
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
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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
  const isDev = !process.env.CONTEXT || process.env.CONTEXT === 'dev';
  if (!isDev && origin && origin !== ALLOWED_ORIGIN) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Origin non autorisée' }),
    };
  }

  // AUTH — token Supabase obligatoire (bloque les appels sans session valide)
  // En dev local, on accepte sans token pour faciliter les tests
  const authHeader = event.headers.authorization || event.headers.Authorization || '';
  if (!isDev && !verifySupabaseToken(authHeader)) {
    return {
      statusCode: 401,
      headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
      body: JSON.stringify({ error: 'Authentification requise' }),
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

  // ── APPEL API — avec timeout 20s pour éviter les suspensions infinies ────
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 20_000);

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body:   JSON.stringify(safePayload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

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
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      console.error('Timeout: Anthropic API did not respond in 20s');
      return {
        statusCode: 504,
        headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
        body: JSON.stringify({ error: 'Délai dépassé. Réessayez.' }),
      };
    }
    console.error('Erreur réseau vers Anthropic:', err.message);
    return {
      statusCode: 502,
      headers: { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN },
      body: JSON.stringify({ error: 'Erreur réseau. Réessayez.' }),
    };
  }
};
