// ── CLOUDFLARE PAGES FUNCTION ─────────────────────────────────────────────────
// Equivalent du netlify/functions/claude.js — adapté pour Cloudflare Pages Functions

const ALLOWED_ORIGINS = [
  'https://devispeintpro.pages.dev',
  'https://devispeintpro.olivarionline.workers.dev',
  'https://5233464e.devispeintpro.pages.dev',
];
const ALLOWED_MODEL    = 'claude-sonnet-4-20250514';
const MAX_TOKENS_LIMIT = 2000;
const MAX_MESSAGES     = 4;
const MAX_CONTENT_LEN  = 8000;

// Rate limiting en mémoire
const rateLimitMap = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_CALLS = 15;

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

function verifySupabaseToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(atob(parts[1]));
    if (!payload.exp || Date.now() / 1000 > payload.exp) return false;
    if (payload.role === 'anon') return false;
    if (payload.iss && !payload.iss.includes('supabase')) return false;
    if (!payload.sub) return false;
    return true;
  } catch {
    return false;
  }
}

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const origin = request.headers.get('origin') || '';

  // CORS
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return new Response(JSON.stringify({ error: 'Origin non autorisée' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  // Auth Supabase
  const authHeader = request.headers.get('authorization') || '';
  if (!verifySupabaseToken(authHeader)) {
    return new Response(JSON.stringify({ error: 'Authentification requise' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  // Rate limiting
  const ip = request.headers.get('cf-connecting-ip') || 
             request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
             'unknown';
  if (isRateLimited(ip)) {
    return new Response(JSON.stringify({ error: 'Trop de requêtes. Réessayez dans 1 minute.' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Retry-After': '60', ...corsHeaders(origin) },
    });
  }

  // Parse body
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Body JSON invalide' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  const { messages, max_tokens, system } = body;

  const safeMaxTokens = Math.min(
    Number.isInteger(max_tokens) && max_tokens > 0 ? max_tokens : 1000,
    MAX_TOKENS_LIMIT
  );

  if (!Array.isArray(messages) || messages.length === 0) {
    return new Response(JSON.stringify({ error: 'messages requis' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
  if (messages.length > MAX_MESSAGES) {
    return new Response(JSON.stringify({ error: `Max ${MAX_MESSAGES} messages autorisés` }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  const safeMessages = [];
  for (const msg of messages) {
    if (!msg || typeof msg !== 'object') continue;
    if (!['user', 'assistant'].includes(msg.role)) {
      return new Response(JSON.stringify({ error: 'Role invalide' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    if (typeof msg.content === 'string') {
      if (msg.content.length > MAX_CONTENT_LEN) {
        return new Response(JSON.stringify({ error: 'Message trop long' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }
      safeMessages.push({ role: msg.role, content: msg.content });
    } else if (Array.isArray(msg.content)) {
      const safeBlocks = [];
      for (const block of msg.content) {
        if (block.type === 'text') {
          if (typeof block.text !== 'string' || block.text.length > MAX_CONTENT_LEN) {
            return new Response(JSON.stringify({ error: 'Bloc texte invalide' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
            });
          }
          safeBlocks.push({ type: 'text', text: block.text });
        } else if (block.type === 'image') {
          if (block.source?.type !== 'base64') {
            return new Response(JSON.stringify({ error: 'Source image : base64 requis' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
            });
          }
          const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
          if (!allowed.includes(block.source.media_type)) {
            return new Response(JSON.stringify({ error: 'Type image non autorisé' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
            });
          }
          safeBlocks.push(block);
        }
      }
      safeMessages.push({ role: msg.role, content: safeBlocks });
    }
  }

  const safeSystem = typeof system === 'string' && system.length <= MAX_CONTENT_LEN
    ? system : undefined;

  const safePayload = {
    model:      ALLOWED_MODEL,
    max_tokens: safeMaxTokens,
    messages:   safeMessages,
    ...(safeSystem ? { system: safeSystem } : {}),
  };

  // Appel Anthropic avec timeout 20s
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 20_000);

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body:   JSON.stringify(safePayload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errText = await response.text();
      return new Response(JSON.stringify({ error: `Erreur API: ${response.status}` }), {
        status: response.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });

  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      return new Response(JSON.stringify({ error: 'Délai dépassé. Réessayez.' }), {
        status: 504,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
    return new Response(JSON.stringify({ error: 'Erreur réseau. Réessayez.' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get('origin') || '';
  return new Response(null, {
    status: 204,
    headers: corsHeaders(origin),
  });
}
