// druvc.com gatekeeper — Cloudflare Worker (Dr. UVC LLC)
// Free pages pass through to the public site. /premium/* is served from a PRIVATE R2 bucket
// only to signed-in paid subscribers (active Stripe subscription) or holders of a valid access code.
// Sign-in is a one-time email link (no passwords); every sign-in email goes onto the list.
//
// Bindings (wrangler.toml): KV = GATE (users, tokens, sessions, codes, caches), R2 = PREMIUM.
// Secrets (set by UV in the Cloudflare dashboard, never in code): STRIPE_KEYS (one or more restricted
// read-only keys, comma-separated), RESEND_KEY (email sending), ADMIN_KEY (for list export / code admin).
// Vars: SITE_ORIGIN (public site), FROM_EMAIL, SITE_NAME.

const DAY = 86400;
const SESSION_DAYS = 30;

export async function onRequest(ctx) {
    const req = ctx.request, env = ctx.env;
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p.startsWith('/functions/') || p === '/wrangler.toml' || p.startsWith('/.git')) return new Response('Not found', { status: 404 });
      if (p === '/account/login') return req.method === 'POST' ? login(req, env, url) : page(env, 'Sign in', loginForm());
      if (p === '/account/verify') return verify(req, env, url);
      if (p === '/account/logout') return logout(req, env);
      if (p === '/account/code') return req.method === 'POST' ? redeem(req, env) : page(env, 'Access code', codeForm());
      if (p === '/account') return account(req, env);
      if (p.startsWith('/admin/')) return admin(req, env, url);
      if (p.startsWith('/premium/')) return premium(req, env, url, ctx);
      const r = await ctx.next();
      const h = new Headers(r.headers); h.set('X-Robots-Tag', 'noai, noimageai');
      return new Response(r.body, { status: r.status, headers: h });
    } catch (e) {
      return page(env, 'Error', `<p>Something went wrong. Please try again.</p>`, 500);
    }
}


// ---------- sign-in by email link ----------
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length < 200;

async function login(req, env, url) {
  const f = await req.formData();
  const email = String(f.get('email') || '').trim().toLowerCase();
  const next = safeNext(String(f.get('next') || '/premium/'));
  if (!emailOk(email)) return page(env, 'Sign in', `<p>Please enter a valid email address.</p>` + loginForm(next), 400);
  if (!(await limit(env, `rl:login:${email}`, 5, 3600)) || !(await limit(env, `rl:loginip:${ip(req)}`, 20, 3600)))
    return page(env, 'Sign in', `<p>Too many requests. Please try again in an hour.</p>`, 429);
  const u = (await env.GATE.get(`user:${email}`, 'json')) || { email, created: now(), source: 'signin' };
  u.last_request = now();
  await env.GATE.put(`user:${email}`, JSON.stringify(u));
  const token = rand(32);
  await env.GATE.put(`token:${token}`, JSON.stringify({ email, next }), { expirationTtl: 900 });
  const link = `${url.origin}/account/verify?t=${token}`;
  await sendMail(env, email, `Your ${env.SITE_NAME} sign-in link`,
    `<p>Click to sign in to ${env.SITE_NAME}. The link works once and expires in 15 minutes.</p><p><a href="${link}">Sign in</a></p>`);
  return page(env, 'Check your email', `<p>We sent a sign-in link to <b>${esc(email)}</b>. It expires in 15 minutes.</p>`);
}

async function verify(req, env, url) {
  const t = url.searchParams.get('t') || '';
  const rec = t && (await env.GATE.get(`token:${t}`, 'json'));
  if (!rec) return page(env, 'Link expired', `<p>This link has expired or was already used.</p>` + loginForm(), 400);
  await env.GATE.delete(`token:${t}`);
  const sid = rand(32);
  await env.GATE.put(`session:${sid}`, JSON.stringify({ email: rec.email, created: now() }), { expirationTtl: SESSION_DAYS * DAY });
  const u = (await env.GATE.get(`user:${rec.email}`, 'json')) || { email: rec.email, created: now() };
  u.verified = true; u.last_login = now();
  await env.GATE.put(`user:${rec.email}`, JSON.stringify(u));
  return redirect(rec.next || '/premium/', cookie('sid', sid, SESSION_DAYS * DAY));
}

async function logout(req, env) {
  const sid = cookies(req).sid;
  if (sid) await env.GATE.delete(`session:${sid}`);
  return redirect('/', cookie('sid', '', 0));
}

async function session(req, env) {
  const sid = cookies(req).sid;
  if (!sid) return null;
  return env.GATE.get(`session:${sid}`, 'json');
}

// ---------- paid status from Stripe (one or more accounts) ----------
async function isPaid(env, email) {
  const ck = `paid:${email}`;
  const c = await env.GATE.get(ck);
  if (c !== null) return c === '1';
  let paid = false;
  const keys = String(env.STRIPE_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const key of keys) {
    const q = encodeURIComponent(`email:'${email.replace(/'/g, "\\'")}'`);
    const cr = await fetch(`https://api.stripe.com/v1/customers/search?query=${q}&limit=10`, { headers: { Authorization: `Bearer ${key}` } });
    if (!cr.ok) continue;
    const cust = (await cr.json()).data || [];
    for (const cu of cust) {
      const sr = await fetch(`https://api.stripe.com/v1/subscriptions?customer=${cu.id}&status=all&limit=20`, { headers: { Authorization: `Bearer ${key}` } });
      if (!sr.ok) continue;
      const subs = (await sr.json()).data || [];
      if (subs.some((s) => ['active', 'trialing', 'past_due'].includes(s.status))) { paid = true; break; }
    }
    if (paid) break;
  }
  await env.GATE.put(ck, paid ? '1' : '0', { expirationTtl: paid ? 6 * 3600 : 1800 });
  return paid;
}

// ---------- access codes ----------
// code record: { scope: "/premium/" or "/premium/key55/", expires: unix, uses_left: n|null, note }
async function redeem(req, env) {
  const f = await req.formData();
  const code = String(f.get('code') || '').trim().toUpperCase();
  if (!(await limit(env, `rl:code:${ip(req)}`, 10, 3600))) return page(env, 'Access code', `<p>Too many attempts. Please try again later.</p>`, 429);
  let rec = code && (await env.GATE.get(`code:${code}`, 'json'));
  if (!rec && env.TEST_CODE && code === env.TEST_CODE) rec = { scope: '/premium/', expires: now() + DAY, uses_left: null };
  if (!rec || (rec.expires && rec.expires < now()) || rec.uses_left === 0)
    return page(env, 'Access code', `<p>That code is not valid or has expired.</p>` + codeForm(), 400);
  if (typeof rec.uses_left === 'number') { rec.uses_left -= 1; await env.GATE.put(`code:${code}`, JSON.stringify(rec)); }
  const gid = rand(24);
  const ttl = Math.max(60, Math.min((rec.expires || now() + 30 * DAY) - now(), 90 * DAY));
  await env.GATE.put(`grant:${gid}`, JSON.stringify({ code, scope: rec.scope || '/premium/', expires: now() + ttl }), { expirationTtl: ttl });
  return redirect(rec.scope || '/premium/', cookie('g', gid, ttl));
}

async function grant(req, env, path) {
  const g = cookies(req).g;
  if (!g) return null;
  const rec = await env.GATE.get(`grant:${g}`, 'json');
  return rec && path.startsWith(rec.scope) ? rec : null;
}

// ---------- premium pages (private R2) ----------
async function premium(req, env, url, ctx) {
  const s = await session(req, env);
  const g = await grant(req, env, url.pathname);
  let who = null;
  if (s && (await isPaid(env, s.email))) who = s.email;
  else if (g) who = `code ${g.code}`;
  if (!who) {
    const msg = s
      ? `<p>You are signed in as <b>${esc(s.email)}</b>, but we don't see an active paid subscription for this email.</p>
         <p><a class="btn" href="https://uvc9876.substack.com/subscribe">Become a paid subscriber</a></p>
         <p>Subscribed with a different email? <a href="/account/logout">Sign out</a> and sign in with that one. Have an access code? <a href="/account/code">Enter it here</a>.</p>`
      : `<p>This page is for paid subscribers.</p>` + loginForm(url.pathname) + `<p>Have an access code? <a href="/account/code">Enter it here</a>.</p>`;
    return page(env, 'Premium', msg, 403);
  }
  if (!(await limit(env, `rl:view:${who}`, 120, 3600))) return page(env, 'Slow down', `<p>Too many pages in a short time. Please try again later.</p>`, 429);
  let key = url.pathname.replace(/^\/premium\//, '');
  if (key === '' || key.endsWith('/')) key += 'index.html';
  const obj = await env.PREMIUM.get(key);
  if (!obj && env.TEST_CODE && key === 'index.html') return new Response(`<!doctype html><html><body style="background:#FFFEF2;font-family:Georgia;padding:30px"><h1 style="color:#1E5C2E">Premium test page</h1><p>If you can read this, the gate let you in.</p></body></html>`.replace('</body>', `<div style="font:12px Georgia;color:#9a8a40;text-align:center">Licensed to ${esc(who)} · Do not redistribute</div></body>`), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  if (!obj) return page(env, 'Not found', `<p>That page doesn't exist.</p>`, 404);
  const type = obj.httpMetadata?.contentType || guessType(key);
  const h = new Headers({ 'Content-Type': type, 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex, noai, noimageai' });
  if (type.startsWith('text/html')) {
    let html = await obj.text();
    const mark = `<div style="font:12px Georgia,serif;color:#9a8a40;text-align:center;padding:10px">Licensed to ${esc(who)} · ${new Date().toISOString().slice(0, 10)} · Do not redistribute</div>`;
    html = html.includes('</body>') ? html.replace('</body>', mark + '</body>') : html + mark;
    return new Response(html, { headers: h });
  }
  return new Response(obj.body, { headers: h });
}

// ---------- account ----------
async function account(req, env) {
  const s = await session(req, env);
  if (!s) return page(env, 'Account', loginForm('/account'));
  const paid = await isPaid(env, s.email);
  return page(env, 'Account', `<p>Signed in as <b>${esc(s.email)}</b>.</p><p>Status: <b>${paid ? 'Paid subscriber' : 'Free'}</b></p>
    <p><a href="/premium/">Premium pages</a> · <a href="/account/logout">Sign out</a></p>`);
}

// ---------- admin (UV only, with ADMIN_KEY) ----------
async function admin(req, env, url) {
  const auth = req.headers.get('Authorization') || '';
  if (!env.ADMIN_KEY || auth !== `Bearer ${env.ADMIN_KEY}`) return new Response('Forbidden', { status: 403 });
  if (url.pathname === '/admin/list.csv') {
    let rows = ['email,created,last_login,verified,source'], cursor;
    do {
      const r = await env.GATE.list({ prefix: 'user:', cursor });
      for (const k of r.keys) {
        const u = await env.GATE.get(k.name, 'json');
        if (u) rows.push([u.email, iso(u.created), iso(u.last_login), u.verified ? 'yes' : 'no', u.source || ''].join(','));
      }
      cursor = r.list_complete ? null : r.cursor;
    } while (cursor);
    return new Response(rows.join('\n'), { headers: { 'Content-Type': 'text/csv' } });
  }
  if (url.pathname === '/admin/code' && req.method === 'POST') {
    const b = await req.json();
    const code = String(b.code || rand(4).toUpperCase()).toUpperCase();
    const rec = { scope: b.scope || '/premium/', expires: b.days ? now() + b.days * DAY : null, uses_left: b.uses ?? null, note: b.note || '' };
    await env.GATE.put(`code:${code}`, JSON.stringify(rec));
    return Response.json({ code, ...rec });
  }
  return new Response('Not found', { status: 404 });
}

// ---------- helpers ----------
async function sendMail(env, to, subject, html) {
  if (!env.RESEND_KEY) { console.log('MAIL', to, subject, html); return; }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: `Bearer ${env.RESEND_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.FROM_EMAIL, to, subject, html }),
  });
  if (!r.ok) throw new Error('mail failed');
}
async function limit(env, key, max, ttl) {
  const n = parseInt((await env.GATE.get(key)) || '0', 10);
  if (n >= max) return false;
  await env.GATE.put(key, String(n + 1), { expirationTtl: ttl });
  return true;
}
const now = () => Math.floor(Date.now() / 1000);
const iso = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 10) : '');
const ip = (req) => req.headers.get('CF-Connecting-IP') || 'x';
const rand = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, n * 2);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeNext = (n) => (n.startsWith('/') && !n.startsWith('//') ? n : '/premium/');
const cookie = (k, v, maxAge) => `${k}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
function cookies(req) {
  const o = {};
  (req.headers.get('Cookie') || '').split(';').forEach((c) => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = c.slice(i + 1).trim(); });
  return o;
}
const redirect = (to, setCookie) => new Response(null, { status: 302, headers: { Location: to, ...(setCookie ? { 'Set-Cookie': setCookie } : {}) } });
function guessType(k) {
  const e = k.split('.').pop().toLowerCase();
  return { html: 'text/html; charset=utf-8', png: 'image/png', jpg: 'image/jpeg', pdf: 'application/pdf', css: 'text/css', js: 'text/javascript', csv: 'text/csv' }[e] || 'application/octet-stream';
}
const loginForm = (next = '/premium/') => `<form method="post" action="/account/login"><p>Enter your email and we'll send you a one-time sign-in link. No password needed.</p>
  <input type="email" name="email" required placeholder="you@example.com"><input type="hidden" name="next" value="${esc(next)}"> <button>Send link</button></form>`;
const codeForm = () => `<form method="post" action="/account/code"><p>Enter your access code.</p><input name="code" required placeholder="CODE"> <button>Unlock</button></form>`;
function page(env, title, body, status = 200) {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex, noai, noimageai"><title>${esc(title)} · ${esc(env.SITE_NAME || '')}</title>
<style>body{background:#FFFEF2;font-family:Georgia,serif;color:#1A1A1A;margin:0}.bar{background:#1E5C2E;color:#FFFEF2;padding:10px 16px}.bar a{color:#FFFEF2;text-decoration:none;font-weight:bold}
.wrap{max-width:560px;margin:30px auto;padding:0 18px}h1{color:#1E5C2E;font-size:30px}p{font-size:19px;line-height:1.6}input{font-size:18px;padding:8px;border:1px solid #CBB76A;width:70%}
button,.btn{font-size:18px;padding:8px 14px;background:#1E5C2E;color:#fff;border:0;border-radius:4px;text-decoration:none;display:inline-block;margin-top:8px}hr{border:0;border-top:2px solid #CBB76A}</style></head>
<body><div class="bar"><a href="/">Dr. UVC Market Insights</a></div><div class="wrap"><h1>${esc(title)}</h1><hr>${body}</div></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}
