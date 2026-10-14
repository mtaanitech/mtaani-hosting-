require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { db, save, init, close } = require('./db');
const E = require('./engine');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('Set JWT_SECRET in the environment'); process.exit(1); }
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
// Public address of this server. If BASE_URL is not set it is detected from the request, so OAuth/Paystack callbacks never point at localhost.
const baseOf = req => process.env.BASE_URL ? BASE_URL : `${req.protocol}://${req.get('host')}`;
const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').toLowerCase().replace(/^\./, '');
const ADMIN_ENV = (process.env.ADMIN_PASSWORD || '').trim();
const ADMIN_PASSWORD = ADMIN_ENV || crypto.randomBytes(9).toString('base64url'); // temporary one is printed in the logs if you forget to set it
const PSK = process.env.PAYSTACK_SECRET_KEY;
const GH_ID = (process.env.GITHUB_CLIENT_ID || '').trim(), GH_SECRET = (process.env.GITHUB_CLIENT_SECRET || '').trim();
const TURNSTILE_SECRET = (process.env.TURNSTILE_SECRET || '').trim(), TURNSTILE_SITE_KEY = (process.env.TURNSTILE_SITE_KEY || '').trim();
const TURNSTILE_ON = !!(TURNSTILE_SECRET && TURNSTILE_SITE_KEY);
const MAX_PROJECTS = Number(process.env.MAX_PROJECTS || 10);
const RESERVED = ['www', 'app', 'api', 'admin', 'mail', 'static', 's', 'dashboard', 'login', 'status'];
const RESERVED_ENV = ['PORT', 'PATH', 'HOME'];
const REPO_RE = /^[\w.-]+\/[\w.-]+$/;

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = msg => new HttpError(400, msg);

const app = express();
app.set('trust proxy', 1);
// Express 4 does not catch errors thrown inside async handlers: wrap every route handler so they reach the error handler.
['get', 'post', 'put', 'patch', 'delete'].forEach(m => {
  const orig = app[m].bind(app);
  app[m] = (p, ...handlers) => {
    if (!handlers.length) return orig(p);
    return orig(p, ...handlers.map(h => (typeof h === 'function' && h.length < 4)
      ? (req, res, next) => { try { const r = h(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); } } : h));
  };
});
const ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use((req, res, next) => { // CORS only matters if the frontend lives on another origin
  const o = req.headers.origin;
  if (o && ORIGINS.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o); res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});

/* ---------- helpers ---------- */
const { now, DAY, isActive, expiry } = E;
const uid = () => crypto.randomBytes(8).toString('hex');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const daysLeft = u => Math.max(0, Math.ceil((expiry(u) - now()) / DAY));
const userStatus = u => u.blocked ? 'blocked' : !u.verified ? 'unverified' : (u.paidUntil && now() < u.paidUntil) ? 'paid' : now() < (u.trialEndsAt || 0) ? 'trial' : 'expired';
const publicUser = u => ({
  id: u.id, email: u.email, displayName: u.displayName || u.email.split('@')[0], status: userStatus(u), active: isActive(u), daysLeft: daysLeft(u),
  trialEndsAt: u.trialEndsAt, paidUntil: u.paidUntil || 0, price: E.getPrice(), hasPassword: !!u.passHash,
  github: { connected: !!u.ghToken, login: u.githubLogin || null },
  storage: { usedBytes: E.usageBytes(u.id), quotaBytes: E.quotaBytes(u) }
});
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hmac = t => crypto.createHmac('sha256', JWT_SECRET).update(t).digest('base64url');
const hits = new Map();
function limiter(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path, h = hits.get(k) || { c: 0, r: now() + windowMs };
    if (now() > h.r) { h.c = 0; h.r = now() + windowMs; }
    if (++h.c > max) return res.status(429).json({ error: 'Too many requests, please wait a moment.' });
    hits.set(k, h); next();
  };
}
setInterval(() => { for (const [k, h] of hits) if (now() > h.r) hits.delete(k); }, 600000).unref();
const pageHtml = (title, msg) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font-family:system-ui,sans-serif;background:#000;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><div style="padding:24px"><h1 style="font-weight:600">${esc(title)}</h1><p style="color:#a1a1aa">${msg}</p><p><a style="color:#34d399" href="${esc(BASE_URL)}">MtaaniHost</a></p></div>`;

/* ---------- email (verification codes) ---------- */
// Render FREE blocks SMTP ports, so use BREVO_API_KEY (HTTPS) there. Gmail SMTP works on paid plans.
const MAIL_USER = (process.env.GMAIL_USER || process.env.SMTP_USER || '').trim();
const MAIL_PASS = (process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASS || '').replace(/\s+/g, '');
const MAIL_FROM = (process.env.MAIL_FROM || MAIL_USER).trim();
const BREVO_KEY = (process.env.BREVO_API_KEY || '').trim();
const smtp = MAIL_USER && MAIL_PASS ? nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: MAIL_USER, pass: MAIL_PASS }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 }) : null;
const mailMode = BREVO_KEY ? 'brevo' : smtp ? 'smtp' : 'none';
// Real-email verification: default is ON when email sending is configured. Force with REQUIRE_EMAIL_VERIFY=1 or 0.
const ENV_VERIFY = process.env.REQUIRE_EMAIL_VERIFY ? process.env.REQUIRE_EMAIL_VERIFY === '1' : mailMode !== 'none';
const requireVerify = () => db.settings.requireVerify === undefined ? ENV_VERIFY : !!db.settings.requireVerify; // the admin can switch it in the admin panel
async function sendEmail(to, subject, html) {
  if (BREVO_KEY) {
    if (!MAIL_FROM) throw new Error('MAIL_FROM is not set');
    const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': BREVO_KEY, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ sender: { name: 'MtaaniHost', email: MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html }) });
    if (!r.ok) throw new Error('Brevo error ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return;
  }
  if (smtp) return smtp.sendMail({ from: `"MtaaniHost" <${MAIL_FROM}>`, to, subject, html });
  throw new Error('Email is not configured');
}
const sendCode = (email, code) => sendEmail(email, `Your MtaaniHost code: ${code}`, `<div style="font-family:sans-serif"><h2>Welcome to MtaaniHost</h2><p>Your verification code:</p><p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p><p>It expires in 15 minutes.</p></div>`);

/* ---------- "verify you are human" ---------- */
const usedHuman = new Map();
setInterval(() => { for (const [k, exp] of usedHuman) if (now() > exp) usedHuman.delete(k); }, 300000).unref();
async function verifyHuman(req) {
  try {
    if (TURNSTILE_ON) {
      const token = String(req.body.cfToken || ''); if (!token) return false;
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, remoteip: req.ip || '' }) });
      return !!(await r.json()).success;
    }
    const [n, exp, sig] = String(req.body.humanToken || '').split('.'), answer = String(req.body.humanAnswer || '').trim();
    if (!n || !exp || !sig || !answer || now() > Number(exp) || usedHuman.has(n)) return false;
    usedHuman.set(n, Number(exp)); // single use, burned on every attempt
    return safeEq(sig, hmac(`human.${n}.${exp}.${answer}`));
  } catch (e) { console.error('human check', e.message); return false; }
}
const HUMAN_FAIL = { error: 'Human check failed. Please try again.' };

/* ---------- GitHub helpers ---------- */
const tokenOf = u => u && u.ghToken ? E.decrypt(u.ghToken) : null;
async function ghApi(token, p) {
  const r = await fetch('https://api.github.com' + p, { headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'MtaaniHost', 'X-GitHub-Api-Version': '2022-11-28', ...(token ? { Authorization: 'Bearer ' + token } : {}) } });
  let json = null; try { json = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, json };
}
const stateSign = o => { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return p + '.' + hmac('oauth.' + p); };
function stateRead(s) {
  const [p, sig] = String(s || '').split('.');
  if (!p || !sig || !safeEq(sig, hmac('oauth.' + p))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > now() ? o : null; } catch { return null; }
}
const ghAuthUrl = (req, mode, userId) => 'https://github.com/login/oauth/authorize?' + new URLSearchParams({
  client_id: GH_ID, redirect_uri: `${baseOf(req)}/api/github/callback`, allow_signup: 'true',
  scope: mode === 'import' ? 'repo read:user user:email' : 'read:user user:email', state: stateSign({ mode, uid: userId || null, exp: now() + 10 * 60000, n: uid() })
});

/* ---------- serving deployed sites (name.BASE_DOMAIN and /s/name) ---------- */
function candidates(p) {
  let x; try { x = decodeURIComponent(p); } catch { return null; }
  if (x.includes('\0') || x.split('/').includes('..')) return null;
  x = x.replace(/^\/+/, '');
  return x === '' || x.endsWith('/') ? [x + 'index.html'] : [x, x + '.html', x + '/index.html'];
}
function sendObj(req, res, o, status) {
  res.status(status); res.setHeader('Content-Type', o.type); if (o.size) res.setHeader('Content-Length', o.size);
  res.setHeader('Cache-Control', 'public, max-age=300'); res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'HEAD') { if (o.stream.destroy) o.stream.destroy(); return res.end(); }
  o.stream.on('error', () => res.destroy()); o.stream.pipe(res);
}
async function serveProject(slug, req, res) {
  const p = db.projects.find(x => x.slug === slug);
  if (!p) return res.status(404).send(pageHtml('Site not found', 'No project is using this address yet.'));
  if (!isActive(db.users.find(u => u.id === p.userId)) || p.adminSuspended) return res.status(402).send(pageHtml('This site is suspended', `The owner of <b>${esc(p.name)}</b> needs to pay, or an admin turned it off.`));
  if (p.kind === 'service') return p.exposeWeb ? E.proxy(p, req, res) : res.status(404).send(pageHtml('No website', 'This project is a background worker and has no website.'));
  if (!['GET', 'HEAD'].includes(req.method)) return res.status(405).send('Method not allowed');
  if (!['live'].includes(p.status) && !p.lastDeployAt) return res.status(503).send(pageHtml('Deploying…', 'This site is being built. Refresh in a minute.'));
  const cands = candidates(req.path);
  if (!cands) return res.status(400).send('Bad request');
  for (const c of cands) { const o = await E.storeGet(p, c); if (o) return sendObj(req, res, o, 200); }
  const nf = await E.storeGet(p, '404.html'); if (nf) return sendObj(req, res, nf, 404);
  if (!/\.[a-z0-9]{1,8}$/i.test(req.path)) { const idx = await E.storeGet(p, 'index.html'); if (idx) return sendObj(req, res, idx, 200); } // single-page apps
  res.status(404).send(pageHtml('404', 'This page does not exist.'));
}
app.use((req, res, next) => {
  if (!BASE_DOMAIN) return next();
  const host = (req.hostname || '').toLowerCase();
  if (!host.endsWith('.' + BASE_DOMAIN)) return next();
  const slug = host.slice(0, -(BASE_DOMAIN.length + 1));
  if (!slug || slug.includes('.') || RESERVED.includes(slug)) return next();
  return serveProject(slug, req, res);
});
app.use('/s/:slug', (req, res) => serveProject(req.params.slug, req, res)); // fallback address when no wildcard domain is set up

/* ---------- Paystack webhook (raw body, before express.json) ---------- */
async function creditPayment(reference) {
  if (db.payments.find(p => p.reference === reference)) return true;
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), { headers: { Authorization: 'Bearer ' + PSK } });
  const j = await r.json();
  if (!j.status || !j.data || j.data.status !== 'success') return false;
  const d = j.data, user = db.users.find(u => u.id === (d.metadata && d.metadata.userId));
  const expected = (db.pending[reference] || {}).amount || E.getPrice() * 100;
  if (!user || d.currency !== 'KES' || d.amount < expected) return false;
  if (db.payments.find(p => p.reference === reference)) return true;
  user.paidUntil = Math.max(now(), user.paidUntil || 0) + 30 * DAY;
  db.payments.push({ id: reference, reference, userId: user.id, email: user.email, amount: d.amount / 100, currency: d.currency, channel: d.channel, at: now() });
  delete db.pending[reference]; save();
  resumeUser(user.id);
  return true;
}
const resumeUser = userId => db.projects.filter(p => p.userId === userId).forEach(p => E.resumeProject(p));
app.post('/api/paystack/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const sig = crypto.createHmac('sha512', PSK || '').update(req.body).digest('hex');
    if (!safeEq(sig, req.headers['x-paystack-signature'] || '')) return res.sendStatus(401);
    const ev = JSON.parse(req.body.toString());
    if (ev.event === 'charge.success') await creditPayment(ev.data.reference);
    res.sendStatus(200);
  } catch (e) { console.error('webhook', e); res.sendStatus(500); }
});

app.use(express.json({ limit: '200kb' }));

/* ---------- public config ---------- */
app.get('/api/health', (req, res) => res.json({ ok: true, mail: mailMode, requireVerify: requireVerify(), baseUrlSet: !!process.env.BASE_URL, githubCallback: `${baseOf(req)}/api/github/callback`, adminConfigured: !!ADMIN_ENV, githubConfigured: !!(GH_ID && GH_SECRET), storage: E.storeMode(), persistentDb: !!process.env.MONGODB_URI, baseDomain: BASE_DOMAIN || null }));
app.get('/api/config', (req, res) => res.json({ price: E.getPrice(), trialDays: E.getTrialDays(), storageGB: E.getStorageGB(), currency: 'KES', human: TURNSTILE_ON ? 'turnstile' : 'math', turnstileSiteKey: TURNSTILE_ON ? TURNSTILE_SITE_KEY : '', github: !!(GH_ID && GH_SECRET), baseDomain: BASE_DOMAIN || null }));
app.get('/api/human', limiter(60, 15 * 60000), (req, res) => {
  if (TURNSTILE_ON) return res.json({ type: 'turnstile' });
  const a = crypto.randomInt(2, 10), b = crypto.randomInt(2, 10), n = uid(), exp = now() + 5 * 60000;
  res.json({ type: 'math', question: `${a} + ${b}`, token: `${n}.${exp}.${hmac(`human.${n}.${exp}.${a + b}`)}` });
});

/* ---------- auth ---------- */
function auth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    if (d.role !== 'user') throw new Error();
    const u = db.users.find(x => x.id === d.id); if (!u) throw new Error();
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
}
function adminAuth(req, res, next) {
  try { if (jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET).role !== 'admin') throw new Error(); next(); }
  catch { res.status(401).json({ error: 'Admin only' }); }
}
const authLimit = limiter(20, 15 * 60000);
const tokenFor = u => jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
const activate = u => { if (!u.verified) { u.verified = true; u.trialEndsAt = now() + E.getTrialDays() * DAY; } u.code = null; };

app.post('/api/auth/signup', authLimit, async (req, res) => {
  if (!(await verifyHuman(req))) return res.status(400).json(HUMAN_FAIL);
  const email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw bad('Invalid email');
  if (password.length < 8) throw bad('Password must be at least 8 characters');
  let u = db.users.find(x => x.email === email);
  if (u && u.verified) throw new HttpError(409, 'This email already has an account. Please log in.');
  const code = String(crypto.randomInt(100000, 1000000)), passHash = await bcrypt.hash(password, 10);
  if (!u) { u = { id: uid(), email, verified: false, trialEndsAt: 0, paidUntil: 0, blocked: false, createdAt: now() }; db.users.push(u); }
  Object.assign(u, { passHash, code, codeExp: now() + 15 * 60000, codeTries: 0 });
  if (!requireVerify()) { activate(u); save(); return res.json({ ok: true, verified: true, token: tokenFor(u), user: publicUser(u) }); }
  save();
  try { await sendCode(email, code); } catch (e) { console.error('mail', e.message); throw new HttpError(500, 'Could not send the verification email. Please try again later.'); }
  res.json({ ok: true });
});
app.post('/api/auth/resend', authLimit, async (req, res) => {
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || u.verified) return res.json({ ok: true });
  u.code = String(crypto.randomInt(100000, 1000000)); u.codeExp = now() + 15 * 60000; u.codeTries = 0; save();
  try { await sendCode(u.email, u.code); } catch (e) { console.error('mail', e.message); throw new HttpError(500, 'Could not send the email'); }
  res.json({ ok: true });
});
app.post('/api/auth/verify', authLimit, (req, res) => {
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || !u.code) throw bad('Invalid code');
  if (now() > u.codeExp || u.codeTries >= 5) throw bad('Code expired. Please request a new one.');
  u.codeTries++;
  if (!safeEq(u.code, String(req.body.code || '').trim())) { save(); throw bad('Invalid code'); }
  activate(u); save(); res.json({ ok: true });
});
app.post('/api/auth/login', authLimit, async (req, res) => {
  if (!(await verifyHuman(req))) return res.status(400).json(HUMAN_FAIL);
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || !u.passHash || !(await bcrypt.compare(String(req.body.password || ''), u.passHash))) throw new HttpError(401, u && !u.passHash ? 'This account uses GitHub. Press "Continue with GitHub".' : 'Incorrect email or password');
  if (!u.verified && !requireVerify()) { activate(u); save(); }
  if (!u.verified) return res.status(403).json({ error: 'Please verify your email first', needVerify: true });
  if (u.blocked) throw new HttpError(403, 'Your account has been blocked. Please contact the admin.');
  res.json({ token: tokenFor(u), user: publicUser(u) });
});
app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));

/* ---------- GitHub: login, connect, repositories, detection ---------- */
const needGh = () => { if (!GH_ID || !GH_SECRET) throw new HttpError(503, 'GitHub login is not configured on the server (set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET).'); };
app.get('/api/auth/github', (req, res) => {
  if (!GH_ID || !GH_SECRET) return res.redirect('/#/login?error=' + encodeURIComponent('GitHub login is not configured yet.'));
  res.redirect(ghAuthUrl(req, 'login'));
});
app.post('/api/github/connect', auth, (req, res) => { needGh(); res.json({ url: ghAuthUrl(req, 'import', req.user.id) }); });
app.post('/api/github/disconnect', auth, (req, res) => { req.user.ghToken = null; save(); res.json({ ok: true }); });
app.get('/api/github/callback', async (req, res) => {
  const st = stateRead(req.query.state), fail = msg => res.redirect('/#/login?error=' + encodeURIComponent(msg));
  if (!st || !req.query.code) return fail('GitHub sign-in expired. Please try again.');
  try {
    needGh();
    const tr = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ client_id: GH_ID, client_secret: GH_SECRET, code: req.query.code, redirect_uri: `${baseOf(req)}/api/github/callback` }) });
    const access = (await tr.json()).access_token;
    if (!access) return fail('GitHub did not accept the sign-in. Please try again.');
    const me = await ghApi(access, '/user');
    if (!me.ok) return fail('Could not read your GitHub profile.');
    if (st.mode === 'import') {
      const u = db.users.find(x => x.id === st.uid);
      if (!u) return fail('Please log in first.');
      const other = db.users.find(x => x.githubId === me.json.id && x.id !== u.id);
      if (other) return res.redirect('/#/new?error=' + encodeURIComponent('That GitHub account is already linked to another MtaaniHost account.'));
      u.githubId = me.json.id; u.githubLogin = me.json.login; u.ghToken = E.encrypt(access); save();
      return res.redirect('/#/new?connected=1');
    }
    const em = await ghApi(access, '/user/emails');
    const emails = em.ok && Array.isArray(em.json) ? em.json : [];
    const best = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
    if (!best) return fail('Your GitHub account has no verified email. Verify one on GitHub, then try again.');
    const email = best.email.toLowerCase();
    let u = db.users.find(x => x.githubId === me.json.id) || db.users.find(x => x.email === email);
    if (!u) { u = { id: uid(), email, verified: true, trialEndsAt: now() + E.getTrialDays() * DAY, paidUntil: 0, blocked: false, createdAt: now(), displayName: me.json.name || me.json.login }; db.users.push(u); }
    if (!u.githubId) { u.githubId = me.json.id; u.githubLogin = me.json.login; }
    activate(u); save();
    if (u.blocked) return fail('Your account has been blocked. Please contact the admin.');
    res.redirect('/#/oauth?token=' + encodeURIComponent(tokenFor(u)));
  } catch (e) { console.error('github callback', e.message); fail('GitHub sign-in failed. Please try again.'); }
});
app.get('/api/github/repos', auth, async (req, res) => {
  const token = tokenOf(req.user);
  if (!token) return res.status(400).json({ error: 'GitHub is not connected', needConnect: true });
  const r = await ghApi(token, '/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member');
  if (r.status === 401) { req.user.ghToken = null; save(); return res.status(400).json({ error: 'The GitHub connection expired. Please connect again.', needConnect: true }); }
  if (!r.ok) throw new HttpError(502, 'GitHub error ' + r.status);
  res.json(r.json.map(x => ({ id: x.id, full_name: x.full_name, name: x.name, private: x.private, default_branch: x.default_branch, updated_at: x.pushed_at || x.updated_at, description: x.description, language: x.language })));
});
app.get('/api/github/detect', auth, async (req, res) => {
  const repo = String(req.query.repo || '').trim();
  if (!REPO_RE.test(repo)) throw bad('Use the format owner/repository');
  const token = tokenOf(req.user), enc = encodeURIComponent;
  const info = await ghApi(token, `/repos/${repo}`);
  if (info.status === 404) return res.status(404).json({ error: 'Repository not found. If it is private, connect GitHub first.', needConnect: !token });
  if (!info.ok) throw new HttpError(502, 'GitHub error ' + info.status);
  const branch = String(req.query.branch || '').trim() || info.json.default_branch;
  const list = await ghApi(token, `/repos/${repo}/contents?ref=${enc(branch)}`);
  if (!list.ok) throw new HttpError(404, `Branch "${branch}" was not found.`);
  const names = Array.isArray(list.json) ? list.json.map(f => f.name) : [];
  let pkg = null;
  if (names.includes('package.json')) {
    const f = await ghApi(token, `/repos/${repo}/contents/package.json?ref=${enc(branch)}`);
    try { pkg = JSON.parse(Buffer.from(f.json.content, 'base64').toString('utf8')); } catch {}
  }
  res.json({ repo: info.json.full_name, branch, private: info.json.private, ...E.detectConfig(pkg, names) });
});

/* ---------- projects ---------- */
function projectView(p) {
  const owner = db.users.find(u => u.id === p.userId), active = isActive(owner) && !p.adminSuspended;
  return {
    id: p.id, name: p.name, slug: p.slug, kind: p.kind, exposeWeb: !!p.exposeWeb, repo: p.repo, branch: p.branch, framework: p.framework || '',
    installCmd: p.installCmd || '', buildCmd: p.buildCmd || '', startCmd: p.startCmd || '', outputDir: p.outputDir || '',
    url: BASE_DOMAIN ? `https://${p.slug}.${BASE_DOMAIN}` : `${BASE_URL}/s/${p.slug}/`,
    status: active ? p.status : 'suspended', desired: p.desired, suspendedBy: p.adminSuspended ? 'admin' : (!active ? 'billing' : null),
    lastError: p.lastError || null, lastDeployAt: p.lastDeployAt || null, sizeBytes: p.sizeBytes || 0, files: p.files || 0, restarts: p.restarts || 0, createdAt: p.createdAt,
    running: E.isRunning(p.id), uptimeSec: E.startedAt(p.id) ? Math.floor((now() - E.startedAt(p.id)) / 1000) : 0
  };
}
const cmd = v => String(v ?? '').trim().slice(0, 500);
const BRANCH_RE = /^\w[\w./-]{0,99}$/;
function slugify(name) {
  const base = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'project';
  let s = base;
  while (RESERVED.includes(s) || db.projects.some(p => p.slug === s)) s = base + '-' + crypto.randomBytes(2).toString('hex');
  return s;
}
function cleanEnv(list, old = []) {
  if (!Array.isArray(list)) throw bad('Invalid environment variables');
  if (list.length > 100) throw bad('Too many variables (max 100)');
  const prev = new Map(old.map(v => [v.key, v.value])), out = [], seen = new Set();
  for (const v of list) {
    const key = String((v && v.key) || '').trim();
    if (!key) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw bad(`Invalid variable name: ${key}`);
    if (RESERVED_ENV.includes(key.toUpperCase())) throw bad(`${key} is set by the platform`);
    if (seen.has(key)) throw bad(`Duplicate variable: ${key}`);
    seen.add(key);
    let value = v.value;
    if (value === null || value === undefined) value = prev.has(key) ? prev.get(key) : ''; // null = keep the saved value
    value = String(value);
    if (value.length > 4000) throw bad(`${key} is too long`);
    out.push({ key, value });
  }
  return out;
}
function canDeploy(u, p) {
  if (!isActive(u)) throw new HttpError(402, 'Your free trial has ended. Please pay to keep deploying.');
  if (E.usageBytes(u.id) >= E.quotaBytes(u)) throw new HttpError(413, 'Your storage is full. Delete a project or ask the admin for more storage.');
}
const ownProject = req => { const p = db.projects.find(x => x.id === req.params.id && x.userId === req.user.id); if (!p) throw new HttpError(404, 'Project not found'); return p; };

app.get('/api/projects', auth, (req, res) => res.json(db.projects.filter(p => p.userId === req.user.id).map(projectView)));
app.post('/api/projects', auth, (req, res) => {
  const b = req.body || {};
  canDeploy(req.user);
  if (db.projects.filter(p => p.userId === req.user.id).length >= MAX_PROJECTS) throw bad(`Maximum projects: ${MAX_PROJECTS}`);
  let repo = String(b.repo || '').trim();
  const m = String(b.githubUrl || '').trim().match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/);
  if (!repo && m) repo = `${m[1]}/${m[2]}`;
  if (!REPO_RE.test(repo)) throw bad('Choose a repository (owner/name) or paste its GitHub URL');
  const branch = String(b.branch || '').trim();
  if (branch && !BRANCH_RE.test(branch)) throw bad('Invalid branch name');
  const kind = b.kind === 'service' ? 'service' : 'static';
  const name = String(b.name || repo.split('/')[1]).trim().slice(0, 40);
  if (!name) throw bad('Enter a project name');
  const p = {
    id: uid(), userId: req.user.id, name, slug: slugify(b.slug || name), kind, repo, branch, framework: String(b.framework || '').slice(0, 40),
    installCmd: cmd(b.installCmd), buildCmd: cmd(b.buildCmd), startCmd: cmd(b.startCmd), outputDir: cmd(b.outputDir), exposeWeb: kind === 'service' ? b.exposeWeb !== false : false,
    env: cleanEnv(b.env || []), status: 'queued', desired: 'running', createdAt: now()
  };
  if (kind === 'service' && !p.startCmd) throw bad('A start command is required for services');
  db.projects.push(p); save();
  E.enqueueDeploy(p);
  res.json(projectView(p));
});
app.get('/api/projects/:id', auth, (req, res) => res.json(projectView(ownProject(req))));
app.patch('/api/projects/:id', auth, (req, res) => {
  const p = ownProject(req), b = req.body || {};
  if (b.name !== undefined) { const n = String(b.name).trim().slice(0, 40); if (!n) throw bad('Enter a project name'); p.name = n; }
  if (b.branch !== undefined) { const br = String(b.branch).trim(); if (br && !BRANCH_RE.test(br)) throw bad('Invalid branch name'); p.branch = br; }
  for (const k of ['installCmd', 'buildCmd', 'startCmd', 'outputDir']) if (b[k] !== undefined) p[k] = cmd(b[k]);
  if (b.kind !== undefined) p.kind = b.kind === 'service' ? 'service' : 'static';
  if (b.exposeWeb !== undefined) p.exposeWeb = p.kind === 'service' && !!b.exposeWeb;
  if (p.kind === 'service' && !p.startCmd) throw bad('A start command is required for services');
  save(); res.json(projectView(p));
});
app.post('/api/projects/:id/deploy', auth, (req, res) => {
  const p = ownProject(req); canDeploy(req.user, p);
  if (p.adminSuspended) throw new HttpError(403, 'This project was turned off by an admin.');
  if (['queued', 'building'].includes(p.status)) throw new HttpError(409, 'A deployment is already running.');
  p.desired = 'running'; E.enqueueDeploy(p); res.json(projectView(p));
});
app.post('/api/projects/:id/stop', auth, (req, res) => {
  const p = ownProject(req);
  if (p.kind !== 'service') throw bad('Only services can be stopped');
  p.desired = 'stopped'; E.stopService(p.id); E.setStatus(p, 'stopped'); res.json(projectView(p));
});
app.post('/api/projects/:id/start', auth, (req, res) => {
  const p = ownProject(req); canDeploy(req.user, p);
  if (p.kind !== 'service') throw bad('Only services can be started');
  if (p.adminSuspended) throw new HttpError(403, 'This project was turned off by an admin.');
  p.desired = 'running'; save();
  if (!E.isRunning(p.id)) { if (p.status === 'stopped') p.status = 'live'; E.resumeProject(p); }
  res.json(projectView(p));
});
app.delete('/api/projects/:id', auth, async (req, res) => {
  const p = ownProject(req); await E.removeProject(p);
  db.projects = db.projects.filter(x => x.id !== p.id); save(); res.json({ ok: true });
});
app.get('/api/projects/:id/env', auth, (req, res) => res.json({ vars: (ownProject(req).env || []).map(v => ({ key: v.key })) })); // values are never sent back
app.put('/api/projects/:id/env', auth, (req, res) => { const p = ownProject(req); p.env = cleanEnv(req.body.vars, p.env); save(); res.json({ ok: true, count: p.env.length }); });
app.get('/api/projects/:id/logs', auth, (req, res) => { const p = ownProject(req); res.json({ lines: E.getLogs(p), status: projectView(p).status }); });
app.get('/api/projects/:id/logs/stream', auth, (req, res) => { // live tail (Server-Sent Events)
  const p = ownProject(req);
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  const send = o => res.write('data: ' + JSON.stringify(o) + '\n\n');
  send({ lines: E.getLogs(p), status: projectView(p).status });
  const off = E.subscribe(p.id, ev => send(ev.status ? { status: projectView(p).status } : ev));
  const hb = setInterval(() => res.write(': hb\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); off(); });
});

/* ---------- profile & settings ---------- */
app.get('/api/profile', auth, (req, res) => {
  const mine = db.projects.filter(p => p.userId === req.user.id);
  res.json({ ...publicUser(req.user), memberSince: req.user.createdAt, projects: mine.length });
});
app.put('/api/profile', auth, (req, res) => {
  const name = String(req.body.displayName || '').trim().replace(/\s+/g, ' ');
  if (name.length < 1 || name.length > 40) throw bad('Display name must be 1-40 characters');
  req.user.displayName = name; save(); res.json(publicUser(req.user));
});
app.post('/api/settings/password', authLimit, auth, async (req, res) => {
  const cur = String(req.body.currentPassword || ''), next = String(req.body.newPassword || '');
  if (req.user.passHash && !(await bcrypt.compare(cur, req.user.passHash))) throw bad('Current password is incorrect');
  if (next.length < 8) throw bad('New password must be at least 8 characters');
  req.user.passHash = await bcrypt.hash(next, 10); save(); res.json({ ok: true });
});
app.delete('/api/account', authLimit, auth, async (req, res) => {
  const u = req.user, given = String(req.body.password || '');
  if (u.passHash ? !(await bcrypt.compare(given, u.passHash)) : given.toLowerCase() !== u.email) throw bad(u.passHash ? 'Incorrect password' : 'Type your email address to confirm');
  for (const p of db.projects.filter(x => x.userId === u.id)) await E.removeProject(p);
  db.projects = db.projects.filter(p => p.userId !== u.id); db.users = db.users.filter(x => x.id !== u.id); save();
  res.json({ ok: true });
});

/* ---------- billing ---------- */
app.post('/api/billing/pay', auth, async (req, res) => {
  if (!PSK) throw new HttpError(500, 'Paystack is not configured');
  const reference = `mh_${req.user.id}_${Date.now()}`, amount = E.getPrice() * 100;
  db.pending[reference] = { userId: req.user.id, amount, at: now() }; save();
  let j;
  try {
    const r = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: 'Bearer ' + PSK, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: req.user.email, amount, currency: 'KES', reference, callback_url: `${baseOf(req)}/billing/return`, metadata: { userId: req.user.id } }) });
    j = await r.json();
  } catch { throw new HttpError(502, 'Could not reach Paystack'); }
  if (!j.status) throw new HttpError(502, j.message || 'Paystack error');
  res.json({ url: j.data.authorization_url });
});
app.get('/billing/return', async (req, res) => {
  const ref = String(req.query.reference || req.query.trxref || '');
  let ok = false; try { ok = ref && await creditPayment(ref); } catch (e) { console.error(e); }
  res.redirect('/#/billing?paid=' + (ok ? '1' : '0'));
});

/* ---------- admin ---------- */
app.post('/api/admin/login', limiter(10, 15 * 60000), (req, res) => {
  if (!safeEq(String(req.body.password || '').trim(), ADMIN_PASSWORD)) throw new HttpError(401, 'Incorrect password');
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
});
app.get('/api/admin/overview', adminAuth, (req, res) => {
  const users = db.users.map(u => ({ id: u.id, email: u.email, status: userStatus(u), daysLeft: daysLeft(u), blocked: !!u.blocked, github: u.githubLogin || null, createdAt: u.createdAt, projects: db.projects.filter(p => p.userId === u.id).length, usedBytes: E.usageBytes(u.id), quotaBytes: E.quotaBytes(u) }));
  const projects = db.projects.map(p => ({ ...projectView(p), owner: (db.users.find(u => u.id === p.userId) || {}).email }));
  const c = s => users.filter(u => u.status === s).length;
  res.json({
    settings: { price: E.getPrice(), trialDays: E.getTrialDays(), storageGB: E.getStorageGB(), requireVerify: requireVerify() },
    stats: { users: users.length, trial: c('trial'), paid: c('paid'), expired: c('expired'), blocked: c('blocked'), projects: projects.length, live: projects.filter(p => p.status === 'live').length, usedBytes: users.reduce((s, u) => s + u.usedBytes, 0), revenue: db.payments.reduce((s, p) => s + p.amount, 0) },
    users, projects, payments: [...db.payments].reverse().slice(0, 200)
  });
});
app.put('/api/admin/settings', adminAuth, (req, res) => {
  const price = Math.round(Number(req.body.price)), trialDays = Math.round(Number(req.body.trialDays)), storageGB = Number(req.body.storageGB);
  if (!Number.isFinite(price) || price < 10 || price > 100000) throw bad('Price must be between KES 10 and 100000');
  if (!Number.isFinite(trialDays) || trialDays < 0 || trialDays > 90) throw bad('Trial days must be between 0 and 90');
  if (!Number.isFinite(storageGB) || storageGB < 0.1 || storageGB > 100000) throw bad('Storage must be between 0.1 and 100000 GB');
  Object.assign(db.settings, { price, trialDays, storageGB });
  if (req.body.requireVerify !== undefined) db.settings.requireVerify = !!req.body.requireVerify;
  save(); res.json({ price, trialDays, storageGB, requireVerify: requireVerify() });
});
const userById = req => { const u = db.users.find(x => x.id === req.params.id); if (!u) throw new HttpError(404, 'User not found'); return u; };
app.post('/api/admin/users/:id/block', adminAuth, (req, res) => {
  const u = userById(req); u.blocked = !!req.body.blocked; save();
  if (u.blocked) db.projects.filter(p => p.userId === u.id).forEach(p => E.stopService(p.id)); else resumeUser(u.id);
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/verify', adminAuth, (req, res) => { activate(userById(req)); save(); res.json({ ok: true }); });
app.post('/api/admin/users/:id/extend', adminAuth, (req, res) => {
  const u = userById(req), d = Math.min(365, Math.max(1, Number(req.body.days) || 30));
  u.paidUntil = Math.max(now(), u.paidUntil || 0) + d * DAY; save(); resumeUser(u.id); res.json({ ok: true });
});
app.post('/api/admin/users/:id/storage', adminAuth, (req, res) => {
  const u = userById(req), gb = req.body.gb === null || req.body.gb === '' ? null : Number(req.body.gb); // empty = use the default
  if (gb !== null && (!Number.isFinite(gb) || gb < 0.1 || gb > 100000)) throw bad('Storage must be between 0.1 and 100000 GB');
  if (gb === null) delete u.storageGB; else u.storageGB = gb;
  save(); res.json({ ok: true });
});
const anyProject = req => { const p = db.projects.find(x => x.id === req.params.id); if (!p) throw new HttpError(404, 'Project not found'); return p; };
app.post('/api/admin/projects/:id/suspend', adminAuth, (req, res) => { // suspend = turn the site off; resume = turn it on
  const p = anyProject(req); p.adminSuspended = !!req.body.suspended; save();
  if (p.adminSuspended) E.stopService(p.id); else E.resumeProject(p);
  res.json({ ok: true });
});
app.delete('/api/admin/projects/:id', adminAuth, async (req, res) => {
  const p = anyProject(req); await E.removeProject(p); db.projects = db.projects.filter(x => x.id !== p.id); save(); res.json({ ok: true });
});

/* ---------- frontend + errors ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.status(404).send('Not found'));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (res.headersSent) return;
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error('ERROR', req.method, req.path, err && err.message);
  res.status(500).json({ error: 'Server error. Please try again.' });
});
/* ---------- start ---------- */
(async () => {
  try { await init(); } catch (e) { console.error('Could not connect to the database:', e.message); process.exit(1); }
  console.log('Database: ' + (process.env.MONGODB_URI ? 'MongoDB' : 'local JSON file (NOT persistent on Render free - set MONGODB_URI)'));
  console.log('Mail: ' + mailMode + ' | email verification: ' + (requireVerify() ? 'REQUIRED' : 'off') + ' | human check: ' + (TURNSTILE_ON ? 'Turnstile' : 'math') + ' | GitHub OAuth: ' + (GH_ID && GH_SECRET ? 'configured' : 'NOT configured') + ' | static storage: ' + E.storeMode());
  if (ADMIN_ENV) console.log('Admin password: set via ADMIN_PASSWORD'); else console.warn('ADMIN PASSWORD (temporary, changes on every restart): ' + ADMIN_PASSWORD + '  <- set ADMIN_PASSWORD to choose your own');
  const server = app.listen(PORT, () => { console.log('MtaaniHost v2 listening on ' + PORT); E.boot(); });
  setInterval(E.enforce, 60000).unref();
  const bye = async () => { server.close(); await close(); process.exit(0); };
  process.on('SIGTERM', bye); process.on('SIGINT', bye);
})();
