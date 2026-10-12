require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AdmZip = require('adm-zip');
const nodemailer = require('nodemailer');
const { execFile } = require('child_process');
const { db, save, DATA } = require('./db');
const runner = require('./runner');
const cf = require('./cf');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('Set JWT_SECRET'); process.exit(1); }

const ADMIN_ENV = (process.env.ADMIN_PASSWORD || '').trim();
const ADMIN_PASSWORD = ADMIN_ENV || crypto.randomBytes(9).toString('base64url');
const REQUIRE_EMAIL_VERIFY = process.env.REQUIRE_EMAIL_VERIFY === '1';
const TURNSTILE_SECRET = (process.env.TURNSTILE_SECRET || '').trim();
const TURNSTILE_SITE_KEY = (process.env.TURNSTILE_SITE_KEY || '').trim();
const TURNSTILE_ON =!!(TURNSTILE_SECRET && TURNSTILE_SITE_KEY);
const PSK = process.env.PAYSTACK_SECRET_KEY;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').toLowerCase();
const GITHUB_CLIENT_ID = (process.env.GITHUB_CLIENT_ID || '').trim();
const GITHUB_CLIENT_SECRET = (process.env.GITHUB_CLIENT_SECRET || '').trim();
const GITHUB_CALLBACK_URL = (process.env.GITHUB_CALLBACK_URL || `${BASE_URL}/auth/github/callback`).trim();

const DAY = 86400000, MAX_PROJECTS = 5;
const getPrice = () => Number(db.settings.price) || 130;
const getTrialDays = () => db.settings.trialDays === undefined? 7 : Number(db.settings.trialDays);
const RESERVED = ['www', 'app', 'api', 'admin', 'p', 'mail', 'static'];

const app = express();
app.set('trust proxy', 1);

['get', 'post', 'put', 'delete'].forEach(m => {
  const orig = app[m].bind(app);
  app[m] = (p,...handlers) => {
    if (!handlers.length) return orig(p);
    return orig(p,...handlers.map(h => (typeof h === 'function' && h.length < 4)
     ? (req, res, next) => { try { const r = h(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); } } : h));
  };
});

const ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ORIGINS.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});

const now = () => Date.now();
const uid = () => crypto.randomBytes(8).toString('hex');
const expiry = u => Math.max(u.trialEndsAt || 0, u.paidUntil || 0);
const isActive = u =>!u.blocked && u.verified && now() < expiry(u);
const daysLeft = u => Math.max(0, Math.ceil((expiry(u) - now()) / DAY));
const userStatus = u => u.blocked? 'blocked' :!u.verified? 'unverified' : (u.paidUntil && now() < u.paidUntil)? 'paid' : now() < (u.trialEndsAt || 0)? 'trial' : 'expired';
const publicUser = u => ({ id: u.id, email: u.email, displayName: u.displayName || u.email.split('@')[0], status: userStatus(u), active: isActive(u), daysLeft: daysLeft(u), trialEndsAt: u.trialEndsAt, paidUntil: u.paidUntil || 0, price: getPrice() });
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

const hits = new Map();
function limiter(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path; const h = hits.get(k) || { c: 0, r: now() + windowMs };
    if (now() > h.r) { h.c = 0; h.r = now() + windowMs; }
    if (++h.c > max) return res.status(429).json({ error: 'Too many requests' });
    hits.set(k, h); next();
  };
}
setInterval(() => { for (const [k, h] of hits) if (now() > h.r) hits.delete(k); }, 600000);

const MAIL_USER = (process.env.GMAIL_USER || process.env.SMTP_USER || '').trim();
const MAIL_PASS = (process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASS || '').replace(/\s+/g, '');
const MAIL_FROM = (process.env.MAIL_FROM || MAIL_USER).trim();
const BREVO_KEY = (process.env.BREVO_API_KEY || '').trim();
const DEV_MODE = process.env.DEV_MODE === '1';
const smtp = MAIL_USER && MAIL_PASS? nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: MAIL_USER, pass: MAIL_PASS } }) : null;
const mailMode = BREVO_KEY? 'brevo' : smtp? 'smtp' : 'none';

async function sendEmail(to, subject, html) {
  if (BREVO_KEY) {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': BREVO_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ sender: { name: 'MtaaniHost', email: MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html }) });
    if (!r.ok) throw new Error('Brevo error ' + r.status);
    return;
  }
  if (smtp) { await smtp.sendMail({ from: `"MtaaniHost" <${MAIL_FROM}>`, to, subject, html }); return; }
  throw new Error('Email not configured');
}
async function sendCode(email, code) {
  if (mailMode === 'none' && DEV_MODE) { console.log(`[DEV] code for ${email}: ${code}`); return; }
  await sendEmail(email, `Your MtaaniHost code: ${code}`, `<p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p>`);
}

// SINGLE AUTH DEFINITION - NO DUPLICATE
function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const d = jwt.verify(t, JWT_SECRET);
    if (d.role!== 'user') throw new Error();
    const u = db.users.find(x => x.id === d.id);
    if (!u) throw new Error();
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
}
function adminAuth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    if (d.role!== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Admin only' }); }
}
const authLimit = limiter(20, 15 * 60000);
const usedHuman = new Map();
const humanSig = text => crypto.createHmac('sha256', JWT_SECRET).update(text).digest('base64url');

async function creditPayment(reference) {
  if (db.payments.find(p => p.reference === reference)) return true;
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), { headers: { Authorization: 'Bearer ' + PSK } });
  const j = await r.json();
  if (!j.status ||!j.data || j.data.status!== 'success') return false;
  const d = j.data, userId = d.metadata && d.metadata.userId;
  const user = db.users.find(u => u.id === userId);
  if (!user || d.currency!== 'KES') return false;
  if (db.payments.find(p => p.reference === reference)) return true;
  user.paidUntil = Math.max(now(), user.paidUntil || 0) + 30 * DAY;
  db.payments.push({ reference, userId, email: user.email, amount: d.amount / 100, currency: d.currency, channel: d.channel, at: now() });
  delete db.pending[reference]; save(); resumeUserBots(user.id); syncSites();
  return true;
}
function resumeUserBots(userId) {
  const o = db.users.find(x => x.id === userId);
  if (!o ||!isActive(o)) return;
  db.projects.filter(p => p.userId === userId && p.type === 'bot' && p.desired === 'running' &&!p.adminSuspended).forEach(p => runner.start(p));
}

app.post('/api/paystack/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const sig = crypto.createHmac('sha512', PSK || '').update(req.body).digest('hex');
    if (!safeEq(sig, req.headers['x-paystack-signature'] || '')) return res.sendStatus(401);
    const ev = JSON.parse(req.body.toString());
    if (ev.event === 'charge.success') await creditPayment(ev.data.reference);
    res.sendStatus(200);
  } catch (e) { res.sendStatus(500); }
});

// GITHUB
app.get('/auth/github', (req, res) => {
  if (!GITHUB_CLIENT_ID) return res.status(500).send('GitHub not configured');
  const state = crypto.randomBytes(8).toString('hex');
  const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(GITHUB_CALLBACK_URL)}&scope=user:email%20repo&state=${state}`;
  res.redirect(url);
});
app.get('/auth/github/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('No code');
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET, code, redirect_uri: GITHUB_CALLBACK_URL }) });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).send('GitHub auth failed: ' + JSON.stringify(tokenData));
    const accessToken = tokenData.access_token;
    const userRes = await fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${accessToken}` } });
    const ghUser = await userRes.json();
    const emailRes = await fetch('https://api.github.com/user/emails', { headers: { Authorization: `Bearer ${accessToken}` } });
    const emails = await emailRes.json();
    const primary = Array.isArray(emails)? (emails.find(e => e.primary && e.verified) || emails[0]) : null;
    const email = (primary?.email || ghUser.email || '').toLowerCase().trim();
    if (!email) return res.status(400).send('Could not get email from GitHub');
    let u = db.users.find(x => x.email === email);
    if (!u) { u = { id: uid(), email, verified: true, displayName: ghUser.name || ghUser.login, trialEndsAt: now() + getTrialDays() * DAY, paidUntil: 0, blocked: false, createdAt: now(), passHash: await bcrypt.hash(crypto.randomBytes(12).toString('hex'), 10) }; db.users.push(u); }
    else { u.verified = true; }
    u.githubToken = accessToken; u.githubLogin = ghUser.login; save();
    const jwtToken = jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
    res.redirect(`/#/auth?token=${jwtToken}`);
  } catch (e) { res.status(500).send('GitHub error: ' + e.message); }
});
app.get('/api/github/repos', auth, async (req, res) => {
  try {
    if (!req.user.githubToken) return res.status(400).json({ error: 'Login with GitHub first' });
    const r = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated', { headers: { Authorization: `Bearer ${req.user.githubToken}` } });
    const j = await r.json();
    res.json(j.map(repo => ({ name: repo.name, full_name: repo.full_name, url: repo.html_url, private: repo.private, branch: repo.default_branch })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

function blockedPage(res, name) {
  res.status(402).send(`<body style="background:#000;color:#fff;display:grid;place-items:center;height:100vh"><h1>${name} suspended - pay to restore</h1></body>`);
}
function serveSite(slug, req, res, next) {
  const p = db.projects.find(x => x.slug === slug && x.type === 'website');
  if (!p) return next();
  const owner = db.users.find(u => u.id === p.userId);
  if (!owner ||!isActive(owner) || p.adminSuspended) return blockedPage(res, p.name);
  express.static(p.dir, { index: 'index.html', extensions: ['html'] })(req, res, () => res.status(404).send('Not found'));
}
app.use((req, res, next) => {
  if (!BASE_DOMAIN) return next();
  const host = (req.hostname || '').toLowerCase();
  if (host.endsWith('.' + BASE_DOMAIN)) {
    const slug = host.slice(0, -(BASE_DOMAIN.length + 1));
    if (!slug.includes('.') &&!RESERVED.includes(slug)) return serveSite(slug, req, res, () => res.status(404).send('Not found'));
  }
  next();
});
app.use('/p/:slug', (req, res, next) => serveSite(req.params.slug, req, res, next));
app.use(express.json({ limit: '100kb' }));
app.get('/api/health', (req, res) => res.json({ ok: true, github:!!GITHUB_CLIENT_ID, mail: mailMode }));
app.get('/api/config', (req, res) => res.json({ price: getPrice(), trialDays: getTrialDays(), human: TURNSTILE_ON? 'turnstile' : 'math', turnstileSiteKey: TURNSTILE_ON? TURNSTILE_SITE_KEY : '' }));

app.get('/api/human', limiter(60, 15 * 60000), (req, res) => {
  if (TURNSTILE_ON) return res.json({ type: 'turnstile' });
  const a = crypto.randomInt(2, 10), b = crypto.randomInt(2, 10), n = uid(), exp = now() + 5 * 60000;
  res.json({ type: 'math', question: `${a} + ${b}`, token: `${n}.${exp}.${humanSig(`${n}.${exp}.${a + b}`)}` });
});
async function verifyHuman(req) {
  try {
    if (TURNSTILE_ON) {
      const t = String(req.body.cfToken || ''); if (!t) return false;
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: t }) });
      const j = await r.json(); return!!j.success;
    }
    const [n, exp, sig] = String(req.body.humanToken || '').split('.');
    const ans = String(req.body.humanAnswer || '').trim();
    if (!n ||!exp ||!sig ||!ans || now() > Number(exp) || usedHuman.has(n)) return false;
    usedHuman.set(n, Number(exp));
    return safeEq(sig, humanSig(`${n}.${exp}.${ans}`));
  } catch { return false; }
}

app.post('/api/auth/signup', authLimit, async (req, res) => {
  if (!(await verifyHuman(req))) return res.status(400).json({ error: 'Human check failed' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });
  let u = db.users.find(x => x.email === email);
  if (u && u.verified) return res.status(409).json({ error: 'Already exists' });
  const passHash = await bcrypt.hash(password, 10);
  if (!u) { u = { id: uid(), email, verified: false, trialEndsAt: 0, paidUntil: 0, blocked: false, createdAt: now() }; db.users.push(u); }
  Object.assign(u, { passHash, code: null });
  u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; save();
  res.json({ ok: true, verified: true, token: jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' }), user: publicUser(u) });
});
app.post('/api/auth/login', authLimit, async (req, res) => {
  if (!(await verifyHuman(req))) return res.status(400).json({ error: 'Human check failed' });
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u ||!(await bcrypt.compare(String(req.body.password || ''), u.passHash))) return res.status(401).json({ error: 'Incorrect email or password' });
  if (u.blocked) return res.status(403).json({ error: 'Blocked' });
  if (!u.verified) { u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; save(); }
  res.json({ token: jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' }), user: publicUser(u) });
});
app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));

// projects helpers
function projectView(p) {
  const owner = db.users.find(u => u.id === p.userId);
  const active = owner && isActive(owner) &&!p.adminSuspended;
  let status =!active? 'suspended' : p.type === 'website'? 'live' : runner.isRunning(p.id)? 'running' : (p.desired === 'running'? 'starting' : 'stopped');
  let url = p.type === 'website'? (BASE_DOMAIN? `https://${p.slug}.${BASE_DOMAIN}` : `${BASE_URL}/p/${p.slug}/`) : null;
  return { id: p.id, name: p.name, type: p.type, botType: p.botType, slug: p.slug, url, status, createdAt: p.createdAt, stats: p.type === 'bot'? runner.stats(p.id) : {} };
}
function slugify(name) { let base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 30) || 'project'; let s = base; while (db.projects.some(p => p.slug === s)) s = base + '-' + crypto.randomBytes(2).toString('hex'); return s; }
function extractZip(zipPath, dest) { const zip = new AdmZip(zipPath); fs.mkdirSync(dest, { recursive: true }); zip.extractAllTo(dest, true); }
const upload = multer({ dest: path.join(os.tmpdir(), 'mh-uploads'), limits: { fileSize: 50 * 1024 * 1024 } });
const rm = p => { try { fs.rmSync(p, { recursive: true, force: true }); } catch {} };
const GH_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?\/?$/;
const gitClone = (url, dest, branch) => new Promise((ok, no) => { const args = ['clone', '--depth', '1']; if (branch) args.push('--branch', branch); execFile('git', [...args, url, dest], { timeout: 120000 }, e => e? no(new Error('Git clone failed')) : ok()); });
function checkCanDeploy(req, res) { if (!isActive(req.user)) { res.status(402).json({ error: 'Trial ended, pay' }); return false; } return true; }
function cleanName(n) { return String(n || '').trim().slice(0, 40); }
function parseEnv(text) { const env = {}; String(text || '').split(/\r?\n/).forEach(l => { const m = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/); if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, ''); }); return env; }

app.get('/api/projects', auth, (req, res) => res.json(db.projects.filter(p => p.userId === req.user.id).map(projectView)));
app.post('/api/projects/website', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file?.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name); const gh = String(req.body.githubUrl || '').trim();
    if (!name) return res.status(400).json({ error: 'Enter name' });
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try { if (tmp) extractZip(tmp, dir); else await gitClone(gh, dir, String(req.body.branch || '').trim()); } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'website', name, slug: slugify(name), dir, createdAt: now() };
    db.projects.push(p); save(); res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});
app.post('/api/projects/bot', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file?.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name); const botType = String(req.body.botType || ''); const gh = String(req.body.githubUrl || '').trim();
    const env = parseEnv(req.body.envVars);
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try { if (tmp) extractZip(tmp, dir); else await gitClone(gh, dir, String(req.body.branch || '').trim()); if (!fs.existsSync(path.join(dir, 'package.json'))) throw new Error('package.json not found'); } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'bot', botType, name, slug: slugify(name), dir, env, github: gh || null, desired: 'running', createdAt: now() };
    db.projects.push(p); save(); runner.start(p); res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});
function ownProject(req, res) { const p = db.projects.find(x => x.id === req.params.id && x.userId === req.user.id); if (!p) res.status(404).json({ error: 'Not found' }); return p; }
app.get('/api/projects/:id/env', auth, (req, res) => { const p = ownProject(req, res); if (p) res.json({ keys: Object.keys(p.env || {}) }); });
app.put('/api/projects/:id/env', auth, async (req, res) => { const p = ownProject(req, res); if (!p) return; p.env = parseEnv(req.body.envVars); save(); runner.stop(p.id); setTimeout(() => runner.start(p), 1000); res.json({ ok: true }); });
app.get('/api/projects/:id/logs', auth, (req, res) => { const p = ownProject(req, res); if (p) res.json({ logs: runner.getLogs(p.id) }); });
app.get('/api/projects/:id/logs/stream', auth, (req, res) => {
  const p = ownProject(req, res); if (!p) return;
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
  res.write(`data: ${JSON.stringify({ type: 'history', logs: runner.getLogs(p.id) })}\n\n`);
  const onLog = (line) => res.write(`data: ${JSON.stringify({ type: 'log', line })}\n\n`);
  if (runner.logEmitter) { runner.logEmitter.on('log:'+p.id, onLog); req.on('close', () => runner.logEmitter.off('log:'+p.id, onLog)); }
});
app.post('/api/projects/:id/:action(start|stop|restart)', auth, async (req, res) => {
  const p = ownProject(req, res); if (!p) return;
  const a = req.params.action;
  if (a === 'stop') { p.desired = 'stopped'; runner.stop(p.id); }
  else { p.desired = 'running'; if (a === 'restart') runner.stop(p.id); setTimeout(() => runner.start(p), 500); else runner.start(p); }
  save(); res.json(projectView(p));
});
function deleteProject(p) { p.desired = 'stopped'; runner.stop(p.id); setTimeout(() => rm(p.dir), 2000); db.projects = db.projects.filter(x => x.id!== p.id); save(); }
app.delete('/api/projects/:id', auth, (req, res) => { const p = ownProject(req, res); if (p) { deleteProject(p); res.json({ ok: true }); } });

app.get('/api/profile', auth, (req, res) => res.json(publicUser(req.user)));
app.put('/api/profile', auth, (req, res) => { req.user.displayName = String(req.body.displayName || '').trim(); save(); res.json(publicUser(req.user)); });
app.post('/api/settings/password', authLimit, auth, async (req, res) => { req.user.passHash = await bcrypt.hash(String(req.body.newPassword || ''), 10); save(); res.json({ ok: true }); });
app.delete('/api/account', auth, async (req, res) => { db.projects.filter(p => p.userId === req.user.id).forEach(deleteProject); db.users = db.users.filter(u => u.id!== req.user.id); save(); res.json({ ok: true }); });

app.get('/api/billing', auth, (req, res) => res.json(publicUser(req.user)));
app.post('/api/billing/pay', auth, async (req, res) => {
  const reference = `mh_${req.user.id}_${Date.now()}`;
  db.pending[reference] = { userId: req.user.id, amount: getPrice() * 100, at: now() }; save();
  const r = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: 'Bearer ' + PSK, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: req.user.email, amount: getPrice() * 100, currency: 'KES', reference, callback_url: `${BASE_URL}/billing/return`, metadata: { userId: req.user.id } }) });
  const j = await r.json(); if (!j.status) return res.status(502).json({ error: j.message }); res.json({ url: j.data.authorization_url });
});
app.get('/billing/return', async (req, res) => { const ref = String(req.query.reference || ''); let ok = false; try { ok = ref && await creditPayment(ref); } catch {} res.redirect('/#/billing?paid=' + (ok? '1' : '0')); });

app.post('/api/admin/login', (req, res) => { if (req.body.password!== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong' }); res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) }); });
app.get('/api/admin/overview', adminAuth, (req, res) => { res.json({ stats: { users: db.users.length, projects: db.projects.length }, users: db.users, projects: db.projects, payments: db.payments }); });

const cfBusy = new Set();
async function syncSites() {}
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.status(404).send('Not found'));
app.listen(PORT, () => {
  console.log('MtaaniHost running on ' + PORT + ' GitHub:' + (GITHUB_CLIENT_ID? 'ON' : 'OFF'));
  db.projects.filter(p => p.type === 'bot' && p.desired === 'running').forEach(p => { const o = db.users.find(u => u.id === p.userId); if (o && isActive(o)) runner.start(p); });
});
