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
if (!JWT_SECRET) { console.error('Set JWT_SECRET in the environment'); process.exit(1); }
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();
const SKIP_EMAIL_VERIFY = process.env.SKIP_EMAIL_VERIFY === '1'; // TEMPORARY: lets people sign up without an email code until email sending works
const PSK = process.env.PAYSTACK_SECRET_KEY;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').toLowerCase();
const DAY = 86400000, MAX_PROJECTS = 5;
// Pricing lives in the database so the admin can change it from the admin panel.
const getPrice = () => Number(db.settings.price) || 130;                                  // KES per month
const getTrialDays = () => db.settings.trialDays === undefined ? 7 : Number(db.settings.trialDays); // free trial length
const RESERVED = ['www', 'app', 'api', 'admin', 'p', 'mail', 'static'];

const app = express();
app.set('trust proxy', 1);

// Express 4 does not catch errors thrown inside async handlers (the request just hangs).
// Wrap every route handler so such errors reach the error handler at the bottom and become a JSON error.
['get', 'post', 'put', 'delete'].forEach(m => {
  const orig = app[m].bind(app);
  app[m] = (p, ...handlers) => {
    if (!handlers.length) return orig(p); // app.get('setting')
    return orig(p, ...handlers.map(h => (typeof h === 'function' && h.length < 4)
      ? (req, res, next) => { try { const r = h(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); } }
      : h));
  };
});

// CORS: only needed if the frontend is hosted elsewhere (e.g. GitHub Pages).
// Set CORS_ORIGINS=https://mtaanitech.github.io (comma separated, no trailing slash, no path)
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

/* ---------- helpers ---------- */
const now = () => Date.now();
const uid = () => crypto.randomBytes(8).toString('hex');
const expiry = u => Math.max(u.trialEndsAt || 0, u.paidUntil || 0);
const isActive = u => !u.blocked && u.verified && now() < expiry(u);
const daysLeft = u => Math.max(0, Math.ceil((expiry(u) - now()) / DAY));
const userStatus = u => u.blocked ? 'blocked' : !u.verified ? 'unverified' : (u.paidUntil && now() < u.paidUntil) ? 'paid' : now() < (u.trialEndsAt || 0) ? 'trial' : 'expired';
const publicUser = u => ({ id: u.id, email: u.email, displayName: u.displayName || u.email.split('@')[0], status: userStatus(u), active: isActive(u), daysLeft: daysLeft(u), trialEndsAt: u.trialEndsAt, paidUntil: u.paidUntil || 0, price: getPrice() });
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

const hits = new Map();
function limiter(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path; const h = hits.get(k) || { c: 0, r: now() + windowMs };
    if (now() > h.r) { h.c = 0; h.r = now() + windowMs; }
    if (++h.c > max) return res.status(429).json({ error: 'Too many requests, please wait a moment.' });
    hits.set(k, h); next();
  };
}
setInterval(() => { for (const [k, h] of hits) if (now() > h.r) hits.delete(k); }, 600000);

/* ---------- email ---------- */
// Render FREE web services block outbound SMTP (ports 25/465/587) since Sept 2025,
// so Gmail SMTP cannot work there. Two options:
//   1) BREVO_API_KEY (HTTPS API, works on free Render)  -> also set MAIL_FROM (a sender verified in Brevo)
//   2) Gmail SMTP (GMAIL_USER + GMAIL_APP_PASSWORD, or SMTP_USER + SMTP_PASS) -> needs a PAID Render instance
const MAIL_USER = (process.env.GMAIL_USER || process.env.SMTP_USER || '').trim();
const MAIL_PASS = (process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASS || '').replace(/\s+/g, ''); // app passwords are shown with spaces
const MAIL_FROM = (process.env.MAIL_FROM || MAIL_USER).trim();
const BREVO_KEY = (process.env.BREVO_API_KEY || '').trim();
const DEV_MODE = process.env.DEV_MODE === '1';
const smtp = MAIL_USER && MAIL_PASS ? nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: MAIL_USER, pass: MAIL_PASS },
  connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 // fail fast instead of hanging
}) : null;
const mailMode = BREVO_KEY ? 'brevo' : smtp ? 'smtp' : 'none';

async function sendEmail(to, subject, html) {
  if (BREVO_KEY) {
    if (!MAIL_FROM) throw new Error('MAIL_FROM is not set');
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': BREVO_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ sender: { name: 'MtaaniHost', email: MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html })
    });
    if (!r.ok) throw new Error('Brevo error ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return;
  }
  if (smtp) { await smtp.sendMail({ from: `"MtaaniHost" <${MAIL_FROM}>`, to, subject, html }); return; }
  throw new Error('Email is not configured (set BREVO_API_KEY or GMAIL_USER + GMAIL_APP_PASSWORD)');
}
async function sendCode(email, code) {
  if (mailMode === 'none' && DEV_MODE) { console.log(`[DEV] Verification code for ${email}: ${code}`); return; }
  await sendEmail(email, `Your MtaaniHost code: ${code}`,
    `<div style="font-family:sans-serif"><h2>Welcome to MtaaniHost</h2><p>Your verification code:</p><p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p><p>It expires in 15 minutes.</p></div>`);
}
// startup diagnostics (visible in the Render logs)
if (mailMode === 'brevo') console.log('Mail: using Brevo HTTPS API, sender ' + MAIL_FROM);
else if (mailMode === 'smtp') {
  console.log('Mail: using Gmail SMTP as ' + MAIL_USER);
  smtp.verify().then(() => console.log('Mail: SMTP login OK'))
    .catch(e => console.error('Mail: SMTP check FAILED (' + (e.code || 'error') + '): ' + e.message + ' -- on Render FREE, SMTP ports are blocked: use BREVO_API_KEY or a paid instance. For Gmail you also need 2-Step Verification + an App Password.'));
} else console.warn('Mail: NOT configured - verification emails cannot be sent');
console.log('Admin login: ' + (ADMIN_PASSWORD ? 'ADMIN_PASSWORD is set' : 'ADMIN_PASSWORD is NOT set - admin cannot log in'));
if (SKIP_EMAIL_VERIFY) console.warn('Email verification is SKIPPED (SKIP_EMAIL_VERIFY=1). Remove it once email sending works.');
if (process.env.RENDER && !process.env.DATA_DIR) console.warn('WARNING: DATA_DIR is not set. Without a persistent disk, users and projects are lost on every restart/redeploy.');

/* ---------- billing: Paystack ---------- */
async function creditPayment(reference) {
  if (db.payments.find(p => p.reference === reference)) return true;
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), { headers: { Authorization: 'Bearer ' + PSK } });
  const j = await r.json();
  if (!j.status || !j.data || j.data.status !== 'success') return false;
  const d = j.data, userId = d.metadata && d.metadata.userId;
  const user = db.users.find(u => u.id === userId);
  const expected = (db.pending[reference] || {}).amount || getPrice() * 100; // price at the time the payment was started
  if (!user || d.currency !== 'KES' || d.amount < expected) return false;
  if (db.payments.find(p => p.reference === reference)) return true;
  user.paidUntil = Math.max(now(), user.paidUntil || 0) + 30 * DAY;
  db.payments.push({ reference, userId, email: user.email, amount: d.amount / 100, currency: d.currency, channel: d.channel, at: now() });
  delete db.pending[reference];
  save();
  resumeUserBots(user.id);
  syncSites();
  return true;
}
function resumeUserBots(userId) {
  const o = db.users.find(x => x.id === userId);
  if (!o || !isActive(o)) return;
  db.projects.filter(p => p.userId === userId && p.type === 'bot' && p.desired === 'running' && !p.adminSuspended).forEach(p => runner.start(p));
}

// Paystack webhook (needs the raw body for the signature) - must be registered before express.json()
app.post('/api/paystack/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const sig = crypto.createHmac('sha512', PSK || '').update(req.body).digest('hex');
    if (!safeEq(sig, req.headers['x-paystack-signature'] || '')) return res.sendStatus(401);
    const ev = JSON.parse(req.body.toString());
    if (ev.event === 'charge.success') await creditPayment(ev.data.reference);
    res.sendStatus(200);
  } catch (e) { console.error('webhook', e); res.sendStatus(500); }
});

/* ---------- hosting: static sites (local fallback) ---------- */
function blockedPage(res, name) {
  res.status(402).send(`<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;background:#000;color:#fff;display:grid;place-items:center;height:100vh;margin:0;text-align:center"><div><h1>This site is suspended</h1><p style="color:#aaa">The owner of <b>${String(name).replace(/[<>&"]/g, '')}</b> needs to pay (or an admin suspended it).</p><a style="color:#4ade80" href="${BASE_URL}">MtaaniHost</a></div>`);
}
function serveSite(slug, req, res, next) {
  const p = db.projects.find(x => x.slug === slug && x.type === 'website');
  if (!p) return next();
  const owner = db.users.find(u => u.id === p.userId);
  if (!owner || !isActive(owner) || p.adminSuspended) return blockedPage(res, p.name);
  express.static(p.dir, { index: 'index.html', extensions: ['html'], dotfiles: 'ignore' })(req, res, () => {
    const nf = path.join(p.dir, '404.html');
    if (fs.existsSync(nf)) return res.status(404).sendFile(nf);
    res.status(404).send('Not found');
  });
}
// subdomain hosting: name.BASE_DOMAIN
app.use((req, res, next) => {
  if (!BASE_DOMAIN) return next();
  const host = (req.hostname || '').toLowerCase();
  if (host.endsWith('.' + BASE_DOMAIN)) {
    const slug = host.slice(0, -(BASE_DOMAIN.length + 1));
    if (!slug.includes('.') && !RESERVED.includes(slug)) return serveSite(slug, req, res, () => res.status(404).send('Project not found'));
  }
  next();
});
// path hosting: /p/name
app.use('/p/:slug', (req, res, next) => serveSite(req.params.slug, req, res, next));

app.use(express.json({ limit: '100kb' }));

app.get('/api/health', (req, res) => res.json({ ok: true, mail: mailMode, skipVerify: SKIP_EMAIL_VERIFY, adminConfigured: !!ADMIN_PASSWORD, persistent: !!process.env.DATA_DIR, onRender: !!process.env.RENDER, cf: cf.enabled }));

app.get('/api/config', (req, res) => res.json({ price: getPrice(), trialDays: getTrialDays(), currency: 'KES' })); // public: used by the landing page

/* ---------- auth ---------- */
function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const d = jwt.verify(t, JWT_SECRET);
    if (d.role !== 'user') throw new Error();
    const u = db.users.find(x => x.id === d.id);
    if (!u) throw new Error();
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
}
function adminAuth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    if (d.role !== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Admin only' }); }
}
const authLimit = limiter(20, 15 * 60000);

app.post('/api/auth/signup', authLimit, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  let u = db.users.find(x => x.email === email);
  if (u && u.verified) return res.status(409).json({ error: 'This email already has an account. Please log in.' });
  const code = String(crypto.randomInt(100000, 1000000));
  const passHash = await bcrypt.hash(password, 10);
  if (!u) { u = { id: uid(), email, verified: false, trialEndsAt: 0, paidUntil: 0, blocked: false, createdAt: now() }; db.users.push(u); }
  Object.assign(u, { passHash, code, codeExp: now() + 15 * 60000, codeTries: 0 });
  if (SKIP_EMAIL_VERIFY) { // no email check: verify right away and start the trial
    u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; u.code = null; save();
    return res.json({ ok: true, verified: true });
  }
  save();
  try { await sendCode(email, code); } catch (e) { console.error('mail', e.message); return res.status(500).json({ error: 'Could not send the verification email. Please try again later.' }); }
  res.json({ ok: true });
});
app.post('/api/auth/resend', authLimit, async (req, res) => {
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || u.verified) return res.json({ ok: true });
  u.code = String(crypto.randomInt(100000, 1000000)); u.codeExp = now() + 15 * 60000; u.codeTries = 0; save();
  try { await sendCode(u.email, u.code); } catch { return res.status(500).json({ error: 'Could not send the email' }); }
  res.json({ ok: true });
});
app.post('/api/auth/verify', authLimit, (req, res) => {
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || !u.code) return res.status(400).json({ error: 'Invalid code' });
  if (now() > u.codeExp || u.codeTries >= 5) return res.status(400).json({ error: 'Code expired. Please request a new one.' });
  u.codeTries++;
  if (!safeEq(u.code, String(req.body.code || '').trim())) { save(); return res.status(400).json({ error: 'Invalid code' }); }
  if (!u.verified) { u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; }
  u.code = null; save();
  res.json({ ok: true });
});
app.post('/api/auth/login', authLimit, async (req, res) => {
  const u = db.users.find(x => x.email === String(req.body.email || '').trim().toLowerCase());
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.passHash))) return res.status(401).json({ error: 'Incorrect email or password' });
  if (!u.verified && SKIP_EMAIL_VERIFY) { u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; u.code = null; save(); }
  if (!u.verified) return res.status(403).json({ error: 'Please verify your email first', needVerify: true });
  if (u.blocked) return res.status(403).json({ error: 'Your account has been blocked. Please contact the admin.' });
  res.json({ token: jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' }), user: publicUser(u) });
});
app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));

/* ---------- projects ---------- */
function projectView(p) {
  const owner = db.users.find(u => u.id === p.userId);
  const active = owner && isActive(owner) && !p.adminSuspended;
  let status;
  if (!active) status = 'suspended';
  else if (p.type === 'website') status = 'live';
  else status = runner.isRunning(p.id) ? 'running' : (p.desired === 'running' ? 'starting' : 'stopped');
  let url = null;
  if (p.type === 'website') url = BASE_DOMAIN ? `https://${p.slug}.${BASE_DOMAIN}` : `${BASE_URL}/p/${p.slug}/`;
  const stats = p.type === 'bot' ? runner.stats(p.id) : { files: (p.stats || {}).files || 0, bytes: (p.stats || {}).bytes || 0, deployedAt: p.createdAt };
  return { id: p.id, name: p.name, type: p.type, botType: p.botType, slug: p.slug, url, status, createdAt: p.createdAt, github: p.github || null, suspendedBy: p.adminSuspended ? 'admin' : (!active ? 'billing' : null), stats };
}
function slugify(name) {
  let base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'project';
  let s = base;
  while (RESERVED.includes(s) || db.projects.some(p => p.slug === s)) s = base + '-' + crypto.randomBytes(2).toString('hex');
  return s;
}
function extractZip(zipPath, dest) {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  let total = 0;
  for (const e of entries) total += e.header.size;
  if (total > 300 * 1024 * 1024) throw new Error('ZIP is too large when extracted (max 300MB)');
  fs.mkdirSync(dest, { recursive: true });
  for (const e of entries) {
    if (e.entryName.startsWith('__MACOSX') || e.entryName.includes('..')) continue;
    const target = path.resolve(dest, e.entryName);
    if (!target.startsWith(path.resolve(dest) + path.sep)) continue; // zip-slip protection
    if (e.isDirectory) fs.mkdirSync(target, { recursive: true });
    else { fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, e.getData()); }
  }
  flatten(dest);
}
function flatten(dir) { // if the zip holds a single folder, lift its contents up
  const items = fs.readdirSync(dir).filter(n => n !== '__MACOSX');
  if (items.length === 1 && fs.statSync(path.join(dir, items[0])).isDirectory()) {
    const inner = path.join(dir, items[0]);
    for (const n of fs.readdirSync(inner)) fs.renameSync(path.join(inner, n), path.join(dir, n));
    fs.rmdirSync(inner);
  }
}
const upload = multer({ dest: path.join(os.tmpdir(), 'mh-uploads'), limits: { fileSize: 50 * 1024 * 1024 } });
const rm = p => { try { fs.rmSync(p, { recursive: true, force: true }); } catch {} };
const GH_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?\/?$/;
const gitClone = (url, dest, branch) => new Promise((ok, no) => {
  const args = ['clone', '--depth', '1'];
  if (branch && /^\w[\w./-]{0,59}$/.test(branch)) args.push('--branch', branch);
  execFile('git', [...args, url, dest], { timeout: 120000 }, e => e ? no(new Error('Git clone failed. Make sure the repository is public and the branch exists.')) : ok());
});

function checkCanDeploy(req, res) {
  if (!isActive(req.user)) { res.status(402).json({ error: 'Your trial has ended. Please pay to keep deploying.' }); return false; }
  if (db.projects.filter(p => p.userId === req.user.id).length >= MAX_PROJECTS) { res.status(400).json({ error: `Maximum projects: ${MAX_PROJECTS}` }); return false; }
  return true;
}
function cleanName(n) { return String(n || '').trim().slice(0, 40); }
function parseEnv(text) {
  const env = {};
  String(text || '').slice(0, 5000).split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
  return env;
}

app.get('/api/projects', auth, (req, res) => res.json(db.projects.filter(p => p.userId === req.user.id).map(projectView)));

app.post('/api/projects/website', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file && req.file.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name);
    const gh = String(req.body.githubUrl || '').trim();
    if (!name) return res.status(400).json({ error: 'Enter a project name' });
    if (!tmp && !gh) return res.status(400).json({ error: 'Upload a ZIP or enter a GitHub URL' });
    if (gh && !GH_RE.test(gh)) return res.status(400).json({ error: 'Invalid GitHub URL' });
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try {
      if (tmp) extractZip(tmp, dir);
      else { await gitClone(gh, dir, String(req.body.branch || '').trim()); rm(path.join(dir, '.git')); }
      if (!fs.existsSync(path.join(dir, 'index.html'))) throw new Error('index.html not found in the project root');
    } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'website', name, slug: slugify(name), dir, github: gh || null, createdAt: now() };
    p.stats = cf.dirStats(dir);
    if (cf.enabled) {
      try { await cf.createSite(p); p.cf = true; p.cfState = 'live'; }
      catch (e) { rm(dir); return res.status(502).json({ error: e.message }); }
    }
    db.projects.push(p); save();
    res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});

app.post('/api/projects/bot', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file && req.file.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name);
    const botType = String(req.body.botType || '');
    if (!name) return res.status(400).json({ error: 'Enter a bot name' });
    if (!['baileys', 'telegram', 'discord'].includes(botType)) return res.status(400).json({ error: 'Choose a bot type' });
    const gh = String(req.body.githubUrl || '').trim();
    if (!tmp && !gh) return res.status(400).json({ error: 'Upload the bot ZIP or enter a GitHub URL' });
    if (gh && !GH_RE.test(gh)) return res.status(400).json({ error: 'Invalid GitHub URL' });
    const env = parseEnv(req.body.envVars);
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try {
      if (tmp) extractZip(tmp, dir); else { await gitClone(gh, dir, String(req.body.branch || '').trim()); rm(path.join(dir, '.git')); }
      if (!fs.existsSync(path.join(dir, 'package.json'))) throw new Error('package.json not found in the ZIP root');
    } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'bot', botType, name, slug: slugify(name), dir, env, github: gh || null, desired: 'running', createdAt: now() };
    db.projects.push(p); save();
    runner.start(p); // continues in the background (npm install + start)
    res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});

function ownProject(req, res) {
  const p = db.projects.find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!p) res.status(404).json({ error: 'Project not found' });
  return p;
}
app.get('/api/projects/:id/env', auth, (req, res) => { const p = ownProject(req, res); if (p) res.json({ keys: Object.keys(p.env || {}) }); }); // values are never returned
app.put('/api/projects/:id/env', auth, async (req, res) => {
  const p = ownProject(req, res); if (!p) return;
  if (p.type !== 'bot') return res.status(400).json({ error: 'Bots only' });
  p.env = parseEnv(req.body.envVars); save();
  if (p.desired === 'running' && isActive(req.user) && !p.adminSuspended) { runner.stop(p.id); await new Promise(r => setTimeout(r, 1500)); runner.start(p); }
  res.json({ ok: true });
});
app.get('/api/projects/:id/logs', auth, (req, res) => { const p = ownProject(req, res); if (p) res.json({ logs: runner.getLogs(p.id) }); });
app.post('/api/projects/:id/:action(start|stop|restart)', auth, async (req, res) => {
  const p = ownProject(req, res); if (!p) return;
  if (p.type !== 'bot') return res.status(400).json({ error: 'Bots only' });
  const a = req.params.action;
  if (a !== 'stop' && !isActive(req.user)) return res.status(402).json({ error: 'Please pay to continue.' });
  if (a !== 'stop' && p.adminSuspended) return res.status(403).json({ error: 'This project was suspended by an admin.' });
  if (a === 'stop') { p.desired = 'stopped'; runner.stop(p.id); }
  else {
    p.desired = 'running';
    if (a === 'restart') { runner.stop(p.id); await new Promise(r => setTimeout(r, 1500)); }
    runner.start(p);
  }
  save(); res.json(projectView(p));
});
function deleteProject(p) {
  if (p.cf) cf.removeSite(p);
  p.desired = 'stopped'; runner.stop(p.id);
  setTimeout(() => rm(p.dir), 3000);
  db.projects = db.projects.filter(x => x.id !== p.id); save();
}
app.delete('/api/projects/:id', auth, (req, res) => { const p = ownProject(req, res); if (p) { deleteProject(p); res.json({ ok: true }); } });

/* ---------- profile & settings ---------- */
app.get('/api/profile', auth, (req, res) => {
  const mine = db.projects.filter(p => p.userId === req.user.id);
  res.json({ ...publicUser(req.user), memberSince: req.user.createdAt, projects: mine.length, websites: mine.filter(p => p.type === 'website').length, bots: mine.filter(p => p.type === 'bot').length });
});
app.put('/api/profile', auth, (req, res) => {
  const name = String(req.body.displayName || '').trim().replace(/\s+/g, ' ');
  if (name.length < 1 || name.length > 40) return res.status(400).json({ error: 'Display name must be 1-40 characters' });
  req.user.displayName = name; save();
  res.json(publicUser(req.user));
});
app.post('/api/settings/password', authLimit, auth, async (req, res) => {
  const cur = String(req.body.currentPassword || ''), next = String(req.body.newPassword || '');
  if (!(await bcrypt.compare(cur, req.user.passHash))) return res.status(400).json({ error: 'Current password is incorrect' });
  if (next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  if (next === cur) return res.status(400).json({ error: 'New password must be different' });
  req.user.passHash = await bcrypt.hash(next, 10); save();
  res.json({ ok: true });
});
app.delete('/api/account', authLimit, auth, async (req, res) => {
  if (!(await bcrypt.compare(String(req.body.password || ''), req.user.passHash))) return res.status(400).json({ error: 'Incorrect password' });
  db.projects.filter(p => p.userId === req.user.id).forEach(deleteProject);
  db.users = db.users.filter(u => u.id !== req.user.id); // payment records are kept for accounting
  save();
  res.json({ ok: true });
});

/* ---------- billing routes ---------- */
app.get('/api/billing', auth, (req, res) => res.json(publicUser(req.user)));
app.post('/api/billing/pay', auth, async (req, res) => {
  if (!PSK) return res.status(500).json({ error: 'Paystack is not configured' });
  const reference = `mh_${req.user.id}_${Date.now()}`;
  db.pending[reference] = { userId: req.user.id, amount: getPrice() * 100, at: now() }; save();
  try {
    const r = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST', headers: { Authorization: 'Bearer ' + PSK, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: req.user.email, amount: getPrice() * 100, currency: 'KES', reference, callback_url: `${BASE_URL}/billing/return`, metadata: { userId: req.user.id } })
    });
    const j = await r.json();
    if (!j.status) return res.status(502).json({ error: j.message || 'Paystack error' });
    res.json({ url: j.data.authorization_url });
  } catch { res.status(502).json({ error: 'Could not reach Paystack' }); }
});
app.get('/billing/return', async (req, res) => {
  const ref = String(req.query.reference || req.query.trxref || '');
  let ok = false;
  try { ok = ref && await creditPayment(ref); } catch (e) { console.error(e); }
  res.redirect('/#/billing?paid=' + (ok ? '1' : '0'));
});

/* ---------- admin ---------- */
app.post('/api/admin/login', limiter(10, 15 * 60000), (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'ADMIN_PASSWORD is not set on the server. Add it in the Render environment and redeploy.' });
  if (!safeEq(String(req.body.password || '').trim(), ADMIN_PASSWORD)) return res.status(401).json({ error: 'Incorrect password' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
});
app.get('/api/admin/settings', adminAuth, (req, res) => res.json({ price: getPrice(), trialDays: getTrialDays() }));
app.put('/api/admin/settings', adminAuth, (req, res) => {
  const price = Math.round(Number(req.body.price)), trialDays = Math.round(Number(req.body.trialDays));
  if (!Number.isFinite(price) || price < 10 || price > 100000) return res.status(400).json({ error: 'Price must be between KES 10 and 100000' });
  if (!Number.isFinite(trialDays) || trialDays < 0 || trialDays > 60) return res.status(400).json({ error: 'Trial days must be between 0 and 60' });
  db.settings.price = price; db.settings.trialDays = trialDays; save();
  res.json({ price, trialDays });
});
app.get('/api/admin/overview', adminAuth, (req, res) => {
  const users = db.users.map(u => ({ id: u.id, email: u.email, status: userStatus(u), daysLeft: daysLeft(u), projects: db.projects.filter(p => p.userId === u.id).length, blocked: !!u.blocked, createdAt: u.createdAt }));
  const projects = db.projects.map(p => ({ ...projectView(p), owner: (db.users.find(u => u.id === p.userId) || {}).email }));
  const revenue = db.payments.reduce((s, p) => s + p.amount, 0);
  const c = s => users.filter(u => u.status === s).length;
  res.json({ stats: { liveSites: projects.filter(p => p.type === 'website' && p.status === 'live').length, runningBots: projects.filter(p => p.type === 'bot' && p.status === 'running').length, users: users.length, trial: c('trial'), paid: c('paid'), expired: c('expired'), blocked: c('blocked'), projects: projects.length, revenue }, users, projects, payments: [...db.payments].reverse() });
});
app.post('/api/admin/users/:id/block', adminAuth, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'User not found' });
  u.blocked = !!req.body.blocked; save();
  if (u.blocked) db.projects.filter(p => p.userId === u.id && p.type === 'bot').forEach(p => runner.stop(p.id));
  else resumeUserBots(u.id);
  syncSites();
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/verify', adminAuth, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'User not found' });
  if (!u.verified) { u.verified = true; u.trialEndsAt = now() + getTrialDays() * DAY; u.code = null; }
  save(); res.json({ ok: true });
});
app.post('/api/admin/users/:id/extend', adminAuth, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'User not found' });
  const d = Math.min(365, Math.max(1, Number(req.body.days) || 30));
  u.paidUntil = Math.max(now(), u.paidUntil || 0) + d * DAY; save(); resumeUserBots(u.id); syncSites();
  res.json({ ok: true });
});
app.post('/api/admin/projects/:id/suspend', adminAuth, async (req, res) => {
  const p = db.projects.find(x => x.id === req.params.id); if (!p) return res.status(404).json({ error: 'Not found' });
  p.adminSuspended = !!req.body.suspended; save();
  if (p.type === 'bot') { if (p.adminSuspended) runner.stop(p.id); else resumeUserBots(p.userId); }
  await syncSites();
  res.json({ ok: true });
});
app.delete('/api/admin/projects/:id', adminAuth, (req, res) => {
  const p = db.projects.find(x => x.id === req.params.id); if (!p) return res.status(404).json({ error: 'Not found' });
  deleteProject(p); res.json({ ok: true });
});

/* ---------- enforcement ---------- */
// every 5 minutes: stop bots of users who have not paid
setInterval(() => {
  db.projects.filter(p => p.type === 'bot' && runner.isRunning(p.id)).forEach(p => {
    const o = db.users.find(u => u.id === p.userId);
    if (!o || !isActive(o) || p.adminSuspended) { runner.log(p.id, 'Stopped: payment expired or suspended by an admin.'); runner.stop(p.id); }
  });
}, 5 * 60000);

// Cloudflare sites: switch between live <-> blocked depending on payment
const cfBusy = new Set();
async function syncSites() {
  if (!cf.enabled) return;
  for (const p of db.projects.filter(x => x.type === 'website' && x.cf)) {
    const o = db.users.find(u => u.id === p.userId);
    const want = o && isActive(o) && !p.adminSuspended ? 'live' : 'blocked';
    if (p.cfState === want || cfBusy.has(p.id)) continue;
    cfBusy.add(p.id);
    try { await cf.setState(p, want); p.cfState = want; save(); }
    catch (e) { console.error('cf sync', p.slug, e.message); }
    cfBusy.delete(p.id);
  }
}
setInterval(syncSites, 5 * 60000);

/* ---------- frontend ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.status(404).send('Not found'));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('ERROR', req.method, req.path, err && err.message);
  if (res.headersSent) return;
  if (err && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File too large (max 50MB)' });
  const status = (err && err.status) || 500;
  res.status(status).json({ error: status === 400 ? 'Bad request' : 'Server error. Please try again.' });
});

app.listen(PORT, () => {
  console.log('MtaaniHost is running on port ' + PORT);
  syncSites();
  // restart bots after a server restart
  db.projects.filter(p => p.type === 'bot' && p.desired === 'running').forEach(p => {
    const o = db.users.find(u => u.id === p.userId);
    if (o && isActive(o) && !p.adminSuspended) runner.start(p);
  });
});
