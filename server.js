require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { execFile } = require('child_process');
const { db, save, DATA } = require('./db');
const runner = require('./runner');

let cf = {
  dirStats: () => ({ files: 0, bytes: 0, deployedAt: Date.now() }),
  removeSite: () => {},
  createSite: async () => null
};
try { cf = require('./cf'); } catch (e) { console.log('cf.js not loaded, using dummy - free /p/ mode'); }

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('Set JWT_SECRET in env'); process.exit(1); }
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PSK = process.env.PAYSTACK_SECRET_KEY;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').toLowerCase();
const PRICE = Number(process.env.PRICE_KES || 200);
const DAY = 86400000, TRIAL_DAYS = 7, MAX_PROJECTS = 5;
const RESERVED = ['www', 'app', 'api', 'admin', 'p', 'mail', 'static'];

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '500kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));

const now = () => Date.now();
const uid = () => crypto.randomBytes(8).toString('hex');
const expiry = u => Math.max(u.trialEndsAt || 0, u.paidUntil || 0);
const isActive = u =>!u.blocked && u.verified && now() < expiry(u);
const daysLeft = u => Math.max(0, Math.ceil((expiry(u) - now()) / DAY));
const userStatus = u => u.blocked? 'blocked' :!u.verified? 'unverified' : (u.paidUntil && now() < u.paidUntil)? 'paid' : now() < (u.trialEndsAt || 0)? 'trial' : 'expired';
const publicUser = u => ({ id: u.id, email: u.email, displayName: u.displayName || u.email.split('@')[0], status: userStatus(u), active: isActive(u), daysLeft: daysLeft(u), trialEndsAt: u.trialEndsAt, paidUntil: u.paidUntil || 0, price: PRICE });
const safeEq = (a, b) => { try { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); if (x.length!== y.length) return false; return crypto.timingSafeEqual(x, y); } catch { return String(a) === String(b); } };

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
const authLimit = limiter(20, 15 * 60000);

app.post('/api/auth/signup', authLimit, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  let u = db.users.find(x => x.email === email);
  if (u && u.verified) return res.status(409).json({ error: 'This email already has an account. Please login.' });
  const passHash = await bcrypt.hash(password, 10);
  if (!u) {
    u = { id: uid(), email, displayName: email.split('@')[0], verified: true, trialEndsAt: now() + TRIAL_DAYS * DAY, paidUntil: 0, blocked: false, createdAt: now(), passHash };
    db.users.push(u);
  } else {
    Object.assign(u, { passHash, verified: true, trialEndsAt: u.trialEndsAt || now() + TRIAL_DAYS * DAY, blocked: false });
  }
  save();
  const token = jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser(u) });
});

app.post('/api/auth/resend', authLimit, async (req, res) => { res.json({ ok: true }); });
app.post('/api/auth/verify', authLimit, (req, res) => { res.json({ ok: true }); });

app.post('/api/auth/login', authLimit, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.users.find(x => x.email === email);
  if (!u ||!(await bcrypt.compare(String(req.body.password || ''), u.passHash))) return res.status(401).json({ error: 'Incorrect email or password' });
  if (u.blocked) return res.status(403).json({ error: 'Your account has been blocked.' });
  if (!u.verified) { u.verified = true; if (!u.trialEndsAt) u.trialEndsAt = now() + TRIAL_DAYS * DAY; save(); }
  res.json({ token: jwt.sign({ id: u.id, role: 'user' }, JWT_SECRET, { expiresIn: '30d' }), user: publicUser(u) });
});

app.post('/api/auth/forgot', authLimit, async (req, res) => { res.json({ ok: true }); });
app.post('/api/auth/reset', authLimit, async (req, res) => { res.status(400).json({ error: 'Reset disabled' }); });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const d = jwt.verify(t, JWT_SECRET);
    if (d.role!== 'user') throw new Error();
    const u = db.users.find(x => x.id === d.id);
    if (!u) throw new Error();
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please login again' }); }
}
function adminAuth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    if (d.role!== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Admin only' }); }
}

app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));
app.get('/api/profile', auth, (req, res) => {
  const u = req.user;
  const projects = db.projects.filter(p => p.userId === u.id);
  res.json({ email: u.email, displayName: u.displayName || u.email.split('@')[0], status: userStatus(u), daysLeft: daysLeft(u), memberSince: u.createdAt, projects: projects.length, websites: projects.filter(p=>p.type==='website').length, bots: projects.filter(p=>p.type==='bot').length,...publicUser(u) });
});
app.put('/api/profile', auth, (req, res) => {
  const { displayName } = req.body;
  if (displayName && displayName.trim().length > 0) { req.user.displayName = displayName.trim().slice(0,40); save(); }
  res.json({ ok: true });
});
app.post('/api/settings/password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword ||!newPassword) return res.status(400).json({ error: 'Fill all fields' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password at least 6 chars' });
  const ok = await bcrypt.compare(currentPassword.trim(), req.user.passHash);
  if (!ok) return res.status(400).json({ error: 'Current password is wrong' });
  req.user.passHash = await bcrypt.hash(newPassword.trim(), 10); save(); res.json({ ok: true });
});
app.delete('/api/account', auth, async (req, res) => {
  const { password } = req.body;
  const ok = await bcrypt.compare(String(password||''), req.user.passHash);
  if (!ok) return res.status(400).json({ error: 'Password is wrong' });
  db.projects.filter(p=>p.userId===req.user.id).forEach(p=>{ p.desired='stopped'; runner.stop(p.id); setTimeout(()=>{ try{fs.rmSync(p.dir,{recursive:true,force:true})}catch{} },2000); });
  db.projects = db.projects.filter(p=>p.userId!==req.user.id);
  db.users = db.users.filter(u=>u.id!==req.user.id); save(); res.json({ ok: true });
});

function projectView(p) {
  const owner = db.users.find(u => u.id === p.userId);
  const active = owner && isActive(owner) &&!p.adminSuspended;
  let status;
  if (!active) status = 'suspended';
  else if (p.type === 'website') status = 'live';
  else status = runner.isRunning(p.id)? 'running' : (p.desired === 'running'? 'starting' : 'stopped');
  let url = null;
  if (p.type === 'website') url = BASE_DOMAIN? `https://${p.slug}.${BASE_DOMAIN}` : `${BASE_URL}/p/${p.slug}/`;
  let stats = {};
  try { stats = p.type === 'bot'? runner.stats(p.id) : cf.dirStats(p.dir); } catch { stats = { files: 0, bytes: 0 }; }
  return { id: p.id, name: p.name, type: p.type, botType: p.botType, slug: p.slug, url, status, createdAt: p.createdAt, github: p.github || null, suspendedBy: p.adminSuspended? 'admin' : (!active? 'billing' : null), stats };
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
  if (total > 300 * 1024 * 1024) throw new Error('Zip too large');
  fs.mkdirSync(dest, { recursive: true });
  for (const e of entries) {
    if (e.entryName.startsWith('__MACOSX') || e.entryName.includes('..')) continue;
    const target = path.resolve(dest, e.entryName);
    if (!target.startsWith(path.resolve(dest) + path.sep)) continue;
    if (e.isDirectory) fs.mkdirSync(target, { recursive: true });
    else { fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, e.getData()); }
  }
  flatten(dest);
}
function flatten(dir) {
  const items = fs.readdirSync(dir).filter(n => n!== '__MACOSX');
  if (items.length === 1 && fs.statSync(path.join(dir, items[0])).isDirectory()) {
    const inner = path.join(dir, items[0]);
    for (const n of fs.readdirSync(inner)) fs.renameSync(path.join(inner, n), path.join(dir, n));
    fs.rmdirSync(inner);
  }
}
const upload = multer({ dest: path.join(os.tmpdir(), 'mh-uploads'), limits: { fileSize: 50 * 1024 * 1024 } });
const rm = p => { try { fs.rmSync(p, { recursive: true, force: true }); } catch {} };
const gitClone = (url, dest) => new Promise((ok, no) => execFile('git', ['clone', '--depth', '1', url, dest], { timeout: 120000 }, e => e? no(new Error('Git clone failed')) : ok()));
function checkCanDeploy(req, res) {
  if (!isActive(req.user)) { res.status(402).json({ error: 'Your trial has expired. Please pay.' }); return false; }
  if (db.projects.filter(p => p.userId === req.user.id).length >= MAX_PROJECTS) { res.status(400).json({ error: `Max projects is ${MAX_PROJECTS}` }); return false; }
  return true;
}
function cleanName(n) { return String(n || '').trim().slice(0, 40); }

app.get('/api/projects', auth, (req, res) => res.json(db.projects.filter(p => p.userId === req.user.id).map(projectView)));
app.get('/api/projects/:id/env', auth, (req, res) => {
  const p = db.projects.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.type!=='bot') return res.status(400).json({ error: 'Bots only' });
  res.json({ keys: Object.keys(p.env||{}) });
});
app.put('/api/projects/:id/env', auth, (req, res) => {
  const p = db.projects.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.type!=='bot') return res.status(400).json({ error: 'Bots only' });
  const env = {};
  String(req.body.envVars||'').split(/\r?\n/).forEach(l=>{
    const m=l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if(m) env[m[1]]=m[2].replace(/^["']|["']$/g,'');
  });
  p.env=env; save(); runner.stop(p.id); setTimeout(()=>runner.start(p),1500); res.json({ ok: true });
});
app.post('/api/projects/website', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file && req.file.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name);
    const gh = String(req.body.githubUrl || '').trim();
    if (!name) return res.status(400).json({ error: 'Enter project name' });
    if (!tmp &&!gh) return res.status(400).json({ error: 'Upload ZIP or GitHub' });
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try {
      if (tmp) extractZip(tmp, dir);
      else { await gitClone(gh, dir); rm(path.join(dir, '.git')); }
      if (!fs.existsSync(path.join(dir, 'index.html'))) throw new Error('index.html not found');
    } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'website', name, slug: slugify(name), dir, github: gh || null, createdAt: now() };
    db.projects.push(p); save(); res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});
app.post('/api/projects/bot', auth, upload.single('file'), async (req, res) => {
  const tmp = req.file && req.file.path;
  try {
    if (!checkCanDeploy(req, res)) return;
    const name = cleanName(req.body.name);
    const botType = String(req.body.botType || '');
    if (!name) return res.status(400).json({ error: 'Enter bot name' });
    if (!['baileys', 'telegram', 'discord'].includes(botType)) return res.status(400).json({ error: 'Select bot type' });
    if (!tmp) return res.status(400).json({ error: 'Upload bot ZIP' });
    const env = {};
    String(req.body.envVars || '').split(/\r?\n/).forEach(l => {
      const m = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    });
    const id = uid(), dir = path.join(DATA, 'projects', id);
    try {
      extractZip(tmp, dir);
      if (!fs.existsSync(path.join(dir, 'package.json'))) throw new Error('package.json not found');
    } catch (e) { rm(dir); return res.status(400).json({ error: e.message }); }
    const p = { id, userId: req.user.id, type: 'bot', botType, name, slug: slugify(name), dir, env, desired: 'running', createdAt: now() };
    db.projects.push(p); save(); runner.start(p); res.json(projectView(p));
  } finally { if (tmp) rm(tmp); }
});
app.get('/api/projects/:id/logs', auth, (req, res) => {
  const p = db.projects.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if(!p) return res.status(404).json({error:'Not found'});
  res.json({ logs: runner.getLogs(p.id) });
});
app.post('/api/projects/:id/:action(start|stop|restart)', auth, async (req, res) => {
  const p = db.projects.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if(!p) return res.status(404).json({error:'Not found'});
  if (p.type!=='bot') return res.status(400).json({ error: 'Bots only' });
  const a = req.params.action;
  if (a!=='stop' &&!isActive(req.user)) return res.status(402).json({ error: 'Please pay' });
  if (a==='stop') { p.desired = 'stopped'; runner.stop(p.id); }
  else { p.desired = 'running'; if (a === 'restart') { runner.stop(p.id); await new Promise(r => setTimeout(r, 1500)); } runner.start(p); }
  save(); res.json(projectView(p));
});
function deleteProject(p) {
  try { if (p.cf) cf.removeSite(p); } catch {}
  p.desired = 'stopped'; runner.stop(p.id);
  setTimeout(() => rm(p.dir), 3000);
  db.projects = db.projects.filter(x => x.id!== p.id); save();
}
app.delete('/api/projects/:id', auth, (req, res) => {
  const p = db.projects.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if(!p) return res.status(404).json({error:'Not found'});
  deleteProject(p); res.json({ ok: true });
});

app.get('/api/billing', auth, (req, res) => res.json(publicUser(req.user)));
async function creditPaymentInner(reference) {
  if (db.payments.find(p => p.reference === reference)) return true;
  if (!PSK) return false;
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), { headers: { Authorization: 'Bearer ' + PSK } });
  const j = await r.json();
  if (!j.status ||!j.data || j.data.status!== 'success') return false;
  const d = j.data, userId = d.metadata && d.metadata.userId;
  const user = db.users.find(u => u.id === userId);
  if (!user || d.currency!== 'KES' || d.amount < PRICE * 100) return false;
  if (db.payments.find(p => p.reference === reference)) return true;
  user.paidUntil = Math.max(now(), user.paidUntil || 0) + 30 * DAY;
  db.payments.push({ reference, userId, email: user.email, amount: d.amount / 100, currency: d.currency, channel: d.channel, at: now() });
  save(); resumeUserBots(user.id); return true;
}
function resumeUserBots(userId) {
  const o = db.users.find(x => x.id === userId);
  if (!o ||!isActive(o)) return;
  db.projects.filter(p => p.userId === userId && p.type === 'bot' && p.desired === 'running' &&!p.adminSuspended).forEach(p => runner.start(p));
}
app.post('/api/billing/pay', auth, async (req, res) => {
  if (!PSK) return res.status(500).json({ error: 'Paystack not configured' });
  const reference = `mh_${req.user.id}_${Date.now()}`;
  try {
    const r = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: 'Bearer ' + PSK, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: req.user.email, amount: PRICE * 100, currency: 'KES', reference, callback_url: `${BASE_URL}/billing/return`, metadata: { userId: req.user.id } }) });
    const j = await r.json();
    if (!j.status) return res.status(502).json({ error: j.message || 'Paystack error' });
    res.json({ url: j.data.authorization_url });
  } catch { res.status(502).json({ error: 'Failed to Paystack' }); }
});
app.get('/billing/return', async (req, res) => {
  const ref = String(req.query.reference || req.query.trxref || '');
  let ok = false;
  try { ok = ref && await creditPaymentInner(ref); } catch (e) { console.error(e); }
  res.redirect('/#/billing?paid=' + (ok? '1' : '0'));
});
app.post('/api/paystack/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const sig = crypto.createHmac('sha512', PSK || '').update(req.body).digest('hex');
    if (!safeEq(sig, req.headers['x-paystack-signature'] || '')) return res.sendStatus(401);
    const ev = JSON.parse(req.body.toString());
    if (ev.event === 'charge.success') await creditPaymentInner(ev.data.reference);
    res.sendStatus(200);
  } catch (e) { console.error('webhook', e); res.sendStatus(500); }
});

function blockedPage(res, name) {
  res.status(402).send(`<body style="font-family:sans-serif;background:#000;color:#fff;display:grid;place-items:center;height:100vh"><div><h1>Suspended</h1><p>${String(name).replace(/[<>&"]/g, '')} needs payment.</p></div>`);
}
function serveSite(slug, req, res, next) {
  const p = db.projects.find(x => x.slug === slug && x.type === 'website');
  if (!p) return next();
  const owner = db.users.find(u => u.id === p.userId);
  if (!owner ||!isActive(owner) || p.adminSuspended) return blockedPage(res, p.name);
  express.static(p.dir, { index: 'index.html', extensions: ['html'], dotfiles: 'ignore' })(req, res, () => {
    const nf = path.join(p.dir, '404.html');
    if (fs.existsSync(nf)) return res.status(404).sendFile(nf);
    res.status(404).send('Not found');
  });
}
app.use((req, res, next) => {
  if (!BASE_DOMAIN) return next();
  const host = (req.hostname || '').toLowerCase();
  if (host.endsWith('.' + BASE_DOMAIN)) {
    const slug = host.slice(0, -(BASE_DOMAIN.length + 1));
    if (!slug.includes('.') &&!RESERVED.includes(slug)) return serveSite(slug, req, res, () => res.status(404).send('Project does not exist'));
  }
  next();
});
app.use('/p/:slug', (req, res, next) => serveSite(req.params.slug, req, res, next));

// ===== FIXED ADMIN - NOW ACCEPTS 1234 =====
app.post('/api/admin/login', limiter(10, 15 * 60000), (req, res) => {
  const input = String(req.body.password || '').trim();
  const real = String(ADMIN_PASSWORD || '').trim();
  console.log('Admin login try:', JSON.stringify(input), 'real len', real.length);
  const isOk = (real && input === real) || input === '1234';
  if (!isOk) return res.status(401).json({ error: 'Incorrect password. Try 1234' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
});

app.get('/api/admin/overview', adminAuth, (req, res) => {
  const users = db.users.map(u => ({ id: u.id, email: u.email, status: userStatus(u), daysLeft: daysLeft(u), projects: db.projects.filter(p => p.userId === u.id).length, blocked:!!u.blocked, createdAt: u.createdAt }));
  const projects = db.projects.map(p => ({...projectView(p), owner: (db.users.find(u => u.id === p.userId) || {}).email }));
  const revenue = db.payments.reduce((s, p) => s + p.amount, 0);
  const c = s => users.filter(u => u.status === s).length;
  res.json({ stats: { liveSites: projects.filter(p => p.type === 'website' && p.status === 'live').length, runningBots: projects.filter(p => p.type === 'bot' && p.status === 'running').length, users: users.length, trial: c('trial'), paid: c('paid'), expired: c('expired'), blocked: c('blocked'), projects: projects.length, revenue }, users, projects, payments: [...db.payments].reverse() });
});
app.post('/api/admin/users/:id/block', adminAuth, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'User not found' });
  u.blocked =!!req.body.blocked; save();
  if (u.blocked) db.projects.filter(p => p.userId === u.id && p.type === 'bot').forEach(p => runner.stop(p.id));
  else resumeUserBots(u.id);
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/extend', adminAuth, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'User not found' });
  const d = Math.min(365, Math.max(1, Number(req.body.days) || 30));
  u.paidUntil = Math.max(now(), u.paidUntil || 0) + d * DAY; save(); resumeUserBots(u.id); res.json({ ok: true });
});
app.post('/api/admin/projects/:id/suspend', adminAuth, async (req, res) => {
  const p = db.projects.find(x => x.id === req.params.id); if (!p) return res.status(404).json({ error: 'Not found' });
  p.adminSuspended =!!req.body.suspended; save();
  if (p.type === 'bot') { if (p.adminSuspended) runner.stop(p.id); else resumeUserBots(p.userId); }
  res.json({ ok: true });
});
app.delete('/api/admin/projects/:id', adminAuth, (req, res) => {
  const p = db.projects.find(x => x.id === req.params.id); if (!p) return res.status(404).json({ error: 'Not found' });
  deleteProject(p); res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.status(404).send('Not found'));
app.listen(PORT, () => {
  console.log('MtaaniHost FIXED FULL - ADMIN backup 1234 enabled - Port ' + PORT);
  db.projects.filter(p => p.type === 'bot' && p.desired === 'running').forEach(p => {
    const o = db.users.find(u => u.id === p.userId);
    if (o && isActive(o) &&!p.adminSuspended) runner.start(p);
  });
});
