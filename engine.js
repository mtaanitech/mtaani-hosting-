// Deployment engine: project detection, git clone, install/build, static file storage,
// running services (Node web apps / bots), live logs, and the reverse proxy for services.
const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, save, DATA } = require('./db');

const DAY = 86400000, GB = 1024 ** 3;
const WORK = path.join(DATA, 'work'), STATIC = path.join(DATA, 'static'), NPM_CACHE = path.join(DATA, 'npm-cache');
[WORK, STATIC, NPM_CACHE].forEach(d => fs.mkdirSync(d, { recursive: true }));
const BUILD_CONCURRENCY = Number(process.env.BUILD_CONCURRENCY || 1);
const MEM_MB = Number(process.env.SERVICE_MEMORY_MB || 384);

/* ---------- billing / quota helpers (shared with server.js) ---------- */
const now = () => Date.now();
const getPrice = () => Number(db.settings.price) || 70;                                         // KES per month
const getTrialDays = () => db.settings.trialDays === undefined ? 14 : Number(db.settings.trialDays);
const getStorageGB = () => db.settings.storageGB === undefined ? 10 : Number(db.settings.storageGB);
const expiry = u => Math.max(u.trialEndsAt || 0, u.paidUntil || 0);
const isActive = u => !!u && !u.blocked && u.verified && now() < expiry(u);
const quotaBytes = u => (u && u.storageGB !== undefined && u.storageGB !== null ? Number(u.storageGB) : getStorageGB()) * GB;
const usageBytes = userId => db.projects.filter(p => p.userId === userId).reduce((s, p) => s + (p.sizeBytes || 0), 0);

/* ---------- token encryption (GitHub access tokens) ---------- */
const KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || process.env.JWT_SECRET || 'dev-only-key').digest();
function encrypt(text) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decrypt(b64) {
  try {
    const b = Buffer.from(b64, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  } catch { return null; }
}

/* ---------- auto-detection of how to build / run a repository ---------- */
const BOT_DEPS = ['@whiskeysockets/baileys', 'baileys', '@adiwajshing/baileys', 'whatsapp-web.js', 'telegraf', 'node-telegram-bot-api', 'grammy', 'discord.js', 'eris'];
const STATIC_FW = [['vite', 'dist', 'Vite'], ['react-scripts', 'build', 'Create React App'], ['@vue/cli-service', 'dist', 'Vue CLI'], ['astro', 'dist', 'Astro'], ['parcel', 'dist', 'Parcel'], ['gatsby', 'public', 'Gatsby'], ['@11ty/eleventy', '_site', 'Eleventy']];
function detectConfig(pkg, files = []) {
  const base = { kind: 'static', framework: 'Static HTML', installCmd: '', buildCmd: '', startCmd: '', outputDir: '.', exposeWeb: false, notes: [] };
  if (!pkg) {
    if (!files.includes('index.html')) base.notes.push('No package.json or index.html found in the repository root. Set the commands manually.');
    return base;
  }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }, sc = pkg.scripts || {};
  const has = n => Object.prototype.hasOwnProperty.call(deps, n);
  const install = 'npm install', build = sc.build ? 'npm run build' : '';
  if (has('next')) return { ...base, kind: 'service', framework: 'Next.js', installCmd: install, buildCmd: 'npm run build', startCmd: 'npm start', outputDir: '', exposeWeb: true, notes: ['Next.js builds need a lot of memory (about 2 GB).'] };
  const bot = BOT_DEPS.find(has);
  if (bot) return { ...base, kind: 'service', framework: 'Bot (' + bot + ')', installCmd: install, buildCmd: build, startCmd: sc.start ? 'npm start' : 'node ' + (pkg.main || 'index.js'), outputDir: '', exposeWeb: false };
  const fw = STATIC_FW.find(f => has(f[0]));
  if (fw) return { ...base, framework: fw[2], installCmd: install, buildCmd: build, outputDir: fw[1] };
  if (sc.start) return { ...base, kind: 'service', framework: has('express') ? 'Express' : 'Node.js', installCmd: install, buildCmd: build, startCmd: 'npm start', outputDir: '', exposeWeb: true };
  if (sc.build) return { ...base, framework: 'Static build', installCmd: install, buildCmd: build, outputDir: 'dist' };
  if (pkg.main) return { ...base, kind: 'service', framework: 'Node.js', installCmd: install, startCmd: 'node ' + pkg.main, outputDir: '', exposeWeb: true };
  return { ...base, framework: 'Static HTML', installCmd: '' };
}

/* ---------- live logs ---------- */
const logBufs = new Map(), subs = new Map();
const mask = s => String(s).replace(/(x-access-token:)[^@\s]+@/g, '$1***@');
function emit(id, ev) { for (const fn of subs.get(id) || []) { try { fn(ev); } catch {} } }
function log(id, text) {
  const arr = logBufs.get(id) || [];
  for (let l of String(text).split(/\r?\n/)) { if (!l) continue; l = mask(l); arr.push(l); emit(id, { line: l }); }
  while (arr.length > 3000) arr.shift();
  logBufs.set(id, arr);
}
function getLogs(p) { const mem = logBufs.get(p.id); return mem && mem.length ? mem : (p.lastLog ? p.lastLog.split('\n') : []); }
function subscribe(id, fn) { if (!subs.has(id)) subs.set(id, new Set()); subs.get(id).add(fn); return () => subs.get(id) && subs.get(id).delete(fn); }
function setStatus(p, status) { p.status = status; save(); emit(p.id, { status }); }

/* ---------- small utils ---------- */
const rmrf = p => { try { fs.rmSync(p, { recursive: true, force: true }); } catch {} };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const fmt = b => b > 1048576 ? (b / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB';
function walk(dir, skip = [], out = []) {
  for (const n of fs.readdirSync(dir)) {
    if (skip.includes(n) || n === '.git') continue;
    const f = path.join(dir, n); let st; try { st = fs.lstatSync(f); } catch { continue; }
    if (st.isSymbolicLink()) continue; // never follow links out of the project folder
    if (st.isDirectory()) walk(f, skip, out); else out.push({ file: f, rel: path.relative(dir, f), size: st.size });
  }
  return out;
}
function dirStats(dir, skip = []) {
  const files = []; (function w(d, base) {
    for (const n of fs.readdirSync(d)) {
      if (skip.includes(n) || n === '.git') continue;
      const f = path.join(d, n); let st; try { st = fs.lstatSync(f); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) w(f, base); else files.push(st.size);
    }
  })(dir, dir);
  return { files: files.length, bytes: files.reduce((a, b) => a + b, 0) };
}
function killTree(child, sig = 'SIGTERM') { try { process.kill(-child.pid, sig); } catch { try { child.kill(sig); } catch {} } }
function freePort() { return new Promise((ok, no) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); s.on('error', no); }); }
function tryConnect(port) { return new Promise(ok => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); ok(true); }); s.on('error', () => ok(false)); }); }

/* ---------- static file storage: local disk, or Cloudflare R2 when configured ---------- */
const R2 = process.env.R2_BUCKET && process.env.CF_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY;
let s3 = null, S3 = null;
if (R2) {
  S3 = require('@aws-sdk/client-s3');
  s3 = new S3.S3Client({ region: 'auto', endpoint: `https://${process.env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY }, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
}
const mime = (() => { try { return require('mime-types'); } catch { return { lookup: () => false }; } })();
const storeMode = () => R2 ? 'r2' : 'disk';
async function storeRemove(p) {
  if (!R2) return rmrf(path.join(STATIC, p.id));
  let token;
  do {
    const l = await s3.send(new S3.ListObjectsV2Command({ Bucket: process.env.R2_BUCKET, Prefix: `static/${p.id}/`, ContinuationToken: token }));
    if (l.Contents && l.Contents.length) await s3.send(new S3.DeleteObjectsCommand({ Bucket: process.env.R2_BUCKET, Delete: { Objects: l.Contents.map(o => ({ Key: o.Key })), Quiet: true } }));
    token = l.IsTruncated ? l.NextContinuationToken : undefined;
  } while (token);
}
async function storePut(p, dir) {
  await storeRemove(p);
  if (!R2) { fs.cpSync(dir, path.join(STATIC, p.id), { recursive: true, dereference: false }); return; }
  const files = walk(dir);
  for (let i = 0; i < files.length; i += 10) {
    await Promise.all(files.slice(i, i + 10).map(f => s3.send(new S3.PutObjectCommand({ Bucket: process.env.R2_BUCKET, Key: `static/${p.id}/${f.rel.split(path.sep).join('/')}`, Body: fs.readFileSync(f.file), ContentType: mime.lookup(f.rel) || 'application/octet-stream' }))));
  }
}
async function storeGet(p, rel) { // -> { stream, size, type } | null
  if (!R2) {
    const base = path.join(STATIC, p.id), f = path.resolve(base, rel);
    if (!f.startsWith(base + path.sep)) return null;
    let st; try { st = fs.statSync(f); } catch { return null; }
    if (!st.isFile()) return null;
    return { stream: fs.createReadStream(f), size: st.size, type: mime.lookup(f) || 'application/octet-stream' };
  }
  try {
    const o = await s3.send(new S3.GetObjectCommand({ Bucket: process.env.R2_BUCKET, Key: `static/${p.id}/${rel}` }));
    return { stream: o.Body, size: o.ContentLength, type: o.ContentType || mime.lookup(rel) || 'application/octet-stream' };
  } catch { return null; }
}

/* ---------- running commands ---------- */
function buildEnv(p, dir, runtime, port) {
  const e = { PATH: process.env.PATH, HOME: dir, CI: 'true', FORCE_COLOR: '0', npm_config_cache: NPM_CACHE, npm_config_fund: 'false', npm_config_audit: 'false', npm_config_update_notifier: 'false' };
  for (const v of p.env || []) if (v && v.key) e[v.key] = String(v.value ?? '');
  if (runtime) { e.NODE_ENV = 'production'; e.PORT = String(port); e.HOST = '0.0.0.0'; e.NODE_OPTIONS = `--max-old-space-size=${MEM_MB}`; }
  return e;
}
function sh(cmd, { cwd, env, id, timeoutMs }) {
  return new Promise(resolve => {
    log(id, '$ ' + cmd);
    const child = spawn('sh', ['-c', cmd], { cwd, env, detached: true });
    const t = setTimeout(() => { log(id, `✖ Timed out after ${Math.round(timeoutMs / 60000)} minutes`); killTree(child, 'SIGKILL'); }, timeoutMs);
    child.stdout.on('data', d => log(id, d)); child.stderr.on('data', d => log(id, d));
    child.on('error', e => { clearTimeout(t); log(id, 'Error: ' + e.message); resolve(1); });
    child.on('close', code => { clearTimeout(t); resolve(code === null ? 1 : code); });
  });
}
function gitClone(p, token, dest) {
  return new Promise(resolve => {
    const plain = p.repoUrl || `https://github.com/${p.repo}.git`;
    const url = token && /^https:\/\/github\.com\//.test(plain) ? plain.replace('https://', `https://x-access-token:${token}@`) : plain;
    const args = ['clone', '--depth', '1'];
    if (p.branch) args.push('--branch', p.branch);
    args.push(url, dest);
    log(p.id, `$ git clone --depth 1 ${p.branch ? '--branch ' + p.branch + ' ' : ''}${plain}`);
    const c = spawn('git', args, { env: { PATH: process.env.PATH, HOME: WORK, GIT_TERMINAL_PROMPT: '0' } });
    c.stdout.on('data', d => log(p.id, d)); c.stderr.on('data', d => log(p.id, d));
    c.on('error', e => { log(p.id, 'Error: ' + e.message); resolve(1); });
    c.on('close', code => resolve(code === null ? 1 : code));
  });
}

/* ---------- services (Node web apps and bots) ---------- */
const procs = new Map(), ports = new Map();
const isRunning = id => procs.has(id);
const portOf = id => ports.get(id);
const startedAt = id => (procs.get(id) || {})._started || null;
function stopService(id) {
  const c = procs.get(id);
  if (!c) return;
  c._stopped = true; killTree(c);
  setTimeout(() => killTree(c, 'SIGKILL'), 5000);
  procs.delete(id);
}
async function waitReady(p, child, port) {
  if (!p.exposeWeb) { await sleep(2500); if (procs.get(p.id) !== child) throw new Error('The process exited right after starting. Check the logs above.'); return; }
  const t0 = Date.now();
  while (Date.now() - t0 < 90000) {
    if (procs.get(p.id) !== child) throw new Error('The process exited before it started listening. Check the logs above.');
    if (await tryConnect(port)) return;
    await sleep(500);
  }
  stopService(p.id);
  throw new Error(`Your app did not start listening on port ${port} within 90 seconds. Make sure it listens on process.env.PORT.`);
}
async function startService(p) {
  stopService(p.id);
  const port = await freePort();
  ports.set(p.id, port);
  const child = spawn('sh', ['-c', p.startCmd], { cwd: p.dir, env: buildEnv(p, p.dir, true, port), detached: true });
  child._started = now();
  procs.set(p.id, child);
  log(p.id, `$ ${p.startCmd}   (PORT=${port})`);
  child.stdout.on('data', d => log(p.id, d)); child.stderr.on('data', d => log(p.id, d));
  child.on('error', e => log(p.id, 'Error: ' + e.message));
  child.on('close', code => {
    if (procs.get(p.id) === child) procs.delete(p.id);
    if (child._stopped) return;
    log(p.id, `Process exited (code ${code})`);
    p.restarts = (p.restarts || 0) + 1; p.lastExit = { code, at: now() }; save();
    if (p.desired !== 'stopped' && (child._autoTry || 0) < 5 && ['live', 'crashed'].includes(p.status)) {
      log(p.id, 'Restarting in 5 seconds…');
      setTimeout(() => {
        if (procs.has(p.id) || p.desired === 'stopped') return;
        startService(p).then(() => setStatus(p, 'live')).catch(e => { log(p.id, '✖ ' + e.message); setStatus(p, 'crashed'); });
      }, 5000);
    } else if (p.status === 'live') setStatus(p, 'crashed');
  });
  await waitReady(p, child, port);
}
function proxy(p, req, res) {
  const port = ports.get(p.id);
  if (!port || !procs.has(p.id)) return res.status(503).send('This service is not running right now.');
  const headers = { ...req.headers, 'x-forwarded-for': req.ip, 'x-forwarded-proto': req.protocol, 'x-forwarded-host': req.headers.host };
  const pr = http.request({ host: '127.0.0.1', port, method: req.method, path: req.url, headers }, up => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
  pr.on('error', () => { if (!res.headersSent) res.status(502).send('Bad gateway: your app is not responding.'); else res.end(); });
  req.pipe(pr);
}

/* ---------- deployments ---------- */
const queue = [], inFlight = new Set(); let running = 0;
function pump() {
  while (running < BUILD_CONCURRENCY && queue.length) {
    const job = queue.shift(); running++;
    job().catch(e => console.error('deploy crashed', e)).finally(() => { running--; inFlight.delete(job.pid); pump(); });
  }
}
function enqueueDeploy(p) {
  if (inFlight.has(p.id)) return false; // already queued or building
  inFlight.add(p.id); setStatus(p, 'queued');
  const job = () => runDeploy(p); job.pid = p.id; queue.push(job); pump();
  return true;
}
function resolveOutput(dir, outputDir) {
  const cands = [];
  if (outputDir) cands.push(outputDir);
  cands.push('dist', 'build', 'out', 'public', '.');
  for (const c of cands) {
    const f = path.resolve(dir, c);
    if ((f === path.resolve(dir) || f.startsWith(path.resolve(dir) + path.sep)) && fs.existsSync(path.join(f, 'index.html'))) return f;
  }
  return null;
}
async function runDeploy(p) {
  const id = p.id, owner = db.users.find(u => u.id === p.userId);
  const token = owner && owner.ghToken ? decrypt(owner.ghToken) : null;
  const dir = path.join(WORK, id, 'd' + Date.now());
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  logBufs.set(id, []); p.lastError = null; setStatus(p, 'building');
  log(id, `▲ Deploying ${p.repo || p.repoUrl} (${p.branch || 'default branch'})`);
  const quotaCheck = size => {
    if (!owner) return;
    const used = usageBytes(owner.id) - (p.sizeBytes || 0), q = quotaBytes(owner);
    if (used + size > q) throw new Error(`Storage limit reached: this project needs ${fmt(size)} but you only have ${fmt(Math.max(0, q - used))} left (limit ${(q / GB).toFixed(1)} GB).`);
  };
  try {
    if (await gitClone(p, token, dir) !== 0) throw new Error('Could not clone the repository. Check the name and branch. For private repositories, connect GitHub first.');
    rmrf(path.join(dir, '.git'));
    const env = buildEnv(p, dir, false);
    if (p.installCmd && await sh(p.installCmd, { cwd: dir, env, id, timeoutMs: 15 * 60000 }) !== 0) throw new Error('The install command failed.');
    if (p.buildCmd && await sh(p.buildCmd, { cwd: dir, env, id, timeoutMs: 15 * 60000 }) !== 0) throw new Error('The build command failed.');
    if (p.kind === 'static') {
      const out = resolveOutput(dir, p.outputDir);
      if (!out) throw new Error(`No index.html found in "${p.outputDir || '.'}". Set the correct Output Directory in the project settings.`);
      const st = dirStats(out); quotaCheck(st.bytes);
      log(id, `Uploading ${st.files} files (${fmt(st.bytes)})…`);
      stopService(id);
      await storePut(p, out);
      p.sizeBytes = st.bytes; p.files = st.files;
      rmrf(path.join(WORK, id));
    } else {
      if (!p.startCmd) throw new Error('A start command is required for services.');
      const st = dirStats(dir, ['node_modules']); quotaCheck(st.bytes);
      const old = p.dir; p.dir = dir; p.sizeBytes = st.bytes; p.files = st.files;
      await startService(p);
      if (old && old !== dir) rmrf(old);
    }
    p.lastDeployAt = now(); p.restarts = 0; log(id, '✔ Deployment ready');
    setStatus(p, 'live');
  } catch (e) {
    log(id, '✖ ' + e.message); p.lastError = e.message; setStatus(p, 'failed');
    if (p.dir !== dir) rmrf(dir);
  } finally { p.lastLog = (logBufs.get(id) || []).slice(-500).join('\n').slice(-60000); save(); }
}
async function removeProject(p) {
  stopService(p.id); subs.delete(p.id); logBufs.delete(p.id);
  await storeRemove(p).catch(e => console.error('store remove', e.message));
  setTimeout(() => rmrf(path.join(WORK, p.id)), 3000);
}
function resumeProject(p) { // start a service again after payment / admin resume (rebuilds if its files are gone)
  const o = db.users.find(u => u.id === p.userId);
  if (!isActive(o) || p.adminSuspended || p.kind !== 'service' || p.desired === 'stopped' || procs.has(p.id) || ['queued', 'building'].includes(p.status)) return;
  if (p.dir && fs.existsSync(p.dir)) startService(p).then(() => setStatus(p, 'live')).catch(e => { log(p.id, '✖ ' + e.message); setStatus(p, 'failed'); });
  else enqueueDeploy(p);
}
function boot() { // after a server restart: bring everything back (Render free wipes local files, so we rebuild from GitHub)
  for (const p of db.projects) {
    const o = db.users.find(u => u.id === p.userId);
    if (!isActive(o) || p.adminSuspended) continue;
    if (['queued', 'building'].includes(p.status)) { enqueueDeploy(p); continue; }
    if (p.kind === 'service') { if (p.desired !== 'stopped') resumeProject(p); }
    else if (!R2 && !fs.existsSync(path.join(STATIC, p.id))) enqueueDeploy(p);
  }
}
function enforce() { // stop services of people who did not pay or were suspended
  for (const p of db.projects) {
    if (!procs.has(p.id)) continue;
    const o = db.users.find(u => u.id === p.userId);
    if (!isActive(o) || p.adminSuspended) { log(p.id, 'Stopped: payment expired or suspended by an admin.'); stopService(p.id); }
  }
}

module.exports = { detectConfig, encrypt, decrypt, now, DAY, GB, getPrice, getTrialDays, getStorageGB, isActive, expiry, quotaBytes, usageBytes,
  getLogs, subscribe, log, enqueueDeploy, runDeploy, removeProject, resumeProject, boot, enforce, stopService, startService, isRunning, portOf, startedAt, proxy,
  storeGet, storeMode, setStatus, WORK, STATIC };
