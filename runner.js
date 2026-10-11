// Inaendesha bots kama child processes
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const procs = new Map();   // projectId -> child
const stopping = new Set();
const logs = new Map();    // projectId -> string[]
const restarts = new Map();
const meta = new Map();
const m = id => { if (!meta.has(id)) meta.set(id, { startedAt: null, crashes: 0, autoRestarts: 0, lastExit: null }); return meta.get(id); };

function log(id, data) {
  const arr = logs.get(id) || [];
  String(data).split(/\r?\n/).filter(Boolean).forEach(l => arr.push(new Date().toISOString().slice(11, 19) + ' ' + l));
  while (arr.length > 300) arr.shift();
  logs.set(id, arr);
}
const getLogs = id => (logs.get(id) || []).join('\n');
const isRunning = id => procs.has(id);

// env safi: HAKUNA siri za server zinazopelekwa kwa bot ya user
function cleanEnv(dir, extra) {
  return { PATH: process.env.PATH, HOME: dir, NODE_ENV: 'production', ...extra };
}

function run(cmd, args, cwd, id, env) {
  return new Promise(resolve => {
    const p = spawn(cmd, args, { cwd, env });
    p.stdout.on('data', d => log(id, d));
    p.stderr.on('data', d => log(id, d));
    p.on('error', e => { log(id, 'Error: ' + e.message); resolve(1); });
    p.on('close', code => resolve(code));
  });
}

async function start(project) {
  const id = project.id;
  if (procs.has(id)) return true;
  const dir = project.dir;
  const env = cleanEnv(dir, project.env || {});
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) { log(id, 'package.json haipo kwenye zip.'); return false; }
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  if (!fs.existsSync(path.join(dir, 'node_modules'))) {
    log(id, '> npm install ...');
    const code = await run('npm', ['install', '--omit=dev', '--no-audit', '--no-fund'], dir, id, env);
    if (code !== 0) { log(id, 'npm install imeshindwa.'); return false; }
  }
  if (procs.has(id)) return true;
  let cmd, args;
  if (pkg.scripts && pkg.scripts.start) { cmd = 'npm'; args = ['start']; }
  else { cmd = 'node'; args = [pkg.main || 'index.js']; }
  log(id, `> ${cmd} ${args.join(' ')}`);
  const child = spawn(cmd, args, { cwd: dir, env });
  procs.set(id, child);
  m(id).startedAt = Date.now();
  child.stdout.on('data', d => log(id, d));
  child.stderr.on('data', d => log(id, d));
  child.on('error', e => log(id, 'Error: ' + e.message));
  child.on('close', code => {
    procs.delete(id);
    const mm = m(id); mm.startedAt = null; mm.lastExit = { code, at: Date.now() };
    if (!stopping.has(id)) mm.crashes++;
    log(id, `Process imeisha (code ${code})`);
    if (stopping.has(id)) { stopping.delete(id); return; }
    const n = (restarts.get(id) || 0) + 1;
    restarts.set(id, n);
    m(id).autoRestarts++;
    if (n <= 5 && project.desired === 'running') {
      log(id, `Inajaribu kuwasha tena (${n}/5) baada ya sekunde 5...`);
      setTimeout(() => { if (project.desired === 'running') start(project); }, 5000);
    }
  });
  setTimeout(() => restarts.set(id, 0), 60000);
  return true;
}

function stop(id) {
  const c = procs.get(id);
  if (!c) return;
  stopping.add(id);
  c.kill('SIGTERM');
  setTimeout(() => { if (procs.has(id)) c.kill('SIGKILL'); }, 5000);
}

function stats(id) {
  const mm = m(id);
  return { running: procs.has(id), startedAt: mm.startedAt, uptimeSec: mm.startedAt ? Math.floor((Date.now() - mm.startedAt) / 1000) : 0, crashes: mm.crashes, autoRestarts: mm.autoRestarts, lastExit: mm.lastExit };
}

module.exports = { start, stop, isRunning, getLogs, log, stats };
