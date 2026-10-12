"use strict";
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const AdmZip = require("adm-zip");
const nodemailer = require("nodemailer");
const { spawn } = require("child_process");
const { EventEmitter } = require("events");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------- config
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET environment variable.");
  process.exit(1);
}
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const BASE_DOMAIN = (process.env.BASE_DOMAIN || "").toLowerCase(); // e.g. mtaanihost.dev
const GH_ID = process.env.GITHUB_CLIENT_ID;
const GH_SECRET = process.env.GITHUB_CLIENT_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const PROJECTS_DIR = path.join(DATA_DIR, "projects");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const RESERVED = new Set(["www", "app", "api", "admin", "mail", "dashboard"]);
fs.mkdirSync(PROJECTS_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------- database
const db = new Database(path.join(DATA_DIR, "host.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  code TEXT,
  github_token TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  repo TEXT,
  branch TEXT,
  kind TEXT NOT NULL DEFAULT 'auto',
  type TEXT,
  root TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued',
  url TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS env_vars (
  project_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (project_id, key)
);`);

const getProject = (id) => db.prepare("SELECT * FROM projects WHERE id = ?").get(id);
const projectDir = (id) => path.join(PROJECTS_DIR, String(id), "src");

// ---------------------------------------------------------------- small helpers
const AES_KEY = crypto.createHash("sha256").update(JWT_SECRET).digest();
function enc(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
  const body = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), body].map((b) => b.toString("base64")).join(".");
}
function dec(text) {
  const [iv, tag, body] = text.split(".").map((x) => Buffer.from(x, "base64"));
  const d = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]).toString("utf8");
}
const signToken = (u) => jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: "30d" });
const cleanEmail = (v) => String(v || "").trim().toLowerCase();

const hits = new Map();
function limit(req, res, next) {
  const now = Date.now();
  const list = (hits.get(req.ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  if (list.length >= 30) return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  list.push(now);
  hits.set(req.ip, list);
  next();
}

// ---------------------------------------------------------------- logs and status (live tail)
const bus = new EventEmitter();
bus.setMaxListeners(0);
const logBuf = new Map(); // projectId -> last 1000 log lines

function log(id, stream, text) {
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const entry = { t: Date.now(), s: stream, m: line.slice(0, 2000) };
    const buf = logBuf.get(id) || [];
    buf.push(entry);
    if (buf.length > 1000) buf.shift();
    logBuf.set(id, buf);
    bus.emit("log:" + id, entry);
  }
}
function setStatus(id, status) {
  db.prepare("UPDATE projects SET status = ? WHERE id = ?").run(status, id);
  bus.emit("status:" + id, status);
}

// ---------------------------------------------------------------- GitHub
async function gh(token, url) {
  const r = await fetch(url.startsWith("http") ? url : "https://api.github.com" + url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "mtaani-host",
    },
    redirect: "follow",
  });
  if (!r.ok) throw new Error(`GitHub error ${r.status}: ${(await r.text()).slice(0, 160)}`);
  return r;
}

// ---------------------------------------------------------------- source handling
function extractZip(buffer, dest) {
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  const entries = new AdmZip(buffer).getEntries().filter((e) => !e.entryName.startsWith("__MACOSX"));
  if (!entries.length) throw new Error("The ZIP file is empty.");
  // GitHub zips and most manual zips wrap everything in one top-level folder: strip it.
  const top = entries[0].entryName.split("/")[0] + "/";
  const strip = entries.every((e) => e.entryName.startsWith(top)) ? top : "";
  const base = path.resolve(dest);
  for (const e of entries) {
    const rel = e.entryName.slice(strip.length);
    if (!rel) continue;
    const target = path.resolve(base, rel);
    if (target !== base && !target.startsWith(base + path.sep)) continue; // zip-slip guard
    if (e.isDirectory) {
      fs.mkdirSync(target, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, e.getData());
    }
  }
}

// Returns the folder (relative to dir) that holds index.html, "" for the root, or null if none.
function findStaticRoot(dir) {
  for (const c of ["", "public", "dist", "build", "docs", "www", "site", "src"]) {
    if (fs.existsSync(path.join(dir, c, "index.html"))) return c;
  }
  for (const d of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!d.isDirectory() || d.name === "node_modules" || d.name.startsWith(".")) continue;
    for (const c of ["", "public", "dist", "build"]) {
      if (fs.existsSync(path.join(dir, d.name, c, "index.html"))) return path.join(d.name, c);
    }
  }
  return null;
}

function detectProject(dir, kind) {
  let pkg = null;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  } catch {}
  const hasStart = !!(pkg && pkg.scripts && pkg.scripts.start);
  const mainExists = !!(pkg && pkg.main && fs.existsSync(path.join(dir, pkg.main)));
  const staticRoot = findStaticRoot(dir);

  let type = kind;
  if (type === "auto") type = hasStart ? "bot" : staticRoot !== null ? "site" : mainExists ? "bot" : null;

  if (type === "bot") {
    if (!hasStart && !mainExists) throw new Error('A bot needs a package.json with a "start" script or an existing "main" file.');
    return { type: "bot", root: "", pkg };
  }
  if (type === "site") {
    if (staticRoot === null) {
      throw new Error("No index.html found (checked the root and public, dist, build, docs, www, site, src). For a bot, add a package.json with a start script.");
    }
    return { type: "site", root: staticRoot };
  }
  throw new Error("Could not tell if this is a website or a bot. Add an index.html or a package.json with a start script.");
}

// ---------------------------------------------------------------- process runner
const procs = new Map(); // projectId -> { child, stopping, restarts, timer, since }

function childEnv(id, dev) {
  // Never pass the platform's own secrets (JWT_SECRET, GitHub secret...) to user code.
  const env = { PATH: process.env.PATH, HOME: process.env.HOME || "/tmp", NODE_ENV: dev ? "development" : "production" };
  for (const r of db.prepare("SELECT key, value FROM env_vars WHERE project_id = ?").all(id)) env[r.key] = r.value;
  return env;
}

function runCmd(id, cmd, cwd) {
  return new Promise((resolve) => {
    const child = spawn(cmd, { cwd, env: childEnv(id, true), shell: true });
    child.stdout.on("data", (d) => log(id, "out", d));
    child.stderr.on("data", (d) => log(id, "err", d));
    child.on("error", (e) => {
      log(id, "err", e.message);
      resolve(1);
    });
    child.on("close", (code) => resolve(code));
  });
}

function startBot(id) {
  const dir = projectDir(id);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const cmd = pkg.scripts && pkg.scripts.start ? "npm start" : `node "${pkg.main}"`;
  const entry = { child: null, stopping: false, restarts: 0, timer: null, since: 0 };
  procs.set(id, entry);

  const launch = () => {
    log(id, "sys", `Starting: ${cmd}`);
    const child = spawn(cmd, { cwd: dir, env: childEnv(id, false), shell: true, detached: true });
    entry.child = child;
    entry.since = Date.now();
    setStatus(id, "running");
    child.stdout.on("data", (d) => log(id, "out", d));
    child.stderr.on("data", (d) => log(id, "err", d));
    child.on("error", (e) => log(id, "err", e.message));
    child.on("close", (code) => {
      if (entry.stopping) return log(id, "sys", "Process stopped.");
      log(id, "sys", `Process exited with code ${code}.`);
      if (Date.now() - entry.since > 60000) entry.restarts = 0; // it ran fine for a while
      if (entry.restarts >= 5) {
        setStatus(id, "crashed");
        return log(id, "sys", "Crashed too many times. Fix the error, then redeploy.");
      }
      entry.restarts++;
      const wait = Math.min(30000, 2000 * entry.restarts);
      setStatus(id, "restarting");
      log(id, "sys", `Restarting in ${wait / 1000}s (attempt ${entry.restarts} of 5)...`);
      entry.timer = setTimeout(launch, wait);
    });
  };
  launch();
}

function stopBot(id, silent) {
  const e = procs.get(id);
  if (!e) return;
  e.stopping = true;
  clearTimeout(e.timer);
  if (e.child && e.child.exitCode === null) {
    try {
      process.kill(-e.child.pid, "SIGTERM"); // kill the whole process group
    } catch {
      e.child.kill();
    }
  }
  procs.delete(id);
  if (!silent) setStatus(id, "stopped");
}

// ---------------------------------------------------------------- domains
const siteUrl = (slug) => (BASE_DOMAIN ? `https://${slug}.${BASE_DOMAIN}` : `${PUBLIC_URL}/sites/${slug}/`);

// Optional: register the subdomain in your separate domain system too.
async function claimDomain(p) {
  if (!process.env.DOMAIN_API_URL || !process.env.DOMAIN_API_KEY) return;
  try {
    const u = db.prepare("SELECT email FROM users WHERE id = ?").get(p.user_id);
    const r = await fetch(process.env.DOMAIN_API_URL.replace(/\/$/, "") + "/api/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": process.env.DOMAIN_API_KEY },
      body: JSON.stringify({ name: p.slug, owner: u.email }),
    });
    const data = await r.json().catch(() => ({}));
    log(p.id, "sys", r.ok ? `Domain registered: ${data.domain || p.slug}` : `Domain system said: ${data.message || r.status}`);
  } catch (e) {
    log(p.id, "sys", "Domain system unreachable: " + e.message);
  }
}

// ---------------------------------------------------------------- deploy pipeline
async function deploy(id) {
  const p = getProject(id);
  const dir = projectDir(id);
  stopBot(id, true);
  logBuf.set(id, []);
  setStatus(id, "building");
  try {
    log(id, "sys", "Getting source code...");
    let zip;
    if (p.source === "github") {
      const u = db.prepare("SELECT github_token FROM users WHERE id = ?").get(p.user_id);
      if (!u || !u.github_token) throw new Error("GitHub is not connected. Connect GitHub and redeploy.");
      const r = await gh(dec(u.github_token), `/repos/${p.repo}/zipball/${p.branch}`);
      zip = Buffer.from(await r.arrayBuffer());
    } else {
      zip = fs.readFileSync(path.join(PROJECTS_DIR, String(id), "source.zip"));
    }
    if (zip.length > 150 * 1024 * 1024) throw new Error("Source is too large (limit 150 MB).");
    extractZip(zip, dir);

    const info = detectProject(dir, p.kind);
    db.prepare("UPDATE projects SET type = ?, root = ? WHERE id = ?").run(info.type, info.root, id);

    if (info.type === "site") {
      log(id, "sys", `Detected a website (folder: ${info.root || "project root"}).`);
      const url = siteUrl(p.slug);
      db.prepare("UPDATE projects SET url = ? WHERE id = ?").run(url, id);
      await claimDomain(p);
      setStatus(id, "live");
      log(id, "sys", `Website is live: ${url}`);
      return;
    }

    log(id, "sys", "Detected a bot / Node app.");
    const pkg = info.pkg || {};
    if (pkg.dependencies || pkg.devDependencies) {
      log(id, "sys", "Installing dependencies...");
      if ((await runCmd(id, "npm install --no-audit --no-fund", dir)) !== 0) throw new Error("npm install failed.");
    }
    if (pkg.scripts && pkg.scripts.build) {
      log(id, "sys", "Running build...");
      if ((await runCmd(id, "npm run build", dir)) !== 0) throw new Error("npm run build failed.");
    }
    startBot(id);
  } catch (e) {
    log(id, "err", "Deploy failed: " + e.message);
    setStatus(id, "failed");
  }
}

function resumeBots() {
  const rows = db.prepare("SELECT id, status FROM projects WHERE type = 'bot' AND status IN ('running','restarting','building')").all();
  for (const { id, status } of rows) {
    if (status === "building") {
      deploy(id);
      continue;
    }
    try {
      startBot(id);
    } catch {
      deploy(id);
    }
  }
}

// ---------------------------------------------------------------- app
const app = express();
app.set("trust proxy", 1);

function serveSite(slug, req, res) {
  const p = db.prepare("SELECT * FROM projects WHERE slug = ? AND type = 'site' AND status = 'live'").get(slug);
  if (!p) return res.status(404).send("This site does not exist or is not live.");
  const root = path.join(projectDir(p.id), p.root);
  express.static(root, { extensions: ["html"], index: "index.html" })(req, res, () => {
    const notFound = path.join(root, "404.html");
    if (fs.existsSync(notFound)) return res.status(404).sendFile(notFound);
    if (!path.extname(req.path)) return res.sendFile(path.join(root, "index.html")); // single-page apps
    res.status(404).send("Not found");
  });
}

// Hosted sites on <slug>.BASE_DOMAIN
app.use((req, res, next) => {
  if (!BASE_DOMAIN) return next();
  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  if (!host.endsWith("." + BASE_DOMAIN)) return next();
  const slug = host.slice(0, -(BASE_DOMAIN.length + 1));
  if (RESERVED.has(slug)) return next();
  serveSite(slug, req, res);
});

// Path mode (testing only): hosted sites share this origin, so use BASE_DOMAIN in production.
if (!BASE_DOMAIN) {
  app.use("/sites/:slug", (req, res) => {
    if (req.path === "/" && !req.originalUrl.split("?")[0].endsWith("/")) return res.redirect(301, req.baseUrl + "/");
    serveSite(req.params.slug, req, res);
  });
}

app.use(express.json({ limit: "1mb" }));
app.get("/health", (req, res) => res.send("ok"));

// ---- auth
const mailer =
  process.env.SMTP_USER && process.env.SMTP_PASS
    ? nodemailer.createTransport({ service: "gmail", auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } })
    : null;

async function issueCode(user) {
  const code = String(crypto.randomInt(100000, 1000000));
  db.prepare("UPDATE users SET code = ? WHERE id = ?").run(code, user.id);
  await mailer.sendMail({
    from: `MtaaniHost <${process.env.SMTP_USER}>`,
    to: user.email,
    subject: "Your MtaaniHost verification code",
    text: `Your verification code is ${code}`,
  });
}

app.post("/api/auth/register", limit, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
    if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) {
      return res.status(409).json({ error: "This email already has an account. Log in instead." });
    }
    const hash = await bcrypt.hash(password, 10);
    const r = db.prepare("INSERT INTO users (email, password_hash, verified, created_at) VALUES (?, ?, ?, ?)").run(email, hash, mailer ? 0 : 1, Date.now());
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(r.lastInsertRowid);
    if (!mailer) return res.json({ token: signToken(user), email });
    await issueCode(user);
    res.json({ needVerify: true, email });
  } catch (e) {
    res.status(500).json({ error: "Could not create the account: " + e.message });
  }
});

app.post("/api/auth/login", limit, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const u = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.password_hash))) {
      return res.status(401).json({ error: "Wrong email or password." });
    }
    if (!u.verified) {
      await issueCode(u);
      return res.json({ needVerify: true, email });
    }
    res.json({ token: signToken(u), email });
  } catch (e) {
    res.status(500).json({ error: "Login failed: " + e.message });
  }
});

app.post("/api/auth/verify", limit, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE email = ?").get(cleanEmail(req.body.email));
  if (!u || !u.code || u.code !== String(req.body.code || "").trim()) return res.status(400).json({ error: "That code is not correct." });
  db.prepare("UPDATE users SET verified = 1, code = NULL WHERE id = ?").run(u.id);
  res.json({ token: signToken(u), email: u.email });
});

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : req.query.token; // query token is for the live log stream
  try {
    const { uid } = jwt.verify(String(token), JWT_SECRET);
    const user = db.prepare("SELECT * FROM users WHERE id = ? AND verified = 1").get(uid);
    if (!user) throw new Error("no user");
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Please log in." });
  }
}

function owned(req, res, next) {
  const p = db.prepare("SELECT * FROM projects WHERE id = ? AND user_id = ?").get(Number(req.params.id), req.user.id);
  if (!p) return res.status(404).json({ error: "Project not found." });
  req.project = p;
  next();
}

app.get("/api/me", auth, (req, res) => res.json({ email: req.user.email, github: !!req.user.github_token }));

// ---- GitHub connect
app.get("/api/github/connect", auth, (req, res) => {
  if (!GH_ID || !GH_SECRET) return res.status(500).json({ error: "GitHub login is not configured on this server." });
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", GH_ID);
  url.searchParams.set("scope", "repo"); // "repo" includes private repositories
  url.searchParams.set("redirect_uri", `${PUBLIC_URL}/auth/github/callback`);
  url.searchParams.set("state", jwt.sign({ uid: req.user.id }, JWT_SECRET, { expiresIn: "10m" }));
  res.json({ url: url.toString() });
});

app.get("/auth/github/callback", async (req, res) => {
  try {
    const { uid } = jwt.verify(String(req.query.state), JWT_SECRET);
    const r = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: GH_ID, client_secret: GH_SECRET, code: req.query.code, redirect_uri: `${PUBLIC_URL}/auth/github/callback` }),
    });
    const data = await r.json();
    if (!data.access_token) throw new Error(data.error_description || "GitHub refused the code");
    db.prepare("UPDATE users SET github_token = ? WHERE id = ?").run(enc(data.access_token), uid);
    res.redirect("/?github=connected");
  } catch {
    res.redirect("/?github=failed");
  }
});

app.get("/api/github/repos", auth, async (req, res) => {
  try {
    if (!req.user.github_token) return res.status(400).json({ error: "GitHub is not connected." });
    const r = await gh(dec(req.user.github_token), "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member");
    const repos = (await r.json()).map((x) => ({ full_name: x.full_name, private: x.private, default_branch: x.default_branch }));
    res.json({ repos });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ---- projects
function makeSlug(name) {
  let base = String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30);
  if (base.length < 3) base += "-site";
  if (RESERVED.has(base)) base += "-site";
  let slug = base;
  while (db.prepare("SELECT 1 FROM projects WHERE slug = ?").get(slug)) slug = base + "-" + crypto.randomBytes(2).toString("hex");
  return slug;
}
function createProject(uid, f) {
  const r = db
    .prepare("INSERT INTO projects (user_id, name, slug, source, repo, branch, kind, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(uid, f.name, makeSlug(f.name), f.source, f.repo || null, f.branch || null, f.kind, Date.now());
  return Number(r.lastInsertRowid);
}
const cleanKind = (k) => (["site", "bot"].includes(k) ? k : "auto");
const cleanName = (n) => String(n || "").trim().slice(0, 60);
const publicProject = (p) => ({ id: p.id, name: p.name, slug: p.slug, source: p.source, repo: p.repo, branch: p.branch, type: p.type, status: p.status, url: p.url, created_at: p.created_at });

app.get("/api/projects", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM projects WHERE user_id = ? ORDER BY id DESC").all(req.user.id);
  res.json({ projects: rows.map(publicProject) });
});

app.post("/api/projects", auth, (req, res) => {
  const name = cleanName(req.body.name);
  const repo = String(req.body.repo || "");
  const branch = String(req.body.branch || "");
  if (!name) return res.status(400).json({ error: "Give the project a name." });
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return res.status(400).json({ error: "Pick a repository." });
  if (!/^[\w./-]+$/.test(branch)) return res.status(400).json({ error: "Invalid branch name." });
  if (!req.user.github_token) return res.status(400).json({ error: "Connect GitHub first." });
  const id = createProject(req.user.id, { name, source: "github", repo, branch, kind: cleanKind(req.body.kind) });
  deploy(id);
  res.json({ project: publicProject(getProject(id)) });
});

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 100 * 1024 * 1024 } });
app.post("/api/projects/upload", auth, upload.single("file"), (req, res) => {
  const name = cleanName(req.body.name);
  if (!req.file) return res.status(400).json({ error: "Choose a ZIP file." });
  if (!name) {
    fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Give the project a name." });
  }
  const id = createProject(req.user.id, { name, source: "upload", kind: cleanKind(req.body.kind) });
  fs.mkdirSync(path.join(PROJECTS_DIR, String(id)), { recursive: true });
  fs.renameSync(req.file.path, path.join(PROJECTS_DIR, String(id), "source.zip"));
  deploy(id);
  res.json({ project: publicProject(getProject(id)) });
});

app.get("/api/projects/:id", auth, owned, (req, res) => res.json({ project: publicProject(req.project) }));

app.post("/api/projects/:id/redeploy", auth, owned, (req, res) => {
  if (req.project.status === "building") return res.status(409).json({ error: "A deploy is already running." });
  deploy(req.project.id);
  res.json({ ok: true });
});

app.post("/api/projects/:id/start", auth, owned, (req, res) => {
  const p = req.project;
  if (p.status === "building") return res.status(409).json({ error: "A deploy is running. Wait for it to finish." });
  if (p.type === "site") {
    setStatus(p.id, "live");
  } else {
    stopBot(p.id, true);
    try {
      startBot(p.id);
    } catch {
      deploy(p.id); // source is missing on disk, fetch it again
    }
  }
  res.json({ ok: true });
});

app.post("/api/projects/:id/stop", auth, owned, (req, res) => {
  stopBot(req.project.id);
  setStatus(req.project.id, "stopped");
  log(req.project.id, "sys", "Stopped by you.");
  res.json({ ok: true });
});

app.delete("/api/projects/:id", auth, owned, (req, res) => {
  const id = req.project.id;
  stopBot(id, true);
  db.prepare("DELETE FROM env_vars WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM projects WHERE id = ?").run(id);
  fs.rmSync(path.join(PROJECTS_DIR, String(id)), { recursive: true, force: true });
  logBuf.delete(id);
  res.json({ ok: true });
});

// ---- environment variables (as many as you want)
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
app.get("/api/projects/:id/env", auth, owned, (req, res) => {
  res.json({ vars: db.prepare("SELECT key, value FROM env_vars WHERE project_id = ? ORDER BY key").all(req.project.id) });
});
app.put("/api/projects/:id/env", auth, owned, (req, res) => {
  const vars = Array.isArray(req.body.vars) ? req.body.vars : [];
  if (vars.length > 100) return res.status(400).json({ error: "Maximum 100 variables." });
  const clean = new Map();
  for (const v of vars) {
    const key = String((v && v.key) || "").trim();
    if (!key) continue;
    if (!KEY_RE.test(key)) return res.status(400).json({ error: `Invalid name "${key}". Use letters, numbers and underscores only.` });
    clean.set(key, String((v && v.value) ?? "").slice(0, 5000));
  }
  db.transaction(() => {
    db.prepare("DELETE FROM env_vars WHERE project_id = ?").run(req.project.id);
    for (const [k, v] of clean) db.prepare("INSERT INTO env_vars (project_id, key, value) VALUES (?, ?, ?)").run(req.project.id, k, v);
  })();
  res.json({ ok: true, count: clean.size });
});

// ---- logs: snapshot + live stream (Server-Sent Events)
app.get("/api/projects/:id/logs", auth, owned, (req, res) => res.json({ logs: logBuf.get(req.project.id) || [] }));

app.get("/api/projects/:id/logs/stream", auth, owned, (req, res) => {
  const id = req.project.id;
  res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  res.flushHeaders();
  const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
  (logBuf.get(id) || []).forEach((e) => send({ type: "log", ...e }));
  send({ type: "status", status: getProject(id).status });
  const onLog = (e) => send({ type: "log", ...e });
  const onStatus = (s) => send({ type: "status", status: s });
  bus.on("log:" + id, onLog);
  bus.on("status:" + id, onStatus);
  const ping = setInterval(() => res.write(": ping\n\n"), 25000);
  req.on("close", () => {
    clearInterval(ping);
    bus.off("log:" + id, onLog);
    bus.off("status:" + id, onStatus);
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Server error." });
});

app.listen(PORT, () => {
  console.log(`MtaaniHost running on port ${PORT}`);
  resumeBots();
});

process.on("SIGTERM", () => {
  for (const id of [...procs.keys()]) stopBot(id, true); // keep status so bots resume on next start
  process.exit(0);
});
