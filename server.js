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
// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const BASE_DOMAIN = (process.env.BASE_DOMAIN || "").toLowerCase().replace(/^\.+|\.+$/g, "");
const GH_ID = process.env.GITHUB_CLIENT_ID;
const GH_SECRET = process.env.GITHUB_CLIENT_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const PROJECTS_DIR = path.join(DATA_DIR, "projects");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const RESERVED = new Set(["www", "app", "api", "admin", "mail", "dashboard"]);

for (const dir of [DATA_DIR, PROJECTS_DIR, UPLOAD_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}
// ---------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------
const db = new Database(path.join(DATA_DIR, "host.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
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
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS env_vars (
  project_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (project_id, key),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
`);
const getProject = (id) => db.prepare("SELECT * FROM projects WHERE id = ?").get(id);
const projectDir = (id) => path.join(PROJECTS_DIR, String(id), "src");
// ---------------------------------------------------------------------
// Helpers and rate limiting
// ---------------------------------------------------------------------
const AES_KEY = crypto.createHash("sha256").update(JWT_SECRET).digest();
function enc(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
  const body = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), body].map((b) => b.toString("base64")).join(".");
}
function dec(value) {
  const parts = String(value).split(".");
  if (parts.length !== 3) throw new Error("Stored GitHub token is invalid. Reconnect GitHub.");
  const [iv, tag, body] = parts.map((part) => Buffer.from(part, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}
const signToken = (user) => jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "30d" });
const cleanEmail = (value) => String(value || "").trim().toLowerCase();
const cleanName = (value) => String(value || "").trim().slice(0, 60);
const cleanKind = (value) => ["site", "bot"].includes(value) ? value : "auto";
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const rateHits = new Map();
function limit(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || "unknown";
  const recent = (rateHits.get(key) || []).filter((time) => now - time < 15 * 60 * 1000);
  if (recent.length >= 30) {
    return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  }
  recent.push(now);
  rateHits.set(key, recent);
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [key, values] of rateHits) {
    const recent = values.filter((time) => now - time < 15 * 60 * 1000);
    if (recent.length) rateHits.set(key, recent);
    else rateHits.delete(key);
  }
}, 10 * 60 * 1000).unref();
// ---------------------------------------------------------------------
// Logs and process status
// ---------------------------------------------------------------------
const bus = new EventEmitter();
bus.setMaxListeners(0);
const logBuf = new Map();
function log(id, stream, value) {
  for (const line of String(value).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const entry = { t: Date.now(), s: stream, m: line.slice(0, 2000) };
    const buffer = logBuf.get(id) || [];
    buffer.push(entry);
    if (buffer.length > 1000) buffer.shift();
    logBuf.set(id, buffer);
    bus.emit("log:" + id, entry);
  }
}
function setStatus(id, status) {
  db.prepare("UPDATE projects SET status = ? WHERE id = ?").run(status, id);
  bus.emit("status:" + id, status);
}
// ---------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------
async function gh(token, url) {
  const response = await fetch(
    url.startsWith("http") ? url : "https://api.github.com" + url,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "mtaani-host",
      },
    }
  );
  if (!response.ok) {
    throw new Error(`GitHub error ${response.status}: ${(await response.text()).slice(0, 160)}`);
  }
  return response;
}
// ---------------------------------------------------------------------
// ZIP extraction and project detection
// ---------------------------------------------------------------------
function extractZip(buffer, destination) {
  fs.rmSync(destination, { recursive: true, force: true });
  fs.mkdirSync(destination, { recursive: true });

const entries = new AdmZip(buffer).getEntries()
    .filter((entry) => !entry.entryName.startsWith("__MACOSX/") && entry.entryName !== "__MACOSX");
if (!entries.length) throw new Error("The ZIP file is empty.");
const first = entries[0].entryName.split("/")[0];
  const top = first ? first + "/" : "";
  const strip = top && entries.every((entry) => entry.entryName.startsWith(top)) ? top : "";
  const base = path.resolve(destination);
for (const entry of entries) {
    const relative = entry.entryName.slice(strip.length);
    if (!relative) continue;
    const target = path.resolve(base, relative);
    if (target !== base && !target.startsWith(base + path.sep)) continue;
if (entry.isDirectory) {
      fs.mkdirSync(target, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, entry.getData());
    }
  }
}
function findStaticRoot(dir) {
  for (const candidate of ["", "public", "dist", "build", "docs", "www", "site", "src"]) {
    if (fs.existsSync(path.join(dir, candidate, "index.html"))) return candidate;
  }
for (const child of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!child.isDirectory() || child.name === "node_modules" || child.name.startsWith(".")) continue;
    for (const candidate of ["", "public", "dist", "build"]) {
      if (fs.existsSync(path.join(dir, child.name, candidate, "index.html"))) {
        return path.join(child.name, candidate, candidate === "" ? "" : "");
      }
    }
  }
  return null;
}
function detectProject(dir, kind) {
  let pkg = null;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
  }
const hasStart = Boolean(pkg && pkg.scripts && pkg.scripts.start);
  const mainExists = Boolean(pkg && pkg.main && fs.existsSync(path.resolve(dir, pkg.main)));
  const staticRoot = findStaticRoot(dir);
  let type = kind;

  if (type === "auto") {
    type = hasStart ? "bot" : staticRoot !== null ? "site" : mainExists ? "bot" : null;
  }
if (type === "bot") {
    if (!pkg || (!hasStart && !mainExists)) {
      throw new Error('A bot needs a package.json with a "start" script or a valid "main" file.');
    }
    return { type: "bot", root: "", pkg };
  }
if (type === "site") {
    if (staticRoot === null) {
      throw new Error("No index.html found. Put it in the root or public/dist/build/docs/www/site/src folder.");
    }
    return { type: "site", root: staticRoot, pkg };
  }
throw new Error("Could not identify this project. Add index.html for a website or package.json with a start script for a bot.");
}
// ---------------------------------------------------------------------
// User project processes
// ---------------------------------------------------------------------
const procs = new Map();
function childEnv(id, development = false) {
  const env = {
    PATH: process.env.PATH || "",
    HOME: process.env.HOME || "/tmp",
    NODE_ENV: development ? "development" : "production",
  };
for (const item of db.prepare("SELECT key, value FROM env_vars WHERE project_id = ?").all(id)) {
    if (KEY_RE.test(item.key)) env[item.key] = item.value;
  }
  return env;
}
function runCmd(id, command, cwd) {
  return new Promise((resolve) => {
    const child = spawn(command, {
      cwd,
      env: childEnv(id, true),
      shell: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (data) => log(id, "out", data));
    child.stderr.on("data", (data) => log(id, "err", data));
    child.on("error", (error) => {
      log(id, "err", error.message);
      resolve(1);
    });
    child.on("close", (code) => resolve(code === 0 ? 0 : (code || 1)));
  });
}
function startBot(id) {
  if (procs.has(id)) stopBot(id, true);
const dir = projectDir(id);
  const packagePath = path.join(dir, "package.json");
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  } catch {
    throw new Error("Could not read the project's package.json.");
  }
const command = pkg.scripts && pkg.scripts.start
    ? "npm start"
    : `node "${String(pkg.main || "").replace(/"/g, '\\"')}"`;
if (!pkg.scripts?.start && (!pkg.main || !fs.existsSync(path.resolve(dir, pkg.main)))) {
    throw new Error('The project needs a valid "start" script or "main" file.');
  }
const entry = { child: null, stopping: false, restarts: 0, timer: null, since: 0 };
  procs.set(id, entry);
const launch = () => {
    if (entry.stopping) return;
    log(id, "sys", `Starting: ${command}`);
    const child = spawn(command, {
      cwd: dir,
      env: childEnv(id),
      shell: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    entry.child = child;
    entry.since = Date.now();    child.stdout.on("data", (data) => log(id, "out", data));
    child.stderr.on("data", (data) => log(id, "err", data));
child.on("error", (error) => {
      log(id, "err", error.message);
      if (!entry.stopping) setStatus(id, "error");
    });
child.on("close", (code) => {
      if (entry.child === child) entry.child = null;
      if (entry.stopping) return;
if (code === 0) {
        log(id, "sys", "Process exited.");
        setStatus(id, "stopped");
        return;
      }
log(id, "sys", `Process exited with code ${code}.`);
      if (entry.restarts < 3) {
        entry.restarts += 1;
        setStatus(id, "restarting");
        entry.timer = setTimeout(launch, 3000);
      } else {
        setStatus(id, "error");
        log(id, "sys", "Restart limit reached.");
        procs.delete(id);
      }
    });
setStatus(id, "running");
  };
launch();
}
function stopBot(id, silent = false) {
  const entry = procs.get(id);
  if (!entry) {
    if (!silent) setStatus(id, "stopped");
    return;
  }
entry.stopping = true;
  if (entry.timer) clearTimeout(entry.timer);
const child = entry.child;
  if (child && !child.killed) {
    try {
      if (process.platform !== "win32" && child.pid) {
        process.kill(-child.pid, "SIGTERM");
      } else {
        child.kill("SIGTERM");
      }
    } catch {
      try {
        child.kill("SIGTERM");
      } catch {}
    }
  }
procs.delete(id);
  if (!silent) setStatus(id, "stopped");
}
// ---------------------------------------------------------------------
// Express app and middleware
// ---------------------------------------------------------------------
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== ".zip") {
      return cb(new Error("Upload a ZIP file."));
    }
    cb(null, true);
  },
});
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
if (!token) return res.status(401).json({ error: "Please log in." });
try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare("SELECT id, email, verified FROM users WHERE id = ?")
      .get(payload.uid);
if (!user) return res.status(401).json({ error: "Account not found." });
req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Please log in again." });
  }
}
function ownedProject(req, res, next) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid project ID." });
  }
const project = db.prepare(
    "SELECT * FROM projects WHERE id = ? AND user_id = ?"
  ).get(id, req.user.id);

  if (!project) return res.status(404).json({ error: "Project not found." });

  req.project = project;
  next();
}
// ---------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "MtaaniHost V2",
    time: new Date().toISOString(),
  });
});
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
// ---------------------------------------------------------------------
// Registration and login
// ---------------------------------------------------------------------
async function registerHandler(req, res) {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Password must be 8–128 characters." });
    }
const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing) return res.status(409).json({ error: "Email is already registered." });
const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `).run(email, passwordHash, Date.now());
const user = { id: Number(result.lastInsertRowid), email };
    res.status(201).json({
      message: "Account created.",
      token: signToken(user),
      user,
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Email is already registered." });
    }
    console.error("Registration error:", error);
    res.status(500).json({ error: "Could not create account." });
  }
}
async function loginHandler(req, res) {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");
const user = db.prepare(
      "SELECT id, email, password_hash FROM users WHERE email = ?"
    ).get(email);
if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }
res.json({
      message: "Login successful.",
      token: signToken(user),
      user: { id: user.id, email: user.email },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Could not log in." });
  }
}
app.post("/api/auth/register", limit, registerHandler);
app.post("/api/auth/signup", limit, registerHandler);
app.post("/api/auth/login", limit, loginHandler);

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ user: req.user });
});
// ---------------------------------------------------------------------
// GitHub OAuth
// ---------------------------------------------------------------------
app.get("/api/github/connect", auth, (req, res) => {
  if (!GH_ID || !GH_SECRET) {
    return res.status(503).json({ error: "GitHub OAuth is not configured." });
  }
const state = crypto.randomBytes(24).toString("hex");
  const callback = `${PUBLIC_URL}/api/github/callback`;
  const url = new URL("https://github.com/login/oauth/authorize");
url.searchParams.set("client_id", GH_ID);
  url.searchParams.set("redirect_uri", callback);
  url.searchParams.set("scope", "repo");
  url.searchParams.set("state", state);
res.json({ url: url.toString(), state });
});
app.get("/api/github/login", (req, res) => {
  if (!GH_ID) {
    return res.status(503).send("GitHub OAuth is not configured.");
  }
const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", GH_ID);
  url.searchParams.set("redirect_uri", `${PUBLIC_URL}/api/github/callback`);
  url.searchParams.set("scope", "repo");
res.redirect(url.toString());
});
app.get("/api/github/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    if (!code) return res.status(400).send("Missing GitHub authorization code.");
if (!GH_ID || !GH_SECRET) {
      return res.status(503).send("GitHub OAuth is not configured.");
    }
const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: GH_ID,
        client_secret: GH_SECRET,
        code,
      }),
    });
const data = await response.json();
    if (!response.ok || !data.access_token) {
      return res.status(400).send("GitHub connection failed. Try again.");
    }
res.send(
      "<!doctype html><html><head><meta charset='utf-8'><title>GitHub</title></head>" +
      "<body><h2>GitHub authorized</h2>" +
      "<p>Authorization succeeded, but secure account linking requires a logged-in session.</p>" +
      "<p>You can close this window.</p></body></html>"
    );
  } catch (error) {
    console.error("GitHub callback error:", error);
    res.status(500).send("GitHub connection failed.");
  }
});
// ---------------------------------------------------------------------
// Projects API
// ---------------------------------------------------------------------
app.get("/api/projects", auth, (req, res) => {
  const projects = db.prepare(`
    SELECT id, name, slug, source, repo, branch, kind, type, root,
           status, url, created_at
    FROM projects
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(req.user.id);
res.json({ projects });
});
app.get("/api/projects/:id", auth, ownedProject, (req, res) => {
  res.json({ project: req.project });
});
app.post("/api/projects", auth, (req, res) => {
  const name = cleanName(req.body.name);
  const source = String(req.body.source || "upload");
  const kind = cleanKind(req.body.kind || req.body.type);
if (!name) return res.status(400).json({ error: "Project name is required." });
const slug = crypto.randomBytes(8).toString("hex");
  const result = db.prepare(`
    INSERT INTO projects
      (user_id, name, slug, source, kind, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'queued', ?)
  `).run(req.user.id, name, slug, source, kind, Date.now());
const id = Number(result.lastInsertRowid);
  fs.mkdirSync(projectDir(id), { recursive: true });
res.status(201).json({ project: getProject(id) });
});
app.post("/api/projects/upload", auth, upload.single("file"), (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Choose a ZIP file to upload." });
    }
const name = cleanName(req.body.name || path.basename(req.file.originalname, ".zip"));
    const kind = cleanKind(req.body.kind || req.body.type);
    if (!name) return res.status(400).json({ error: "Project name is required." });
const slug = crypto.randomBytes(8).toString("hex");
    const result = db.prepare(`
      INSERT INTO projects
        (user_id, name, slug, source, kind, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'queued', ?)
    `).run(req.user.id, name, slug, "upload", kind, Date.now());
const id = Number(result.lastInsertRowid);
    const dir = projectDir(id);
     try{
      extractZip(req.file.buffer, dir);
      const detected = detectProject(dir, kind);
db.prepare(`
        UPDATE projects SET type = ?, root = ?, status = ? WHERE id = ?
      `).run(detected.type, detected.root, "ready", id);
res.status(201).json({ project: getProject(id) });
    } catch (error) {
      db.prepare("DELETE FROM projects WHERE id = ?").run(id);
      fs.rmSync(path.dirname(dir), { recursive: true, force: true });
      throw error;
    }
  } catch (error) {
    next(error);
  }
});
// ---------------------------------------------------------------------
// Deploy / start project
// ---------------------------------------------------------------------
app.post("/api/projects/:id/deploy", auth, ownedProject, async (req, res, next) => {
  try {
    const project = req.project;
    const dir = projectDir(project.id);
if (project.type === "site") {
      const detected = detectProject(dir, "site");
      const url = `${PUBLIC_URL}/sites/${project.slug}/`;
db.prepare(`
        UPDATE projects SET type = 'site', root = ?, status = 'running', url = ?
        WHERE id = ?
      `).run(detected.root, url, project.id);
return res.json({ message: "Website deployed.", project: getProject(project.id) });
    }
const detected = detectProject(dir, "bot");
if (detected.pkg.dependencies || detected.pkg.devDependencies) {
      const installCode = await runCmd(project.id, "npm install --omit=dev", dir);
      if (installCode !== 0) {
        setStatus(project.id, "error");
        return res.status(500).json({ error: "npm install failed. Check project logs." });
      }
    }
startBot(project.id);
    res.json({ message: "Bot started.", project: getProject(project.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/projects/:id/stop", auth, ownedProject, (req, res) => {
  stopBot(req.project.id);
  res.json({ message: "Project stopped.", project: getProject(req.project.id) });
});
app.post("/api/projects/:id/restart", auth, ownedProject, (req, res, next) => {
  try {
    if (req.project.type !== "bot") {
      return res.status(400).json({ error: "Only bot projects can be restarted." });
    }
    stopBot(req.project.id, true);
    startBot(req.project.id);
    res.json({ message: "Project restarted.", project: getProject(req.project.id) });
  } catch (error) {
    next(error);
  }
});
// ---------------------------------------------------------------------
// Project logs
// ---------------------------------------------------------------------
app.get("/api/projects/:id/logs", auth, ownedProject, (req, res) => {
  const limitCount = Math.max(1, Math.min(500, Number(req.query.limit) || 100));
  const entries = (logBuf.get(req.project.id) || []).slice(-limitCount);
  res.json({ logs: entries });
});
// ---------------------------------------------------------------------
// Project environment variables
// ---------------------------------------------------------------------
app.get("/api/projects/:id/env", auth, ownedProject, (req, res) => {
  const vars = db.prepare(`
    SELECT key, value FROM env_vars WHERE project_id = ? ORDER BY key
  `).all(req.project.id);
res.json({ env: vars });
});
app.put("/api/projects/:id/env", auth, ownedProject, (req, res) => {
  const vars = req.body.env;
if (!vars || typeof vars !== "object" || Array.isArray(vars)) {
    return res.status(400).json({ error: "Send env as an object of key/value pairs." });
  }
const entries = Object.entries(vars);
  if (entries.length > 100) {
    return res.status(400).json({ error: "Maximum 100 environment variables per project." });
  }
for (const [key, value] of entries) {
    if (!KEY_RE.test(key) || key.length > 128) {
      return res.status(400).json({ error: `Invalid environment variable name: ${key}` });
    }
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
      return res.status(400).json({ error: `Invalid value for ${key}.` });
    }
    if (String(value).length > 10000) {
      return res.status(400).json({ error: `Value for ${key} is too long.` });
    }
  }
const save = db.transaction(() => {
    for (const [key, value] of entries) {
      db.prepare(`
        INSERT INTO env_vars (project_id, key, value)
        VALUES (?, ?, ?)
        ON CONFLICT(project_id, key) DO UPDATE SET value = excluded.value
      `).run(req.project.id, key, String(value));
    }
  });
 save();
  res.json({ message: "Environment variables saved." });
});
app.delete("/api/projects/:id/env/:key", auth, ownedProject, (req, res) => {
  db.prepare("DELETE FROM env_vars WHERE project_id = ? AND key = ?")
    .run(req.project.id, req.params.key);
  res.json({ message: "Environment variable deleted." });
});
// ---------------------------------------------------------------------
// Delete project
// ---------------------------------------------------------------------
app.delete("/api/projects/:id", auth, ownedProject, (req, res) => {
  const id = req.project.id;
 stopBot(id, true);
  db.prepare("DELETE FROM projects WHERE id = ?").run(id);
  fs.rmSync(path.dirname(projectDir(id)), { recursive: true, force: true });

  logBuf.delete(id);
  res.json({ message: "Project deleted." });
});
// ---------------------------------------------------------------------
// Serve deployed static websites
// ---------------------------------------------------------------------
app.get("/sites/:slug/*", (req, res, next) => {
  const project = db.prepare(`
    SELECT * FROM projects
    WHERE slug = ? AND type = 'site' AND status = 'running'
  `).get(req.params.slug);
if (!project) return res.status(404).send("Website not found.");
const root = path.resolve(projectDir(project.id), project.root || "");
  const requested = req.params[0] || "index.html";
  const file = path.resolve(root, requested);
if (file !== root && !file.startsWith(root + path.sep)) {
    return res.status(403).send("Forbidden.");
  }
if (fs.existsSync(file) && fs.statSync(file).isFile()) {
    return res.sendFile(file);
  }
const index = path.join(root, "index.html");
  if (fs.existsSync(index)) return res.sendFile(index);
  next();
});
app.get("/sites/:slug", (req, res) => {
  res.redirect(`/sites/${encodeURIComponent(req.params.slug)}/`);
});
// ---------------------------------------------------------------------
// Email configuration status
// ---------------------------------------------------------------------
app.get("/api/status", (req, res) => {
  res.json({
    service: "MtaaniHost V2",
    status: "online",
    githubConfigured: Boolean(GH_ID && GH_SECRET),
    emailConfigured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER),
  });
});
// ---------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});
app.use((error, req, res, next) => {
  console.error("Request error:", error);
if (res.headersSent) return next(error);
if (error instanceof multer.MulterError) {
    return res.status(400).json({ error: error.message });
  }
if (error.message === "Upload a ZIP file.") {
    return res.status(400).json({ error: error.message });
  }
 res.status(500).json({
    error: error.message || "Internal server error.",
  });
});
// ---------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`MtaaniHost V2 running on port ${PORT}`);
  console.log(`Health check: ${PUBLIC_URL}/health`);
});
function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  for (const id of [...procs.keys()]) {
    stopBot(id, true);
  }
 server.close(() => {
    try {
      db.close();
    } catch (error) {
      console.error("Database close error:", error.message);
    }
    process.exit(0);
  });
setTimeout(() => process.exit(1), 10000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("unhandledRejection", (error) => {
  console.error("Unhandled rejection:", error);
});
process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});
