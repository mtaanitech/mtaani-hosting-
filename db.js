// Data layer. With MONGODB_URI the data lives in MongoDB (real, persistent database);
// without it a local JSON file is used (fine for development only: Render free wipes local files).
// All data is kept in memory for fast reads and written through to the database (only changed documents are written).
const fs = require('fs');
const path = require('path');

const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(DATA, { recursive: true });
const FILE = path.join(DATA, 'db.json');
const COLS = ['users', 'projects', 'payments']; // every document has a unique string "id"

const db = { users: [], projects: [], payments: [], settings: {}, pending: {} };
let mode = 'json', cols = {}, hashes = {}, kvHash = {}, timer = null, flushing = null, again = false, client = null;

async function init() {
  if (process.env.MONGODB_URI) {
    const { MongoClient } = require('mongodb');
    client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 15000 });
    await client.connect();
    const d = client.db(process.env.MONGODB_DB || 'mtaanihost');
    for (const c of COLS) {
      cols[c] = d.collection(c);
      db[c] = await cols[c].find({}, { projection: { _id: 0 } }).toArray();
      hashes[c] = new Map(db[c].map(x => [x.id, JSON.stringify(x)]));
    }
    cols.kv = d.collection('kv');
    for (const k of ['settings', 'pending']) {
      const row = await cols.kv.findOne({ _id: k });
      db[k] = row ? row.value : {};
      kvHash[k] = JSON.stringify(db[k]);
    }
    mode = 'mongo';
  } else if (fs.existsSync(FILE)) {
    Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8')));
  }
  return mode;
}

async function flushMongo() {
  for (const c of COLS) {
    const prev = hashes[c], ops = [], next = new Map(), seen = new Set();
    for (const doc of db[c]) {
      seen.add(doc.id);
      const h = JSON.stringify(doc);
      next.set(doc.id, h);
      if (prev.get(doc.id) !== h) ops.push({ replaceOne: { filter: { _id: doc.id }, replacement: { ...doc, _id: doc.id }, upsert: true } });
    }
    for (const id of prev.keys()) if (!seen.has(id)) ops.push({ deleteOne: { filter: { _id: id } } });
    if (ops.length) await cols[c].bulkWrite(ops, { ordered: false });
    hashes[c] = next; // only after the write succeeded, so a failed write is retried next time
  }
  for (const k of ['settings', 'pending']) {
    const h = JSON.stringify(db[k]);
    if (h !== kvHash[k]) { await cols.kv.replaceOne({ _id: k }, { _id: k, value: db[k] }, { upsert: true }); kvHash[k] = h; }
  }
}
function flushJson() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, FILE);
}
async function flush() {
  if (flushing) { again = true; return flushing; }
  flushing = (async () => {
    try { if (mode === 'mongo') await flushMongo(); else flushJson(); }
    catch (e) { console.error('DB write failed (will retry):', e.message); again = true; }
    flushing = null;
    if (again) { again = false; setTimeout(save, 2000); }
  })();
  return flushing;
}
function save() { clearTimeout(timer); timer = setTimeout(flush, 300); }
async function close() { clearTimeout(timer); await flush(); if (flushing) await flushing; if (client) await client.close(); }

module.exports = { db, save, flush, close, init, DATA, mode: () => mode };
