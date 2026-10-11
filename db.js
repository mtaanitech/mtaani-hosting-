const fs = require('fs');
const path = require('path');
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(path.join(DATA, 'projects'), { recursive: true });
const file = path.join(DATA, 'db.json');
let db = { users: [], projects: [], payments: [] };
if (fs.existsSync(file)) {
  try { db = Object.assign(db, JSON.parse(fs.readFileSync(file, 'utf8'))); }
  catch (e) { console.error('db.json imeharibika', e); process.exit(1); }
}
let timer = null;
function flush() {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, file);
}
function save() { clearTimeout(timer); timer = setTimeout(flush, 150); }
process.on('SIGTERM', () => { flush(); process.exit(0); });
process.on('SIGINT', () => { flush(); process.exit(0); });
module.exports = { db, save, flush, DATA };
