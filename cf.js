// Sites za users zinahifadhiwa R2. Worker inazihudumia kwa jina.BASE_DOMAIN
const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const mime = require('mime-types');

const ACC = process.env.CF_ACCOUNT_ID, KEY = process.env.R2_ACCESS_KEY_ID, SECRET = process.env.R2_SECRET_ACCESS_KEY, BUCKET = process.env.R2_BUCKET, DOMAIN = process.env.BASE_DOMAIN;
const enabled = !!(ACC && KEY && SECRET && BUCKET && DOMAIN);
const s3 = enabled ? new S3Client({
  region: 'auto', endpoint: `https://${ACC}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: KEY, secretAccessKey: SECRET },
  requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED'
}) : null;

function walk(dir, base = dir, out = []) {
  for (const n of fs.readdirSync(dir)) {
    if (n.startsWith('.') || n === 'node_modules' || n === '__MACOSX') continue;
    const f = path.join(dir, n), st = fs.statSync(f);
    if (st.isDirectory()) walk(f, base, out);
    else out.push({ file: f, rel: path.relative(base, f).split(path.sep).join('/'), size: st.size });
  }
  return out;
}
function dirStats(dir) {
  try { const l = walk(dir); return { files: l.length, bytes: l.reduce((s, f) => s + f.size, 0) }; }
  catch { return { files: 0, bytes: 0 }; }
}
const put = (Key, Body, ContentType) => s3.send(new PutObjectCommand({ Bucket: BUCKET, Key, Body, ContentType }));
const metaKey = p => `sites/${p.slug}/meta.json`;
const putMeta = (p, status) => put(metaKey(p), JSON.stringify({ status, name: p.name, updatedAt: Date.now() }), 'application/json');

async function createSite(p) {
  const files = walk(p.dir);
  if (files.length > 3000) throw new Error('Files nyingi mno (max 3000)');
  try {
    for (let i = 0; i < files.length; i += 10) {
      await Promise.all(files.slice(i, i + 10).map(f =>
        put(`sites/${p.slug}/files/${f.rel}`, fs.readFileSync(f.file), mime.lookup(f.rel) || 'application/octet-stream')));
    }
    await putMeta(p, 'live');
  } catch (e) { await removeSite(p); throw new Error('Cloudflare R2 upload imeshindwa: ' + e.message); }
}

// suspend/resume ni kuandika meta.json tu
async function setState(p, state) { await putMeta(p, state === 'live' ? 'live' : 'suspended'); }

async function removeSite(p) {
  try {
    let token;
    do {
      const l = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: `sites/${p.slug}/`, ContinuationToken: token }));
      if (l.Contents && l.Contents.length)
        await s3.send(new DeleteObjectsCommand({ Bucket: BUCKET, Delete: { Objects: l.Contents.map(o => ({ Key: o.Key })), Quiet: true } }));
      token = l.IsTruncated ? l.NextContinuationToken : undefined;
    } while (token);
  } catch (e) { console.error('r2 remove', e.message); }
}

module.exports = { enabled, createSite, setState, removeSite, dirStats };
