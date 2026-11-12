const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PASSWORD = process.env.PASSWORD || 'E123';
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES = path.join(DATA, 'files');
fs.mkdirSync(FILES, { recursive: true });
const META = path.join(DATA, 'meta.json');
const sha = s => crypto.createHash('sha256').update(s).digest();
const TOKEN = crypto.createHmac('sha256', process.env.SECRET || 'secret:' + PASSWORD).update('ok').digest('hex');

let meta = [];
try { meta = JSON.parse(fs.readFileSync(META, 'utf8')); } catch {}
const save = () => { fs.writeFileSync(META + '.tmp', JSON.stringify(meta)); fs.renameSync(META + '.tmp', META); };
const fp = (id, ext) => path.join(FILES, id + '.' + ext);
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ---- auth ----
const attempts = new Map();
app.post('/api/login', express.json(), (req, res) => {
  const ip = req.ip, a = attempts.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 10 * 60e3) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 10) return res.status(429).json({ error: 'تلاش زیاد! چند دقیقه صبر کن' });
  const ok = crypto.timingSafeEqual(sha(String(req.body?.password ?? '')), sha(PASSWORD));
  if (!ok) { a.n++; attempts.set(ip, a); return res.status(401).json({ error: 'رمز اشتباهه' }); }
  attempts.delete(ip);
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `auth=${TOKEN}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}${secure}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'auth=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});
const auth = (req, res, next) => {
  const m = /(?:^|;\s*)auth=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (m && safeEq(m[1], TOKEN)) return next();
  res.status(401).json({ error: 'unauthorized' });
};

app.use(express.static(path.join(__dirname, 'public')));

// ---- files ----
app.get('/api/files', auth, (req, res) => {
  res.json({ files: [...meta].reverse(), total: meta.reduce((s, f) => s + f.size, 0) });
});

const upload = multer({
  storage: multer.diskStorage({
    destination: FILES,
    filename: (req, file, cb) => {
      req.fid = req.fid || crypto.randomBytes(8).toString('hex');
      cb(null, req.fid + '.' + (file.fieldname === 'thumb' ? 'jpg' : 'dat'));
    }
  })
}).fields([{ name: 'file', maxCount: 1 }, { name: 'thumb', maxCount: 1 }]);

app.post('/api/upload', auth, (req, res) => {
  let finished = false;
  req.on('aborted', () => { if (!finished && req.fid) { fs.rm(fp(req.fid, 'dat'), () => {}); fs.rm(fp(req.fid, 'jpg'), () => {}); } });
  upload(req, res, err => {
    finished = true;
    if (err || !req.files?.file) return res.status(400).json({ error: err?.message || 'فایلی نیومد' });
    const f = req.files.file[0];
    const item = {
      id: req.fid,
      name: String(req.body.name || 'file').slice(0, 200),
      size: f.size,
      mime: String(req.body.mime || 'application/octet-stream').slice(0, 100),
      thumb: !!req.files.thumb,
      added: Date.now()
    };
    meta.push(item); save();
    res.json(item);
  });
});

const find = id => meta.find(f => f.id === id);
app.get('/f/:id', auth, (req, res) => {
  const f = find(req.params.id);
  if (!f) return res.sendStatus(404);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', 'sandbox');
  if (req.query.dl) res.attachment(f.name); // attachment sets filename*=UTF-8 safely
  res.setHeader('Content-Type', f.mime); // Range requests (seeking) handled by sendFile
  res.sendFile(fp(f.id, 'dat'));
});
app.get('/t/:id', auth, (req, res) => {
  const f = find(req.params.id);
  if (!f || !f.thumb) return res.sendStatus(404);
  res.setHeader('Cache-Control', 'private, max-age=31536000');
  res.type('jpg').sendFile(fp(f.id, 'jpg'));
});
app.delete('/api/files/:id', auth, (req, res) => {
  const f = find(req.params.id);
  if (!f) return res.sendStatus(404);
  meta = meta.filter(x => x.id !== f.id); save();
  fs.rm(fp(f.id, 'dat'), () => {}); fs.rm(fp(f.id, 'jpg'), () => {});
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Uploader running'));
