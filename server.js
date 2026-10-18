// First run:  ADMIN_USER=owner ADMIN_PASSWORD='a-long-password' node server.js   (Node 18+, no npm install)
// More users: node createuser.js <username> <password>
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';           // set to 1 behind nginx / a load balancer
const DB = path.join(__dirname, 'data', 'properties.json');
const USERS = path.join(__dirname, 'data', 'users.json');
const PUBLIC = path.join(__dirname, 'public'), VIEWS = path.join(__dirname, 'views');
const CATEGORIES = ['Commercial Building', 'Villa', 'Apartment', 'Land', 'Other'];
const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml' };
const SESSION_MS = 8 * 3600e3, MAX_FAILS = 5, LOCK_MS = 15 * 60e3;

fs.mkdirSync(path.dirname(DB), { recursive: true });
if (!fs.existsSync(DB)) fs.writeFileSync(DB, JSON.stringify([
  { id: 'p1', title: 'Palm Grove Villa', category: 'Villa', price: 18500000, location: 'Kannur', beds: 4, area: 3200, status: 'Available', image: '', description: 'Four-bedroom villa with a private garden and covered parking.' },
  { id: 'p2', title: 'Harbour Road Commercial Block', category: 'Commercial Building', price: 42000000, location: 'Kannur', beds: 0, area: 9000, status: 'Available', image: '', description: 'Three-floor commercial building on a main road, ready for tenants.' }
], null, 2));

// ---------- users (scrypt-hashed passwords) ----------
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 64).toString('hex');
const loadUsers = () => fs.existsSync(USERS) ? JSON.parse(fs.readFileSync(USERS, 'utf8')) : [];
if (!loadUsers().length) {
  const user = (process.env.ADMIN_USER || 'admin').toLowerCase();
  let pw = process.env.ADMIN_PASSWORD;
  if (!pw) { pw = crypto.randomBytes(12).toString('base64url'); console.log(`\nNo ADMIN_PASSWORD set. Created user "${user}" with password: ${pw}\nSave it now, it is shown only once.\n`); }
  const salt = crypto.randomBytes(16).toString('hex');
  fs.writeFileSync(USERS, JSON.stringify([{ username: user, salt, hash: hashPw(pw, salt) }], null, 2), { mode: 0o600 });
}
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
function checkLogin(username, password) {
  const u = loadUsers().find(x => x.username === String(username).toLowerCase().trim());
  const h = Buffer.from(hashPw(password, u ? u.salt : DUMMY_SALT), 'hex');   // always hash: no timing hint about valid usernames
  return !!u && crypto.timingSafeEqual(h, Buffer.from(u.hash, 'hex')) ? u.username : null;
}

// ---------- sessions + brute-force lock ----------
const sessions = new Map(), fails = new Map();
const ip = req => (TRUST_PROXY && req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const getCookie = (req, n) => (new RegExp('(?:^|; )' + n + '=([\\w-]+)').exec(req.headers.cookie || '') || [])[1];
const cookie = req => getCookie(req, 'sid');
const sessionOf = req => { const s = sessions.get(cookie(req)); if (s && s.exp > Date.now()) return s; sessions.delete(cookie(req)); return null; };
const secure = req => process.env.COOKIE_SECURE === '1' || req.headers['x-forwarded-proto'] === 'https';
setInterval(() => { const t = Date.now(); sessions.forEach((s, k) => s.exp < t && sessions.delete(k)); fails.forEach((f, k) => f.until < t && f.count >= MAX_FAILS && fails.delete(k)); }, 600e3).unref();

// ---------- 2-step verification: code emailed to ONE allowed Gmail address ----------
const ALLOWED_EMAIL = (process.env.ALLOWED_EMAIL || 'mohdnihalvdev@gmail.com').toLowerCase();
const SMTP_USER = process.env.SMTP_USER, SMTP_PASS = process.env.SMTP_PASS;   // Gmail address + Google App Password
const CODE_MS = 10 * 60e3, MAX_TRIES = 5, MAX_SENDS = 3, RESEND_MS = 30e3;
let mailer = null;
if (SMTP_USER && SMTP_PASS) {
  try { mailer = require('nodemailer').createTransport({ service: 'gmail', auth: { user: SMTP_USER, pass: SMTP_PASS } }); }
  catch { console.log('\nSMTP is set but nodemailer is missing. Run: npm install\n'); }
} else console.log('\nSMTP_USER / SMTP_PASS not set: login codes will be printed here in the console instead of emailed.\n');
const pending = new Map();
const hashCode = (salt, code) => crypto.createHash('sha256').update(salt + code).digest('hex');
const mask = e => e.replace(/^(.{2}).*(@.*)$/, '$1••••••$2');
async function sendCode(pend) {
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  pend.salt = crypto.randomBytes(8).toString('hex'); pend.hash = hashCode(pend.salt, code);
  pend.exp = Date.now() + CODE_MS; pend.tries = 0; pend.sends++; pend.last = Date.now();
  const text = `Your MAV Estate admin login code is ${code}.\nIt expires in 10 minutes. If you did not try to log in, ignore this email and change your password.`;
  if (!mailer) return console.log(`[dev] login code for ${pend.user}: ${code}`);
  await mailer.sendMail({ from: `"MAV Estate" <${SMTP_USER}>`, to: ALLOWED_EMAIL, subject: `${code} is your MAV Estate login code`, text });
}
setInterval(() => { const t = Date.now(); pending.forEach((p, k) => p.exp < t && pending.delete(k)); }, 600e3).unref();

// ---------- helpers ----------
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' };
const read = () => JSON.parse(fs.readFileSync(DB, 'utf8'));
const write = d => fs.writeFileSync(DB, JSON.stringify(d, null, 2));
const json = (res, code, obj, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...SEC, ...h }); res.end(JSON.stringify(obj)); };
const body = req => new Promise((ok, no) => {
  let s = ''; req.on('data', c => { s += c; if (s.length > 6e6) { no(new Error('Too large')); req.destroy(); } });
  req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch (e) { no(e); } });
});
const sendFile = (res, full, extra = {}) => { res.writeHead(200, { 'Content-Type': TYPES[path.extname(full)] || 'application/octet-stream', ...SEC, ...extra }); fs.createReadStream(full).pipe(res); };
const clean = b => ({
  title: String(b.title || '').trim().slice(0, 120),
  category: CATEGORIES.includes(b.category) ? b.category : 'Other',
  price: Math.max(0, Number(b.price) || 0), location: String(b.location || '').trim().slice(0, 120),
  beds: Math.max(0, parseInt(b.beds) || 0), area: Math.max(0, Number(b.area) || 0),
  status: ['Available', 'Sold'].includes(b.status) ? b.status : 'Available',
  image: /^(data:image\/(jpeg|png|webp);base64,|https?:\/\/)/.test(b.image || '') ? b.image : '',
  description: String(b.description || '').trim().slice(0, 2000)
});

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname, me = sessionOf(req);
  try {
    // CSRF defence in depth: state-changing calls must be same-origin JSON
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const o = req.headers.origin;
      if (o && new URL(o).host !== req.headers.host) return json(res, 403, { error: 'Blocked' });
    }
    // ---- admin pages: server-side gate ----
    if (p === '/admin/login') {
      if (me) { res.writeHead(302, { Location: '/admin' }); return res.end(); }
      return sendFile(res, path.join(VIEWS, 'login.html'), { 'Cache-Control': 'no-store' });
    }
    if (p === '/admin' || p === '/admin/') {
      if (!me) { res.writeHead(302, { Location: '/admin/login' }); return res.end(); }
      return sendFile(res, path.join(VIEWS, 'admin.html'), { 'Cache-Control': 'no-store' });
    }
    // ---- API ----
    if (p === '/api/properties' && req.method === 'GET') { const c = url.searchParams.get('category'); return json(res, 200, read().filter(x => !c || x.category === c)); }
    if (p === '/api/categories') return json(res, 200, CATEGORIES);
    if (p === '/api/me') return json(res, me ? 200 : 401, me ? { admin: true, user: me.user } : { admin: false });
    if (p === '/api/login' && req.method === 'POST') {
      const k = ip(req), f = fails.get(k) || { count: 0, until: 0 };
      if (f.count >= MAX_FAILS && f.until > Date.now()) return json(res, 429, { error: `Too many attempts. Try again in ${Math.ceil((f.until - Date.now()) / 60000)} minutes.` });
      if (f.count >= MAX_FAILS) f.count = 0;
      const { username, password } = await body(req);
      const user = checkLogin(username || '', password || '');
      if (!user) { f.count++; f.until = Date.now() + LOCK_MS; fails.set(k, f); return json(res, 401, { error: 'Incorrect username or password.' }); }
      const pid = crypto.randomBytes(32).toString('hex');
      const pend = { user, sends: 0, last: 0, tries: 0, exp: 0, hash: '', salt: '' };
      pending.set(pid, pend);
      try { await sendCode(pend); }
      catch (e) { pending.delete(pid); console.log('Mail error:', e.message); return json(res, 502, { error: 'Could not send the verification email. Check the SMTP settings on the server.' }); }
      return json(res, 200, { step: 'code', email: mask(ALLOWED_EMAIL) }, { 'Set-Cookie': `pid=${pid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=600${secure(req) ? '; Secure' : ''}` });
    }
    if ((p === '/api/verify' || p === '/api/resend') && req.method === 'POST') {
      const pid = getCookie(req, 'pid'), pend = pending.get(pid);
      if (!pend || pend.exp < Date.now() && p === '/api/verify') { pending.delete(pid); return json(res, 401, { error: 'Code expired. Please log in again.', restart: true }); }
      if (p === '/api/resend') {
        if (pend.sends >= MAX_SENDS) { pending.delete(pid); return json(res, 429, { error: 'Too many codes requested. Please log in again.', restart: true }); }
        if (Date.now() - pend.last < RESEND_MS) return json(res, 429, { error: 'Please wait a few seconds before asking for another code.' });
        try { await sendCode(pend); } catch { return json(res, 502, { error: 'Could not send the verification email.' }); }
        return json(res, 200, { ok: true });
      }
      const { code } = await body(req), k = ip(req);
      const good = Buffer.from(pend.hash, 'hex'), got = Buffer.from(hashCode(pend.salt, String(code || '').trim()), 'hex');
      if (++pend.tries > MAX_TRIES || !crypto.timingSafeEqual(good, got)) {
        const f = fails.get(k) || { count: 0, until: 0 }; f.count++; f.until = Date.now() + LOCK_MS; fails.set(k, f);
        if (pend.tries >= MAX_TRIES) { pending.delete(pid); return json(res, 401, { error: 'Too many wrong codes. Please log in again.', restart: true }); }
        return json(res, 401, { error: `Incorrect code. ${MAX_TRIES - pend.tries} tries left.` });
      }
      pending.delete(pid); fails.delete(k);
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { user: pend.user, exp: Date.now() + SESSION_MS });
      const flags = `HttpOnly; SameSite=Strict; Path=/${secure(req) ? '; Secure' : ''}`;
      return json(res, 200, { ok: true }, { 'Set-Cookie': [`sid=${sid}; ${flags}; Max-Age=${SESSION_MS / 1000}`, `pid=; ${flags}; Max-Age=0`] });
    }
    if (p === '/api/logout' && req.method === 'POST') { sessions.delete(cookie(req)); return json(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }); }
    if (p === '/api/properties' && req.method === 'POST') {
      if (!me) return json(res, 401, { error: 'Login required' });
      const item = { id: crypto.randomUUID(), ...clean(await body(req)) };
      if (!item.title) return json(res, 400, { error: 'Title is required' });
      const all = read(); all.unshift(item); write(all); return json(res, 201, item);
    }
    const del = /^\/api\/properties\/([\w-]+)$/.exec(p);
    if (del && req.method === 'DELETE') {
      if (!me) return json(res, 401, { error: 'Login required' });
      write(read().filter(x => x.id !== del[1])); return json(res, 200, { ok: true });
    }
    // ---- public site (only the public/ folder is ever served) ----
    const full = path.join(PUBLIC, p === '/' ? 'index.html' : p.slice(1));
    if (!full.startsWith(PUBLIC + path.sep) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) { res.writeHead(404, SEC); return res.end('Not found'); }
    sendFile(res, full);
  } catch (e) { json(res, 400, { error: 'Bad request' }); }
}).listen(PORT, () => console.log(`Site: http://localhost:${PORT}   Admin: http://localhost:${PORT}/admin`));
