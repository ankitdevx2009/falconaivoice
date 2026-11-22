// Voice Studio backend: Firebase login check + credits + Razorpay + Cartesia TTS.
// No npm packages needed (Node 18+). Secrets stay here, never in the browser.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- load .env ----------
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch {}

const E = process.env;
const CARTESIA_KEY = E.CARTESIA_API_KEY;
const CARTESIA_VERSION = E.CARTESIA_VERSION || '2025-04-16';
const MODEL = E.TTS_MODEL || 'sonic-latest';
const PORT = E.PORT || 3000;
const FIREBASE_PROJECT = E.FIREBASE_PROJECT_ID;
const ADMIN_EMAIL = (E.ADMIN_EMAIL || '').trim().toLowerCase();
const RZP_ID = E.RAZORPAY_KEY_ID, RZP_SECRET = E.RAZORPAY_KEY_SECRET;
const FREE_CREDITS = Number(E.FREE_CREDITS || 5);
const MAX_CHARS = Number(E.MAX_CHARS || 1000);
const BASE = 'https://api.cartesia.ai';

// ---------- PRICING (edit freely). amount is in paise: 1100 = Rs 11 ----------
// 1 credit = 1 audio generation.
const PLANS = {
  starter: { name: 'Starter', credits: 50,  amount: 1100,  note: 'One-time pack' },
  creator: { name: 'Creator', credits: 250, amount: 5500,  note: 'One-time pack' },
  monthly: { name: 'Pro Pack', credits: 500, amount: 14900, note: 'One-time pack', featured: true },
};

if (!CARTESIA_KEY) { console.error('Missing CARTESIA_API_KEY in .env'); process.exit(1); }
if (!FIREBASE_PROJECT || FIREBASE_PROJECT.startsWith('PASTE')) console.warn('! FIREBASE_PROJECT_ID not set in .env - login will not work yet.');
if (!RZP_ID || !RZP_SECRET) console.warn('! Razorpay keys not set - buying credits is disabled until you add them.');

// ---------- tiny JSON database ----------
const DB_FILE = path.join(__dirname, 'db.json');
let db = { users: {}, orders: {}, payments: {} };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) }; } catch {}
function save() { fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db)); fs.renameSync(DB_FILE + '.tmp', DB_FILE); }
function getUser(uid, email) {
  if (!db.users[uid]) { db.users[uid] = { email: email || '', credits: FREE_CREDITS, created: Date.now(), generated: 0 }; save(); }
  return db.users[uid];
}

// ---------- Firebase ID token verification (no libraries) ----------
let certs = { map: null, exp: 0 };
async function getCerts() {
  if (certs.map && Date.now() < certs.exp) return certs.map;
  const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  const age = Number((r.headers.get('cache-control') || '').match(/max-age=(\d+)/)?.[1] || 3600);
  certs = { map: await r.json(), exp: Date.now() + age * 1000 };
  return certs.map;
}
const b64 = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
async function verifyToken(token) {
  const [h, p, s] = String(token).split('.');
  if (!s) throw new Error('bad token');
  const header = JSON.parse(b64(h)), payload = JSON.parse(b64(p));
  if (header.alg !== 'RS256') throw new Error('bad alg');
  const pem = (await getCerts())[header.kid];
  if (!pem) throw new Error('unknown key');
  const key = new crypto.X509Certificate(pem).publicKey;
  if (!crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), key, b64(s))) throw new Error('bad signature');
  const now = Date.now() / 1000;
  if (payload.aud !== FIREBASE_PROJECT || payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT) throw new Error('wrong project');
  if (payload.exp < now || payload.iat > now + 60 || !payload.sub) throw new Error('expired');
  return { uid: payload.sub, email: payload.email || '', emailVerified: payload.email_verified === true };
}
async function authUser(req) {
  const t = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!t) return null;
  try {
    const u = await verifyToken(t);
    const isAdminEmail = Boolean(ADMIN_EMAIL && u.email.toLowerCase() === ADMIN_EMAIL);
    return {
      ...u,
      isAdmin: isAdminEmail && u.emailVerified,
      requiresEmailVerification: isAdminEmail && !u.emailVerified,
      rec: getUser(u.uid, u.email),
    };
  } catch { return null; }
}

// ---------- helpers ----------
function readBody(req, limit = 1e6) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > limit) { reject(new Error('Body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}
const json = (res, status, obj, extra = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', ...extra }); res.end(JSON.stringify(obj)); };
const cHeaders = (extra = {}) => ({ 'X-API-Key': CARTESIA_KEY, 'Cartesia-Version': CARTESIA_VERSION, ...extra });
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

let voiceCache = { data: null, exp: 0 };
const busy = new Set();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    // ----- static files -----
    if (req.method === 'GET' && !url.pathname.startsWith('/api/')) {
      const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      const file = path.join(__dirname, 'public', rel);
      if (file.startsWith(path.join(__dirname, 'public')) && MIME[path.extname(file)] && fs.existsSync(file)) {
        res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] });
        return res.end(fs.readFileSync(file));
      }
      return json(res, 404, { error: 'Not found' });
    }

    // ----- public config for the page -----
    if (req.method === 'GET' && url.pathname === '/api/config') {
      return json(res, 200, {
        freeCredits: FREE_CREDITS, maxChars: MAX_CHARS,
        razorpayKeyId: RZP_ID && RZP_SECRET ? RZP_ID : null,
        plans: Object.entries(PLANS).map(([id, p]) => ({ id, ...p })),
      });
    }

    // ----- voices (cached 1 hour) -----
    if (req.method === 'GET' && url.pathname === '/api/voices') {
      if (!voiceCache.data || Date.now() > voiceCache.exp) {
        const list = [];
        let cursor = null, hasMore = true;
        while (hasMore) {
          const pageUrl = new URL(`${BASE}/voices`);
          pageUrl.searchParams.set('limit', '100');
          if (cursor) pageUrl.searchParams.set('starting_after', cursor);
          const r = await fetch(pageUrl, { headers: cHeaders() });
          if (!r.ok) return json(res, r.status, { error: await r.text() });
          const j = await r.json();
          const page = Array.isArray(j) ? j : j.data || [];
          list.push(...page.map(v => ({
            id: v.id, name: v.name, language: v.language, description: v.description,
            gender: v.gender, country: v.country, accents: v.accents || [],
          })));
          hasMore = !Array.isArray(j) && Boolean(j.has_more);
          cursor = j.next_page || null;
          if (hasMore && !cursor) throw new Error('Cartesia voice catalog has another page but no cursor.');
        }
        voiceCache = { data: list, exp: Date.now() + 3600e3 };
      }
      return json(res, 200, voiceCache.data);
    }

    // ----- everything below needs login -----
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: 'Please sign in.' });

    if (req.method === 'GET' && url.pathname === '/api/me') {
      return json(res, 200, {
        email: user.email, credits: user.isAdmin ? null : user.rec.credits,
        generated: user.rec.generated, isAdmin: user.isAdmin,
        requiresEmailVerification: user.requiresEmailVerification,
      });
    }

    // ----- text to speech (costs 1 credit) -----
    if (req.method === 'POST' && url.pathname === '/api/tts') {
      const { text, voice_id, language = 'en' } = JSON.parse((await readBody(req)) || '{}');
      if (!text || !String(text).trim() || !voice_id) return json(res, 400, { error: 'Text and voice are required.' });
      if (text.length > MAX_CHARS) return json(res, 400, { error: `Text is too long. Maximum ${MAX_CHARS} characters.` });
      if (!user.isAdmin && user.rec.credits < 1) return json(res, 402, { error: 'You are out of credits. Buy more to continue.' });
      if (busy.has(user.uid)) return json(res, 429, { error: 'Please wait for your current audio to finish.' });
      busy.add(user.uid);
      const charged = !user.isAdmin;
      if (charged) { user.rec.credits -= 1; save(); } // charge first, refund if it fails
      try {
        const r = await fetch(`${BASE}/tts/bytes`, {
          method: 'POST', headers: cHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            model_id: MODEL, transcript: text, voice: { mode: 'id', id: voice_id }, language,
            output_format: { container: 'wav', encoding: 'pcm_s16le', sample_rate: 44100 },
          }),
        });
        if (!r.ok) throw new Error((await r.text()) || 'Voice generation failed');
        const audio = Buffer.from(await r.arrayBuffer());
        user.rec.generated += 1; save();
        res.writeHead(200, {
          'Content-Type': 'audio/wav',
          'X-Credits-Left': user.isAdmin ? 'unlimited' : String(user.rec.credits),
          'Access-Control-Expose-Headers': 'X-Credits-Left',
        });
        return res.end(audio);
      } catch (e) {
        if (charged) { user.rec.credits += 1; save(); }
        const refund = charged ? 'your credit was returned. ' : '';
        return json(res, 502, { error: 'Generation failed, ' + refund + String(e.message).slice(0, 200) });
      } finally { busy.delete(user.uid); }
    }

    // ----- create Razorpay order -----
    if (req.method === 'POST' && url.pathname === '/api/pay/order') {
      if (!RZP_ID || !RZP_SECRET) return json(res, 503, { error: 'Payments are not set up yet.' });
      const { plan } = JSON.parse((await readBody(req)) || '{}');
      const p = PLANS[plan]; if (!p) return json(res, 400, { error: 'Unknown plan.' });
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(RZP_ID + ':' + RZP_SECRET).toString('base64') },
        body: JSON.stringify({ amount: p.amount, currency: 'INR', receipt: `vs_${Date.now()}`, notes: { uid: user.uid, plan } }),
      });
      const o = await r.json();
      if (!r.ok) return json(res, 502, { error: o?.error?.description || 'Could not create order.' });
      db.orders[o.id] = { uid: user.uid, plan, credits: p.credits, amount: p.amount, status: 'created', at: Date.now() }; save();
      return json(res, 200, { order_id: o.id, amount: o.amount, currency: o.currency, name: p.name, email: user.email });
    }

    // ----- verify payment, then add credits -----
    if (req.method === 'POST' && url.pathname === '/api/pay/verify') {
      const { razorpay_order_id: oid, razorpay_payment_id: pid, razorpay_signature: sig } = JSON.parse((await readBody(req)) || '{}');
      const order = db.orders[oid];
      if (!order || order.uid !== user.uid) return json(res, 400, { error: 'Order not found.' });
      if (order.status === 'paid') return json(res, 200, { credits: user.rec.credits });
      const expect = crypto.createHmac('sha256', RZP_SECRET).update(oid + '|' + pid).digest('hex');
      const ok = sig && sig.length === expect.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect));
      if (!ok || db.payments[pid]) return json(res, 400, { error: 'Payment could not be verified.' });
      db.payments[pid] = oid; order.status = 'paid'; order.paymentId = pid;
      user.rec.credits += order.credits; save();
      return json(res, 200, { credits: user.rec.credits, added: order.credits });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
});

server.listen(PORT, () => console.log(`Falcon Voice running -> http://localhost:${PORT}`));
