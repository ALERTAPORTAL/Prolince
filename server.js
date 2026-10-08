require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const PRIVATE_KEY = (process.env.EC_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();

const log = (tag, msg) => console.log(`[${new Date().toISOString().substring(11,19)}] ▸ ${tag.padEnd(6)} ${msg}`);

async function redisSet(k, v) {
  await fetch(`${UPSTASH_URL}/set/${encodeURIComponent(k)}`, {
    method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'text/plain' },
    body: typeof v === 'string' ? v : JSON.stringify(v)
  });
}
async function redisGet(k) {
  const r = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(k)}`, { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  const d = await r.json();
  return d.result ? JSON.parse(d.result) : null;
}
function signToken(c) { return jwt.sign(c, PRIVATE_KEY, { algorithm: 'ES256', expiresIn: '30d' }); }

app.get('/', (req, res) => res.json({ ok: true, service: 'prolince', version: '1.0.0' }));
app.get('/health', (req, res) => res.json({ ok: true, uptime: Math.floor(process.uptime()) }));

app.post('/v1/activate', async (req, res) => {
  const { installId, licenseKey } = req.body || {};
  log('ATIV', `installId=${installId || '?'} key=${licenseKey || '(vazia)'}`);
  if (!installId) return res.status(400).json({ error: 'missing_installId' });
  if (!licenseKey) {
    const now = Math.floor(Date.now()/1000);
    const token = signToken({ sub: installId, tier: 'free', iat: now, exp: now + 2592000 });
    return res.json({ token, tier: 'free', installId });
  }
  const lic = await redisGet(licenseKey);
  if (!lic) return res.status(404).json({ error: 'invalid_license' });
  const now = Math.floor(Date.now()/1000);
  const token = signToken({ sub: installId, tier: 'premium', plan: lic.plano, iat: now, exp: Math.floor(lic.expiraEm/1000) });
  return res.json({ token, tier: 'premium', plan: lic.plano, expiresAt: lic.expiraEm });
});

app.use((req, res) => res.status(404).json({ error: 'not_found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log('SYS', `Prolince v1.0.0 na porta ${PORT}`);
  log('SYS', `Redis: ${UPSTASH_URL ? 'OK' : 'FALTA'}`);
  log('SYS', `Chave EC: ${PRIVATE_KEY ? 'OK' : 'FALTA'}`);
});
