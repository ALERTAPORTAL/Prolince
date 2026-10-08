/* ═══════════════════════════════════════════════════════════════
   ✦ PROLINCE  ·  v1.0.0
   License Server · Telegram Bot · Jetix Extension API
   ═══════════════════════════════════════════════════════════════ */
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Expose-Headers', '*');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ═══════════════════════════════════════════════════════════════
// ENV
// ═══════════════════════════════════════════════════════════════
const UPSTASH_URL    = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN  = process.env.UPSTASH_REDIS_REST_TOKEN;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const OWNER_ID       = process.env.OWNER_ID;

function loadKey(name) {
  const paths = [`/etc/secrets/${name}`, `./${name}`, `/etc/secrets/${name.toLowerCase()}.pem`, `./${name.toLowerCase()}.pem`];
  for (const p of paths) { try { if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim(); } catch {} }
  let v = (process.env[name] || '').trim();
  if (!v) return '';
  if (!v.includes('BEGIN')) { try { v = Buffer.from(v, 'base64').toString('utf8'); } catch {} }
  return v.replace(/\\n/g, '\n').trim();
}
const PRIVATE_KEY = loadKey('EC_PRIVATE_KEY');
const PUBLIC_KEY  = loadKey('EC_PUBLIC_KEY');

const log = (tag, msg) => console.log(`[${new Date().toISOString().substring(11,19)}] ▸ ${tag.padEnd(6)} ${msg}`);

// ═══════════════════════════════════════════════════════════════
// REDIS
// ═══════════════════════════════════════════════════════════════
function normalizeKey(k) { if (!k || typeof k !== 'string') return ''; return k.trim().toUpperCase().replace(/\s+/g,'').replace(/[^A-Z0-9\-]/g,''); }
async function redisSet(key, value) {
  const k = encodeURIComponent(normalizeKey(key));
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  const r = await fetch(`${UPSTASH_URL}/set/${k}`, { method:'POST', headers:{ Authorization:`Bearer ${UPSTASH_TOKEN}`, 'Content-Type':'text/plain' }, body });
  return r.json();
}
async function redisGet(key) {
  const k = encodeURIComponent(normalizeKey(key));
  if (!k) return null;
  const r = await fetch(`${UPSTASH_URL}/get/${k}`, { headers:{ Authorization:`Bearer ${UPSTASH_TOKEN}` } });
  const d = await r.json();
  if (!d.result) return null;
  try { return JSON.parse(d.result); } catch { return null; }
}
async function redisDel(key) {
  const k = encodeURIComponent(normalizeKey(key));
  await fetch(`${UPSTASH_URL}/del/${k}`, { method:'POST', headers:{ Authorization:`Bearer ${UPSTASH_TOKEN}` } });
}
async function redisKeys(pattern='JETIX-*') {
  const p = encodeURIComponent(pattern);
  const r = await fetch(`${UPSTASH_URL}/keys/${p}`, { headers:{ Authorization:`Bearer ${UPSTASH_TOKEN}` } });
  const d = await r.json();
  return (d.result || []).filter(k => typeof k === 'string');
}

// ═══════════════════════════════════════════════════════════════
// JWT
// ═══════════════════════════════════════════════════════════════
function signToken(claims, expiresIn='30d') { if (!PRIVATE_KEY) throw new Error('Chave privada EC não configurada'); return jwt.sign(claims, PRIVATE_KEY, { algorithm:'ES256', expiresIn }); }
function verifyToken(token) { const key = PUBLIC_KEY || PRIVATE_KEY; return jwt.verify(token, key, { algorithms:['ES256'], clockTolerance:30 }); }
function validateBearer(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return { ok:false, error:'missing_bearer' };
  try { return { ok:true, decoded: verifyToken(auth.substring(7)) }; } catch (e) { return { ok:false, error:e.message }; }
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = () => { let s=''; for (let i=0;i<4;i++) s+=chars[crypto.randomInt(0,chars.length)]; return s; };
  return `JETIX-${b()}-${b()}-${b()}`;
}
function formatDate(ts) { if (!ts) return 'Nunca'; return new Date(ts).toLocaleString('pt-BR',{timeZone:'America/Sao_Paulo',day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}); }
function humanTime(ms) { if (ms<=0) return 'expirada'; const s=Math.floor(ms/1000), d=Math.floor(s/86400), h=Math.floor((s%86400)/3600), m=Math.floor((s%3600)/60); if(d>0) return `${d}d ${h}h ${m}m`; if(h>0) return `${h}h ${m}m`; return `${m}m`; }
function progressBar(pct, size=10) { pct = Math.max(0, Math.min(100, pct)); const cheio = Math.round(pct*size/100); return '#'.repeat(cheio) + '-'.repeat(size-cheio); }

const PACOTES = {
  '3d':   { nome:'3 Dias',   dias:3,    preco:3,   emoji:'o', lifetime:false },
  '7d':   { nome:'7 Dias',   dias:7,    preco:5,   emoji:'o', lifetime:false },
  '30d':  { nome:'30 Dias',  dias:30,   preco:12,  emoji:'o', lifetime:false },
  '90d':  { nome:'3 Meses',  dias:90,   preco:30,  emoji:'*', lifetime:false },
  '1a':   { nome:'1 Ano',    dias:365,  preco:70,  emoji:'*', lifetime:false },
  'life': { nome:'LIFETIME', dias:36500, preco:190, emoji:'inf', lifetime:true },
};
const precoFmt = usd => `$${Number(usd).toFixed(2)}`;

// ═══════════════════════════════════════════════════════════════
// JETIX ECDH — Handshake
// ═══════════════════════════════════════════════════════════════
const SESSIONS = new Map(); // sessionId -> { key: CryptoKey, fingerprint, createdAt }
const SERVER_ECDH = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

function base64ToBuffer(b64) { return Buffer.from(b64, 'base64'); }
function bufferToBase64(buf) { return Buffer.from(buf).toString('base64'); }

async function deriveSessionKey(clientPubRaw) {
  // Importa a public key do cliente (raw, uncompressed P-256)
  const clientKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), base64ToBuffer(clientPubRaw)]),
    format: 'der', type: 'spki'
  });
  // ECDH
  const shared = crypto.diffieHellman({ privateKey: SERVER_ECDH.privateKey, publicKey: clientKey });
  // HKDF-SHA256 com info "jetix-v2.5-ecdhe-session-key"
  const hkdf = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from('jetix-v2.5-ecdhe-session-key'), 32);
  return Buffer.from(hkdf);
}

function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]).toString('base64');
}
function aesGcmDecrypt(key, b64) {
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const enc = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// ═══════════════════════════════════════════════════════════════
// TELEGRAM
// ═══════════════════════════════════════════════════════════════
const TG_API = `https://api.telegram.org/bot${TELEGRAM_TOKEN}`;
async function tgSend(chatId, text, keyboard=null) {
  try { const body={chat_id:chatId,text,parse_mode:'HTML',disable_web_page_preview:true}; if(keyboard) body.reply_markup=keyboard; await fetch(`${TG_API}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); } catch(e){ log('TG','send erro: '+e.message); }
}
async function tgEdit(chatId, messageId, text, keyboard=null) {
  try { const body={chat_id:chatId,message_id:messageId,text,parse_mode:'HTML',disable_web_page_preview:true}; if(keyboard) body.reply_markup=keyboard; await fetch(`${TG_API}/editMessageText`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); } catch(e){ log('TG','edit erro: '+e.message); }
}
async function tgAnswer(id, text='') { try { await fetch(`${TG_API}/answerCallbackQuery`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({callback_query_id:id,text})}); } catch {} }

const SUPPORT_SESSIONS = new Map();
const USER_LANG = new Map();
setInterval(() => { const now = Date.now(); for (const [k,v] of SUPPORT_SESSIONS.entries()) if (now - v.ts > 10*60*1000) SUPPORT_SESSIONS.delete(k); }, 60000);

function menuPrincipal() {
  return { texto: `<b>PROLINCE  v1.0.0</b>\n<i>License Engine</i>`, teclado: { inline_keyboard: [
    [{ text:'⚡ Gerar Licenca', callback_data:'m_gerar' }],
    [{ text:'◈ Minhas Chaves', callback_data:'m_listar' }, { text:'◧ Estatisticas', callback_data:'m_stats' }],
    [{ text:'◉ Consultar', callback_data:'m_consultar' }],
    [{ text:'? Ajuda', callback_data:'m_ajuda' }]
  ] } };
}
async function cmdStart(chatId, msgId=null) { const m = menuPrincipal(); if (msgId) await tgEdit(chatId, msgId, m.texto, m.teclado); else await tgSend(chatId, m.texto, m.teclado); }

async function handleCallback(cb) {
  const chatId = cb.message.chat.id, msgId = cb.message.message_id, data = cb.data, userId = String(cb.from.id);
  const isOwner = userId === String(OWNER_ID);
  if (!isOwner) { await tgAnswer(cb.id, 'x'); return; }
  try {
    if (data === 'm_home') { await tgAnswer(cb.id); return cmdStart(chatId, msgId); }
    if (data === 'm_gerar') {
      await tgAnswer(cb.id, 'ok');
      const kb = { inline_keyboard: [] };
      const entries = Object.entries(PACOTES);
      for (let i = 0; i < entries.length; i += 2) {
        const linha = [{ text: `${entries[i][1].nome} - ${precoFmt(entries[i][1].preco)}`, callback_data:`g_${entries[i][0]}` }];
        if (entries[i+1]) linha.push({ text: `${entries[i+1][1].nome} - ${precoFmt(entries[i+1][1].preco)}`, callback_data:`g_${entries[i+1][0]}` });
        kb.inline_keyboard.push(linha);
      }
      kb.inline_keyboard.push([{ text: '‹ Menu', callback_data:'m_home' }]);
      await tgEdit(chatId, msgId, `<b>Gerar Licenca</b>\n<i>Escolha um plano:</i>`, kb);
      return;
    }
    if (data.startsWith('g_')) {
      const pk = data.substring(2), p = PACOTES[pk];
      if (!p) { await tgAnswer(cb.id, 'x'); return; }
      const chave = generateLicenseKey();
      const agora = Date.now();
      const expira = p.lifetime ? (agora + 100*365*24*60*60*1000) : (agora + p.dias*24*60*60*1000);
      await redisSet(chave, JSON.stringify({ chave, plano:pk, planoNome:p.nome, preco:p.preco, dias:p.dias, lifetime:p.lifetime===true, criadaEm:agora, expiraEm:expira, ativa:true, installId:null, ativadaEm:null, v:1 }));
      log('OK', `Chave ${pk} gerada: ${chave}`);
      await tgAnswer(cb.id, 'ok');
      await tgEdit(chatId, msgId, `<b>LICENCA EMITIDA</b>\n\n<b>Chave:</b>\n<code>${chave}</code>\n\n<b>${p.nome}</b> - ${precoFmt(p.preco)}\nExpira: ${p.lifetime ? 'Nunca' : formatDate(expira)}`, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] });
      return;
    }
    if (data === 'm_listar') { await tgAnswer(cb.id, 'ok'); const keys = await redisKeys('JETIX-*'); if (keys.length === 0) { await tgEdit(chatId, msgId, `<b>Minhas Chaves</b>\n\n<i>Nenhuma licenca.</i>`, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] }); return; } let txt = `<b>Minhas Chaves (${keys.length})</b>\n\n`; for (let i = 0; i < Math.min(keys.length, 15); i++) { const l = await redisGet(keys[i]); if (!l) continue; txt += `<b>${l.ativa?'o':'x'}</b> <code>${keys[i]}</code>\n<i>${l.planoNome}</i>\n`; } await tgEdit(chatId, msgId, txt, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] }); return; }
    if (data === 'm_stats') { await tgAnswer(cb.id, 'ok'); const keys = await redisKeys('JETIX-*'); let ativas=0, expiradas=0, life=0, receita=0; for (const k of keys) { const l = await redisGet(k); if (!l) continue; if (l.ativa) ativas++; if (!l.lifetime && l.expiraEm < Date.now()) expiradas++; if (l.lifetime) life++; if (l.preco) receita += Number(l.preco)||0; } await tgEdit(chatId, msgId, `<b>Estatisticas</b>\n\nTotal: <code>${keys.length}</code>\nAtivas: <code>${ativas}</code>\nExpiradas: <code>${expiradas}</code>\nLifetime: <code>${life}</code>\nReceita: <code>${precoFmt(receita)}</code>`, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] }); return; }
    if (data === 'm_consultar') { await tgAnswer(cb.id); return tgEdit(chatId, msgId, `<b>Consultar</b>\n\n<code>/status &lt;chave&gt;</code>`, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] }); }
    if (data === 'm_ajuda') { await tgAnswer(cb.id); await tgEdit(chatId, msgId, `<b>Ajuda</b>\n\n<code>/start</code>\n<code>/gerar</code>\n<code>/listar</code>\n<code>/stats</code>\n<code>/status &lt;k&gt;</code>\n<code>/revogar &lt;k&gt;</code>\n<code>/deletar &lt;k&gt;</code>`, { inline_keyboard: [[{text:'‹ Menu',callback_data:'m_home'}]] }); return; }
    await tgAnswer(cb.id);
  } catch (e) { log('ERRO', 'Callback: ' + e.message); try { await tgAnswer(cb.id, 'x'); } catch {} }
}

async function handleMessage(msg) {
  const chatId = msg.chat.id, userId = String(msg.from.id);
  const texto = (msg.text || '').trim();
  const args = texto.replace(/\n/g,' ').split(' ').filter(a=>a.length>0);
  const cmd = (args[0] || '').toLowerCase();
  const isOwner = userId === String(OWNER_ID);
  if (!isOwner) {
    if (cmd === '/start' || cmd === '/ajuda') await tgSend(chatId, `<b>PROLINCE</b>\n\nUse /start`);
    return;
  }
  try {
    if (cmd === '/start' || cmd === '/menu') { await cmdStart(chatId); return; }
    if (cmd === '/gerar') { const kb = { inline_keyboard: [] }; const entries = Object.entries(PACOTES); for (let i = 0; i < entries.length; i += 2) { const linha = [{text:`${entries[i][1].nome} - ${precoFmt(entries[i][1].preco)}`,callback_data:`g_${entries[i][0]}`}]; if (entries[i+1]) linha.push({text:`${entries[i+1][1].nome} - ${precoFmt(entries[i+1][1].preco)}`,callback_data:`g_${entries[i+1][0]}`}); kb.inline_keyboard.push(linha); } await tgSend(chatId, `<b>Gerar Licenca</b>`, kb); return; }
    if (cmd === '/listar') { const keys = await redisKeys('JETIX-*'); if (keys.length === 0) { await tgSend(chatId, `Nenhuma licenca.`); return; } let txt = `<b>Minhas Chaves (${keys.length})</b>\n`; for (let i = 0; i < Math.min(keys.length, 30); i++) { const l = await redisGet(keys[i]); if (!l) continue; txt += `<b>${l.ativa?'o':'x'}</b> <code>${keys[i]}</code> - <i>${l.planoNome}</i>\n`; } await tgSend(chatId, txt); return; }
    if (cmd === '/status') { const k = args[1]; if (!k) { await tgSend(chatId, `/status <chave>`); return; } const l = await redisGet(k); if (!l) { await tgSend(chatId, `Nao encontrada`); return; } await tgSend(chatId, `<b>Detalhes</b>\n<code>${k}</code>\n${l.planoNome}\n${precoFmt(l.preco)}\nEmitida: ${formatDate(l.criadaEm)}\nExpira: ${l.lifetime?'Nunca':formatDate(l.expiraEm)}\nStatus: ${l.ativa?'Ativa':'Revogada'}`); return; }
    if (cmd === '/revogar') { const k = args[1]; if (!k) return tgSend(chatId, `/revogar <chave>`); const l = await redisGet(k); if (!l) return tgSend(chatId, `Nao encontrada`); l.ativa = false; await redisSet(k, JSON.stringify(l)); await tgSend(chatId, `Revogada`); return; }
    if (cmd === '/deletar') { const k = args[1]; if (!k) return tgSend(chatId, `/deletar <chave>`); await redisDel(k); await tgSend(chatId, `Deletada`); return; }
    if (cmd === '/stats') { const keys = await redisKeys('JETIX-*'); let ativas=0, exp=0, life=0, receita=0; for (const k of keys) { const l = await redisGet(k); if (!l) continue; if (l.ativa) ativas++; if (!l.lifetime && l.expiraEm < Date.now()) exp++; if (l.lifetime) life++; if (l.preco) receita += Number(l.preco)||0; } await tgSend(chatId, `<b>Stats</b>\nTotal: <code>${keys.length}</code>\nAtivas: <code>${ativas}</code>\nExpiradas: <code>${exp}</code>\nLifetime: <code>${life}</code>\nReceita: <code>${precoFmt(receita)}</code>`); return; }
    await tgSend(chatId, `Use /start`);
  } catch (e) { log('ERRO', 'Message: ' + e.message); }
}

// ═══════════════════════════════════════════════════════════════
// ROTAS BASE
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ ok: true, service: 'prolince', version: '1.0.0' }));
app.get('/health', (req, res) => res.json({ ok: true, uptime: Math.floor(process.uptime()) }));
app.get('/v1/health', (req, res) => res.json({ ok: true, status: 'healthy', version: '1.0.0', timestamp: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
// JETIX — /api/auth/key-exchange (POST) — Handshake ECDH
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/key-exchange', async (req, res) => {
  try {
    const { publicKey, fingerprint } = req.body || {};
    log('JETIX', `key-exchange fp=${(fingerprint||'').substring(0,12)}... pkLen=${(publicKey||'').length}`);
    if (!publicKey || !fingerprint) return res.status(400).json({ error: 'missing_params' });
    const sessionKey = await deriveSessionKey(publicKey);
    const serverPubRaw = SERVER_ECDH.publicKey.export({ format: 'der', type: 'spki' }).subarray(26).toString('base64');
    const sessionId = crypto.randomUUID();
    SESSIONS.set(sessionId, { key: sessionKey, fingerprint, createdAt: Date.now() });
    log('JETIX', `✓ Session ${sessionId.substring(0,8)} criada para fp=${fingerprint.substring(0,12)}...`);
    return res.json({ success: true, data: { serverPublicKey: serverPubRaw, sessionId } });
  } catch (e) {
    log('ERRO', 'key-exchange: ' + e.message);
    return res.status(500).json({ error: 'key_exchange_failed', message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// JETIX — /api/auth/bot-info (GET)
// ═══════════════════════════════════════════════════════════════
app.get('/api/auth/bot-info', (req, res) => {
  res.json({ username: 'ProlinceBot' });
});

// ═══════════════════════════════════════════════════════════════
// JETIX — /api/auth/verify (GET)
// ═══════════════════════════════════════════════════════════════
app.get('/api/auth/verify', (req, res) => {
  const fp = req.query.fingerprint || req.headers['x-fingerprint'] || '';
  log('JETIX', `verify fp=${fp.substring(0,12)}...`);
  // Retorna uma sessão "válida" básica — Jetix vai mostrar o dashboard
  return res.json({
    success: true,
    data: {
      user: {
        id: 1,
        username: 'prolince_user',
        effective_tier: 'premium',
        effective_status: 'active',
        has_active_extension: true,
        has_active_credit: true,
        is_banned: false,
        subscription_end: null
      },
      sessionToken: jwt.sign({ sub: fp, tier: 'premium' }, PRIVATE_KEY || 'fallback', { algorithm: PRIVATE_KEY ? 'ES256' : 'HS256', expiresIn: '7d' }),
      formFillDefaults: { country: 'US', name: 'John Doe', email: 'user@example.com' }
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// JETIX — /api/auth/redeem (POST) — Resgatar key JETIX
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/redeem', async (req, res) => {
  const { code, fingerprint } = req.body || {};
  log('JETIX', `redeem code=${code} fp=${(fingerprint||'').substring(0,12)}...`);
  if (!code) return res.status(400).json({ error: 'missing_code' });
  const key = normalizeKey(code);
  const lic = await redisGet(key);
  if (!lic) return res.status(404).json({ error: 'invalid_license' });
  if (!lic.ativa) return res.status(403).json({ error: 'revoked' });
  if (!lic.lifetime && Date.now() > lic.expiraEm) return res.status(403).json({ error: 'expired' });
  if (!lic.installId) { lic.installId = fingerprint; lic.ativadaEm = Date.now(); await redisSet(key, JSON.stringify(lic)); }
  return res.json({ success: true, data: { tier: 'premium', plan: lic.plano, expiresAt: lic.expiraEm, licenseKey: key } });
});

// ═══════════════════════════════════════════════════════════════
// JETIX — Outros endpoints /api/*
// ═══════════════════════════════════════════════════════════════
app.get('/api/data/address', (req, res) => {
  const country = req.query.country || 'US';
  return res.json({
    success: true,
    data: {
      countryCode: country, zip: '10001', city: 'New York', state: 'NY',
      street: '123 Main St', line1: '123 Main St', line2: 'Apt 4B',
      phone: '555-0100', email: 'user@example.com',
      firstName: 'John', lastName: 'Doe'
    }
  });
});
app.get('/api/data/user', (req, res) => res.json({ success: true, data: { id: 1, username: 'prolince_user', tier: 'premium' } }));
app.get('/api/config/selectors', (req, res) => res.json({ success: true, data: { selectors: {}, uiInteraction: null } }));
app.post('/api/tracking/log', (req, res) => { log('JETIX', `tracking: ${JSON.stringify(req.body).substring(0,100)}`); res.json({ ok: true }); });
app.post('/api/stats/sync', (req, res) => { log('JETIX', `stats-sync: ${JSON.stringify(req.body).substring(0,100)}`); res.json({ ok: true, received: true }); });
app.post('/api/bypass/instructions', (req, res) => res.json({ success: true, data: { instructions: [], rules: [] } }));
app.get('/api/session-rules', (req, res) => res.json({ success: true, data: { rules: [] } }));
app.post('/api/proxy/test', (req, res) => res.json({ success: true, data: { ok: true, ip: '127.0.0.1' } }));
app.post('/api/proxy/test-geo', (req, res) => res.json({ success: true, data: { country: 'US', city: 'New York' } }));

// ═══════════════════════════════════════════════════════════════
// PROLINCE — /v1/activate, /v1/verify, /v1/campaign
// ═══════════════════════════════════════════════════════════════
app.post('/v1/activate', async (req, res) => {
  const { installId, licenseKey } = req.body || {};
  log('ATIV', `installId=${installId || '?'} key=${licenseKey || '(vazia)'}`);
  if (!installId) return res.status(400).json({ error: 'missing_installId' });
  if (!PRIVATE_KEY) return res.status(500).json({ error: 'server_misconfigured' });
  if (!licenseKey) {
    const now = Math.floor(Date.now()/1000);
    const token = signToken({ sub: installId, tier: 'free', iat: now, exp: now + 2592000 });
    return res.json({ token, tier: 'free', installId });
  }
  const keyNorm = normalizeKey(licenseKey);
  const lic = await redisGet(keyNorm);
  if (!lic) return res.status(404).json({ error: 'invalid_license' });
  if (!lic.ativa) return res.status(403).json({ error: 'revoked' });
  if (!lic.lifetime && Date.now() > lic.expiraEm) return res.status(403).json({ error: 'expired' });
  if (!lic.installId) { lic.installId = installId; lic.ativadaEm = Date.now(); await redisSet(keyNorm, JSON.stringify(lic)); }
  else if (lic.installId !== installId) return res.status(403).json({ error: 'already_used' });
  const now = Math.floor(Date.now()/1000);
  const isLife = lic.plano === 'life';
  const expSec = isLife ? now + (100*365*24*60*60) : Math.floor(lic.expiraEm/1000);
  const token = signToken({ sub:installId, tier:'premium', plan:lic.plano, licenseKey:lic.chave, iat:now, exp:expSec });
  return res.json({ token, tier:'premium', plan:lic.plano, expiresAt:lic.expiraEm, licenseKey:keyNorm });
});

app.post('/v1/verify', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, error:'missing_token' });
  try { return res.json({ ok:true, valido:true, dados: verifyToken(token) }); }
  catch (e) { return res.status(401).json({ ok:false, valido:false, erro:e.message }); }
});

app.get('/v1/campaign', (req, res) => res.json({ ok:true, campaign:null, serverTime:Date.now() }));

// ═══════════════════════════════════════════════════════════════
// WEBHOOK TELEGRAM
// ═══════════════════════════════════════════════════════════════
app.post('/telegram-webhook', async (req, res) => {
  res.sendStatus(200);
  const update = req.body || {};
  try {
    if (update.callback_query) return handleCallback(update.callback_query);
    if (update.message && update.message.text) return handleMessage(update.message);
  } catch (e) { log('ERRO', 'Webhook: ' + e.message); }
});

app.use((req, res) => res.status(404).json({ error: 'not_found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log('SYS', `Prolince v1.0.0 na porta ${PORT}`);
  log('SYS', `Redis: ${UPSTASH_URL ? 'OK' : 'FALTA'}`);
  log('SYS', `Chave EC: ${PRIVATE_KEY ? 'OK' : 'FALTA'}`);
  log('SYS', `Telegram: ${TELEGRAM_TOKEN ? 'OK' : 'FALTA'}`);
  log('SYS', `Owner ID: ${OWNER_ID || 'FALTA'}`);
  log('JETIX', `✔ /api/auth/key-exchange (ECDH + HKDF + AES-GCM)`);
  log('JETIX', `✔ /api/auth/verify`);
  log('JETIX', `✔ /api/auth/bot-info`);
  log('JETIX', `✔ /api/auth/redeem`);
  log('JETIX', `✔ /api/data/* + /api/config/* + /api/stats/* + /api/proxy/*`);
  log('JETIX', `✔ Key formato JETIX-XXXX-XXXX-XXXX`);
  log('OK',  `Bot Telegram completo`);
});

process.on('uncaughtException', e => log('ERRO', 'Uncaught: ' + e.message));
process.on('unhandledRejection', e => log('ERRO', 'Rejection: ' + (e?.message || e)));
