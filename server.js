
/* ═══════════════════════════════════════════════════════════════
   ✦ PROLINCE · v2.0.0
   License Server · Telegram Bot · Jetix Extension API
   Compatível com Jetix V2.5 (api.js + login.js)
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
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const OWNER_ID = process.env.OWNER_ID;
const BOT_USERNAME = process.env.BOT_USERNAME || 'ProlinceBot';

function loadKey(name) {
  const paths = [`/etc/secrets/${name}`, `./${name}`, `/etc/secrets/${name.toLowerCase()}.pem`, `./${name.toLowerCase()}.pem`];
  for (const p of paths) { try { if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim(); } catch {} }
  let v = (process.env[name] || '').trim();
  if (!v) return '';
  if (!v.includes('BEGIN')) { try { v = Buffer.from(v, 'base64').toString('utf8'); } catch {} }
  return v.replace(/\\n/g, '\n').trim();
}
const PRIVATE_KEY = loadKey('EC_PRIVATE_KEY');
const PUBLIC_KEY = loadKey('EC_PUBLIC_KEY');

const log = (tag, msg) => console.log(`[${new Date().toISOString().substring(11, 19)}] ▸ ${tag.padEnd(6)} ${msg}`);

// ═══════════════════════════════════════════════════════════════
// REDIS (Upstash)
// ═══════════════════════════════════════════════════════════════
function normalizeKey(k) {
  if (!k || typeof k !== 'string') return '';
  return k.trim().toUpperCase().replace(/\s+/g, '').replace(/[^A-Z0-9\-]/g, '');
}
async function redisSet(key, value, ttlSeconds = null) {
  const k = encodeURIComponent(normalizeKey(key));
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  let url = `${UPSTASH_URL}/set/${k}`;
  if (ttlSeconds) url += `?EX=${ttlSeconds}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'text/plain' }, body });
  return r.json();
}
async function redisGet(key) {
  const k = encodeURIComponent(normalizeKey(key));
  if (!k) return null;
  const r = await fetch(`${UPSTASH_URL}/get/${k}`, { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  const d = await r.json();
  if (!d.result) return null;
  try { return JSON.parse(d.result); } catch { return d.result; }
}
async function redisDel(key) {
  const k = encodeURIComponent(normalizeKey(key));
  await fetch(`${UPSTASH_URL}/del/${k}`, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
}
async function redisKeys(pattern = 'JETIX-*') {
  const p = encodeURIComponent(pattern);
  const r = await fetch(`${UPSTASH_URL}/keys/${p}`, { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  const d = await r.json();
  return (d.result || []).filter(k => typeof k === 'string');
}

// ═══════════════════════════════════════════════════════════════
// JWT
// ═══════════════════════════════════════════════════════════════
function signToken(claims, expiresIn = '30d') {
  if (!PRIVATE_KEY) throw new Error('Chave privada EC não configurada');
  return jwt.sign(claims, PRIVATE_KEY, { algorithm: 'ES256', expiresIn });
}
function verifyToken(token) {
  const key = PUBLIC_KEY || PRIVATE_KEY;
  return jwt.verify(token, key, { algorithms: ['ES256'], clockTolerance: 30 });
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = () => { let s = ''; for (let i = 0; i < 5; i++) s += chars[crypto.randomInt(0, chars.length)]; return s; };
  return `JETIX-${b()}-${b()}-${b()}`;
}
function formatDate(ts) {
  if (!ts) return 'Nunca';
  return new Date(ts).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const PACOTES = {
  '3d': { nome: '3 Dias', dias: 3, preco: 3, lifetime: false },
  '7d': { nome: '7 Dias', dias: 7, preco: 5, lifetime: false },
  '30d': { nome: '30 Dias', dias: 30, preco: 12, lifetime: false },
  '90d': { nome: '3 Meses', dias: 90, preco: 30, lifetime: false },
  '1a': { nome: '1 Ano', dias: 365, preco: 70, lifetime: false },
  'life': { nome: 'LIFETIME', dias: 36500, preco: 190, lifetime: true },
};
const precoFmt = usd => `$${Number(usd).toFixed(2)}`;

// ═══════════════════════════════════════════════════════════════
// ECDH Handshake
// ═══════════════════════════════════════════════════════════════
const SESSIONS = new Map();
const SERVER_ECDH = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

async function deriveSessionKey(clientPubRaw) {
  const clientKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Buffer.from(clientPubRaw, 'base64')]),
    format: 'der', type: 'spki'
  });
  const shared = crypto.diffieHellman({ privateKey: SERVER_ECDH.privateKey, publicKey: clientKey });
  const hkdf = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from('jetix-v2.5-ecdhe-session-key'), 32);
  return Buffer.from(hkdf);
}

// ═══════════════════════════════════════════════════════════════
// TELEGRAM
// ═══════════════════════════════════════════════════════════════
const TG_API = `https://api.telegram.org/bot${TELEGRAM_TOKEN}`;

async function tgSend(chatId, text, keyboard = null) {
  if (!TELEGRAM_TOKEN) return { ok: false, error: 'no_token' };
  try {
    const body = { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true };
    if (keyboard) body.reply_markup = keyboard;
    const r = await fetch(`${TG_API}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return await r.json();
  } catch (e) { log('TG', 'send erro: ' + e.message); return { ok: false, error: e.message }; }
}
async function tgEdit(chatId, messageId, text, keyboard = null) {
  try {
    const body = { chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML', disable_web_page_preview: true };
    if (keyboard) body.reply_markup = keyboard;
    await fetch(`${TG_API}/editMessageText`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch (e) { log('TG', 'edit erro: ' + e.message); }
}
async function tgAnswer(id, text = '') {
  try { await fetch(`${TG_API}/answerCallbackQuery`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_query_id: id, text }) }); } catch {}
}

// ═══════════════════════════════════════════════════════════════
// BOT — MENU
// ═══════════════════════════════════════════════════════════════
function menuPrincipal() {
  return {
    texto: `<b>PROLINCE · v2.0.0</b>\n<i>License Engine</i>`,
    teclado: { inline_keyboard: [
      [{ text: '⚡ Gerar Licença', callback_data: 'm_gerar' }],
      [{ text: '◈ Minhas Chaves', callback_data: 'm_listar' }, { text: '◧ Estatísticas', callback_data: 'm_stats' }],
      [{ text: '◉ Consultar', callback_data: 'm_consultar' }],
      [{ text: '❔ Ajuda', callback_data: 'm_ajuda' }]
    ] }
  };
}
async function cmdStart(chatId, msgId = null) {
  const m = menuPrincipal();
  if (msgId) await tgEdit(chatId, msgId, m.texto, m.teclado);
  else await tgSend(chatId, m.texto, m.teclado);
}

async function handleCallback(cb) {
  const chatId = cb.message.chat.id, msgId = cb.message.message_id, data = cb.data, userId = String(cb.from.id);
  const isOwner = userId === String(OWNER_ID);
  if (!isOwner) { await tgAnswer(cb.id, '⛔'); return; }
  try {
    if (data === 'm_home') { await tgAnswer(cb.id); return cmdStart(chatId, msgId); }
    if (data === 'm_gerar') {
      await tgAnswer(cb.id, 'ok');
      const kb = { inline_keyboard: [] };
      const entries = Object.entries(PACOTES);
      for (let i = 0; i < entries.length; i += 2) {
        const linha = [{ text: `${entries[i][1].nome} — ${precoFmt(entries[i][1].preco)}`, callback_data: `g_${entries[i][0]}` }];
        if (entries[i + 1]) linha.push({ text: `${entries[i + 1][1].nome} — ${precoFmt(entries[i + 1][1].preco)}`, callback_data: `g_${entries[i + 1][0]}` });
        kb.inline_keyboard.push(linha);
      }
      kb.inline_keyboard.push([{ text: '‹ Menu', callback_data: 'm_home' }]);
      await tgEdit(chatId, msgId, `<b>Gerar Licença</b>\n<i>Escolha um plano:</i>`, kb);
      return;
    }
    if (data.startsWith('g_')) {
      const pk = data.substring(2), p = PACOTES[pk];
      if (!p) { await tgAnswer(cb.id, 'x'); return; }
      const chave = generateLicenseKey();
      const agora = Date.now();
      const expira = p.lifetime ? (agora + 100 * 365 * 24 * 60 * 60 * 1000) : (agora + p.dias * 24 * 60 * 60 * 1000);
      await redisSet(chave, JSON.stringify({ chave, plano: pk, planoNome: p.nome, preco: p.preco, dias: p.dias, lifetime: p.lifetime === true, criadaEm: agora, expiraEm: expira, ativa: true, installId: null, ativadaEm: null, v: 1 }));
      log('OK', `Chave ${pk} gerada: ${chave}`);
      await tgAnswer(cb.id, 'ok');
      await tgEdit(chatId, msgId, `<b>LICENÇA EMITIDA</b>\n\n<b>Chave:</b>\n<code>${chave}</code>\n\n<b>${p.nome}</b> — ${precoFmt(p.preco)}\nExpira: ${p.lifetime ? 'Nunca' : formatDate(expira)}`, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] });
      return;
    }
    if (data === 'm_listar') {
      await tgAnswer(cb.id, 'ok');
      const keys = await redisKeys('JETIX-*');
      if (keys.length === 0) { await tgEdit(chatId, msgId, `<b>Minhas Chaves</b>\n\n<i>Nenhuma licença.</i>`, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] }); return; }
      let txt = `<b>Minhas Chaves (${keys.length})</b>\n\n`;
      for (let i = 0; i < Math.min(keys.length, 15); i++) {
        const l = await redisGet(keys[i]);
        if (!l) continue;
        txt += `<b>${l.ativa ? '✅' : '❌'}</b> <code>${keys[i]}</code>\n<i>${l.planoNome}</i>\n`;
      }
      await tgEdit(chatId, msgId, txt, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] });
      return;
    }
    if (data === 'm_stats') {
      await tgAnswer(cb.id, 'ok');
      const keys = await redisKeys('JETIX-*');
      let ativas = 0, expiradas = 0, life = 0, receita = 0;
      for (const k of keys) {
        const l = await redisGet(k);
        if (!l) continue;
        if (l.ativa) ativas++;
        if (!l.lifetime && l.expiraEm < Date.now()) expiradas++;
        if (l.lifetime) life++;
        if (l.preco) receita += Number(l.preco) || 0;
      }
      await tgEdit(chatId, msgId, `<b>Estatísticas</b>\n\nTotal: <code>${keys.length}</code>\nAtivas: <code>${ativas}</code>\nExpiradas: <code>${expiradas}</code>\nLifetime: <code>${life}</code>\nReceita: <code>${precoFmt(receita)}</code>`, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] });
      return;
    }
    if (data === 'm_consultar') { await tgAnswer(cb.id); return tgEdit(chatId, msgId, `<b>Consultar</b>\n\n<code>/status &lt;chave&gt;</code>`, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] }); }
    if (data === 'm_ajuda') {
      await tgAnswer(cb.id);
      await tgEdit(chatId, msgId, `<b>Ajuda</b>\n\n<code>/start</code>\n<code>/id</code>\n<code>/gerar</code>\n<code>/listar</code>\n<code>/stats</code>\n<code>/status &lt;k&gt;</code>\n<code>/revogar &lt;k&gt;</code>\n<code>/deletar &lt;k&gt;</code>`, { inline_keyboard: [[{ text: '‹ Menu', callback_data: 'm_home' }]] });
      return;
    }
    await tgAnswer(cb.id);
  } catch (e) { log('ERRO', 'Callback: ' + e.message); try { await tgAnswer(cb.id, 'x'); } catch {} }
}

async function handleMessage(msg) {
  const chatId = msg.chat.id, userId = String(msg.from.id);
  const texto = (msg.text || '').trim();
  const args = texto.replace(/\n/g, ' ').split(' ').filter(a => a.length > 0);
  const cmd = (args[0] || '').toLowerCase();
  const isOwner = userId === String(OWNER_ID);

  try {
    if (cmd === '/start') {
      if (isOwner) return cmdStart(chatId);
      return tgSend(chatId, `👋 <b>Bem-vindo ao Prolince!</b>\n\nSeu Telegram ID:\n<code>${userId}</code>\n\nUse esse ID no painel Jetix para receber o código OTP.`);
    }
    if (cmd === '/id') {
      return tgSend(chatId, `🆔 <b>Seu Telegram ID:</b>\n<code>${userId}</code>\n\nUse esse número no painel Jetix para fazer login.`);
    }
    if (cmd === '/ajuda' || cmd === '/help') {
      if (isOwner) return tgSend(chatId, `<b>Ajuda (Owner)</b>\n\n/start — menu\n/id — seu ID\n/gerar — nova licença\n/listar — suas chaves\n/stats — estatísticas\n/status &lt;k&gt; — consultar\n/revogar &lt;k&gt; — revogar\n/deletar &lt;k&gt; — deletar`);
      return tgSend(chatId, `Use /start ou /id.`);
    }
    if (!isOwner) return tgSend(chatId, `Use /start ou /id.`);

    if (cmd === '/menu') return cmdStart(chatId);
    if (cmd === '/gerar') {
      const kb = { inline_keyboard: [] };
      const entries = Object.entries(PACOTES);
      for (let i = 0; i < entries.length; i += 2) {
        const linha = [{ text: `${entries[i][1].nome} — ${precoFmt(entries[i][1].preco)}`, callback_data: `g_${entries[i][0]}` }];
        if (entries[i + 1]) linha.push({ text: `${entries[i + 1][1].nome} — ${precoFmt(entries[i + 1][1].preco)}`, callback_data: `g_${entries[i + 1][0]}` });
        kb.inline_keyboard.push(linha);
      }
      return tgSend(chatId, `<b>Gerar Licença</b>`, kb);
    }
    if (cmd === '/listar') {
      const keys = await redisKeys('JETIX-*');
      if (keys.length === 0) return tgSend(chatId, `Nenhuma licença.`);
      let txt = `<b>Minhas Chaves (${keys.length})</b>\n`;
      for (let i = 0; i < Math.min(keys.length, 30); i++) {
        const l = await redisGet(keys[i]);
        if (!l) continue;
        txt += `<b>${l.ativa ? '✅' : '❌'}</b> <code>${keys[i]}</code> — <i>${l.planoNome}</i>\n`;
      }
      return tgSend(chatId, txt);
    }
    if (cmd === '/status') {
      const k = args[1];
      if (!k) return tgSend(chatId, `/status &lt;chave&gt;`);
      const l = await redisGet(k);
      if (!l) return tgSend(chatId, `Não encontrada`);
      return tgSend(chatId, `<b>Detalhes</b>\n<code>${k}</code>\n${l.planoNome}\n${precoFmt(l.preco)}\nEmitida: ${formatDate(l.criadaEm)}\nExpira: ${l.lifetime ? 'Nunca' : formatDate(l.expiraEm)}\nStatus: ${l.ativa ? 'Ativa' : 'Revogada'}`);
    }
    if (cmd === '/revogar') {
      const k = args[1];
      if (!k) return tgSend(chatId, `/revogar &lt;chave&gt;`);
      const l = await redisGet(k);
      if (!l) return tgSend(chatId, `Não encontrada`);
      l.ativa = false;
      await redisSet(k, JSON.stringify(l));
      return tgSend(chatId, `Revogada`);
    }
    if (cmd === '/deletar') {
      const k = args[1];
      if (!k) return tgSend(chatId, `/deletar &lt;chave&gt;`);
      await redisDel(k);
      return tgSend(chatId, `Deletada`);
    }
    if (cmd === '/stats') {
      const keys = await redisKeys('JETIX-*');
      let ativas = 0, exp = 0, life = 0, receita = 0;
      for (const k of keys) {
        const l = await redisGet(k);
        if (!l) continue;
        if (l.ativa) ativas++;
        if (!l.lifetime && l.expiraEm < Date.now()) exp++;
        if (l.lifetime) life++;
        if (l.preco) receita += Number(l.preco) || 0;
      }
      return tgSend(chatId, `<b>Stats</b>\nTotal: <code>${keys.length}</code>\nAtivas: <code>${ativas}</code>\nExpiradas: <code>${exp}</code>\nLifetime: <code>${life}</code>\nReceita: <code>${precoFmt(receita)}</code>`);
    }
    return tgSend(chatId, `Use /start`);
  } catch (e) { log('ERRO', 'Message: ' + e.message); }
}

// ═══════════════════════════════════════════════════════════════
// ROTAS BASE
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ ok: true, service: 'prolince', version: '2.0.0' }));
app.get('/health', (req, res) => res.json({ success: true, ok: true, uptime: Math.floor(process.uptime()) }));
app.get('/v1/health', (req, res) => res.json({ success: true, ok: true, status: 'healthy', version: '2.0.0', timestamp: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
// JETIX — ECDH
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/key-exchange', async (req, res) => {
  try {
    const { publicKey, fingerprint } = req.body || {};
    log('JETIX', `key-exchange fp=${(fingerprint || '').substring(0, 12)}...`);
    if (!publicKey || !fingerprint) return res.status(400).json({ success: false, error: 'missing_params' });
    const sessionKey = await deriveSessionKey(publicKey);
    const serverPubRaw = SERVER_ECDH.publicKey.export({ format: 'der', type: 'spki' }).subarray(26).toString('base64');
    const sessionId = crypto.randomUUID();
    SESSIONS.set(sessionId, { key: sessionKey, fingerprint, createdAt: Date.now() });
    return res.json({ success: true, data: { serverPublicKey: serverPubRaw, sessionId } });
  } catch (e) {
    log('ERRO', 'key-exchange: ' + e.message);
    return res.status(500).json({ success: false, error: 'key_exchange_failed', message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// JETIX — LOGIN (envia OTP)
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  try {
    const { telegramId } = req.body || {};
    log('JETIX', `login telegramId=${telegramId}`);
    if (!telegramId) return res.status(400).json({ success: false, error: 'missing_telegramId' });
    if (!/^\d+$/.test(String(telegramId))) return res.status(400).json({ success: false, error: 'invalid_telegramId' });

    const otp = String(crypto.randomInt(100000, 999999));
    await redisSet(`OTP-${telegramId}`, JSON.stringify({ otp, createdAt: Date.now(), expiresAt: Date.now() + 10 * 60 * 1000 }), 600);

    if (TELEGRAM_TOKEN) {
      const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: telegramId, text: `🔐 <b>Seu código Jetix</b>\n\n<code>${otp}</code>\n\n<i>Expira em 10 minutos.</i>`, parse_mode: 'HTML' })
      });
      const data = await r.json();
      if (!data.ok) {
        log('TG', `falha ao enviar OTP: ${data.description}`);
        return res.status(400).json({ success: false, error: 'bot_not_started', detail: data.description || 'Envie /start para o bot primeiro' });
      }
    }

    log('OK', `OTP enviado para ${telegramId}`);
    return res.json({ success: true, data: { sent: true, telegramId } });
  } catch (e) {
    log('ERRO', 'login: ' + e.message);
    return res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// JETIX — VERIFY (valida OTP) — CORRIGIDO
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { telegramId, otp, fingerprint } = req.body || {};
    log('JETIX', `verify telegramId=${telegramId} otp=${otp ? '***' : '?'}`);
    if (!telegramId || !otp) return res.status(400).json({ success: false, error: 'missing_params' });

    const stored = await redisGet(`OTP-${telegramId}`);
    if (!stored) return res.status(404).json({ success: false, error: 'no_otp' });
    if (Date.now() > stored.expiresAt) { await redisDel(`OTP-${telegramId}`); return res.status(403).json({ success: false, error: 'otp_expired' }); }
    if (String(stored.otp) !== String(otp)) return res.status(403).json({ success: false, error: 'otp_invalid' });

    await redisDel(`OTP-${telegramId}`);
    const sessionToken = signToken({ sub: String(telegramId), tier: 'premium', kind: 'session' }, '30d');
    log('OK', `login OK para ${telegramId}`);

    return res.json({
      success: true,
      data: {
        sessionToken,
        user: {
          id: telegramId, telegram_id: telegramId, username: 'user_' + telegramId,
          name: 'User ' + telegramId,
          effective_tier: 'premium', effective_status: 'active',
          has_active_extension: true, has_active_credit: true,
          is_banned: false, subscription_end: null,
          is_admin: false, acquisition_source: 'free'
        },
        formFillDefaults: { country: 'US', name: 'John Doe', email: 'user@example.com' }
      }
    });
  } catch (e) {
    log('ERRO', 'verify: ' + e.message);
    return res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  req.url = '/api/auth/verify';
  return app._router.handle(req, res, () => {});
});

// ═══════════════════════════════════════════════════════════════
// JETIX — VERIFY (GET) — sessão por fingerprint
// ═══════════════════════════════════════════════════════════════
app.get('/api/auth/verify', (req, res) => {
  const fp = req.query.fingerprint || req.headers['x-fingerprint'] || '';
  log('JETIX', `verify(GET) fp=${fp.substring(0, 12)}...`);
  const sessionToken = signToken({ sub: fp || 'anonymous', tier: 'premium', kind: 'session' }, '7d');
  return res.json({
    success: true,
    data: {
      user: {
        id: 1, username: 'prolince_user', name: 'Prolince User',
        effective_tier: 'premium', effective_status: 'active',
        has_active_extension: true, has_active_credit: true,
        is_banned: false, subscription_end: null,
        is_admin: false, acquisition_source: 'free'
      },
      sessionToken,
      formFillDefaults: { country: 'US', name: 'John Doe', email: 'user@example.com' }
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// JETIX — BOT INFO
// ═══════════════════════════════════════════════════════════════
app.get('/api/auth/bot-info', (req, res) => res.json({ success: true, username: BOT_USERNAME, botUsername: BOT_USERNAME }));
app.get('/api/bot-username', (req, res) => res.json({ success: true, username: BOT_USERNAME, botUsername: BOT_USERNAME }));

// ═══════════════════════════════════════════════════════════════
// JETIX — REDEEM
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/redeem', async (req, res) => {
  try {
    const { code, fingerprint } = req.body || {};
    log('JETIX', `redeem code=${code}`);
    if (!code) return res.status(400).json({ success: false, error: 'missing_code' });
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return res.status(500).json({ success: false, error: 'redis_not_configured' });

    const key = normalizeKey(code);
    const lic = await redisGet(key);
    if (!lic) return res.status(404).json({ success: false, error: 'invalid_license' });
    if (!lic.ativa) return res.status(403).json({ success: false, error: 'revoked' });
    if (!lic.lifetime && Date.now() > lic.expiraEm) return res.status(403).json({ success: false, error: 'expired' });
    if (!lic.installId) { lic.installId = fingerprint; lic.ativadaEm = Date.now(); await redisSet(key, JSON.stringify(lic)); }

    log('OK', `redeem OK: ${key}`);
    return res.json({
      success: true,
      data: {
        tier: 'premium', plan: lic.plano, expiresAt: lic.expiraEm, licenseKey: key,
        user: { id: 1, username: 'prolince_user', name: 'Prolince User', effective_tier: 'premium', effective_status: 'active', has_active_extension: true, has_active_credit: true, is_banned: false }
      }
    });
  } catch (e) {
    log('ERRO', 'redeem: ' + e.message);
    return res.status(500).json({ success: false, error: 'internal_error', message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// JETIX — DATA / CONFIG / PROXY / SYNC
// ═══════════════════════════════════════════════════════════════
app.get('/api/data/address', (req, res) => {
  const country = req.query.country || 'US';
  return res.json({
    success: true,
    data: { countryCode: country, zip: '10001', city: 'New York', state: 'NY', street: '123 Main St', line1: '123 Main St', line2: 'Apt 4B', phone: '555-0100', email: 'user@example.com', firstName: 'John', lastName: 'Doe' }
  });
});
app.get('/api/data/user', (req, res) => res.json({ success: true, data: { id: 1, username: 'prolince_user', name: 'Prolince User', tier: 'premium' } }));
app.get('/api/data/email', (req, res) => res.json({ success: true, data: { email: 'user@example.com' } }));
app.get('/api/news', (req, res) => res.json({ success: true, data: [] }));
app.get('/api/notifications', (req, res) => res.json({ success: true, data: [] }));
app.get('/api/config/selectors', (req, res) => res.json({ success: true, data: { selectors: {}, uiInteraction: null } }));
app.get('/api/site-config', (req, res) => res.json({ success: true, data: { name: 'Prolince', version: '2.0.0' } }));
app.get('/api/session-rules', (req, res) => res.json({ success: true, data: { rules: [] } }));

app.post('/api/tracking/log', (req, res) => { log('JETIX', `tracking: ${JSON.stringify(req.body).substring(0, 100)}`); res.json({ ok: true }); });
app.post('/api/stats/sync', (req, res) => { log('JETIX', `stats-sync: ${JSON.stringify(req.body).substring(0, 100)}`); res.json({ ok: true, received: true }); });
app.post('/api/bypass/instructions', (req, res) => res.json({ success: true, data: { instructions: [], rules: [] } }));
app.post('/api/proxy/test', (req, res) => res.json({ success: true, data: { ok: true, ip: '127.0.0.1' } }));
app.post('/api/proxy/test-geo', (req, res) => res.json({ success: true, data: { country: 'US', city: 'New York' } }));
app.post('/api/proxy/import', (req, res) => res.json({ success: true, data: { imported: 0 } }));
app.get('/api/proxy/export', (req, res) => res.json({ success: true, data: { proxies: [] } }));

// Email fictício
app.get('/api/email/domains', (req, res) => res.json({ success: true, data: { domains: ['example.com'] } }));
app.post('/api/email/create', (req, res) => res.json({ success: true, data: { email: 'user@example.com', token: 'tok_' + Date.now() } }));
app.get('/api/email/saved', (req, res) => res.json({ success: true, data: [] }));
app.post('/api/email/reconnect', (req, res) => res.json({ success: true, data: {} }));
app.get('/api/email/messages', (req, res) => res.json({ success: true, data: [] }));
app.get('/api/email/message', (req, res) => res.json({ success: true, data: {} }));
app.post('/api/email/delete-message', (req, res) => res.json({ success: true }));
app.post('/api/email/mark-message', (req, res) => res.json({ success: true }));
app.post('/api/email/delete-account', (req, res) => res.json({ success: true }));
app.post('/api/email/delete-saved', (req, res) => res.json({ success: true }));

// Sync
app.get('/api/sync/get', (req, res) => res.json({ success: true, data: {} }));
app.post('/api/sync/push', (req, res) => res.json({ success: true }));
app.post('/api/sync/push-bulk', (req, res) => res.json({ success: true }));

// Session verify (para o SW)
app.post('/api/session/verify', (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'missing_bearer' });
  try {
    const decoded = verifyToken(auth.substring(7));
    return res.json({ success: true, data: { valid: true, user: decoded } });
  } catch (e) {
    return res.status(401).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// PROLINCE — /v1/activate, /v1/verify, /v1/campaign
// ═══════════════════════════════════════════════════════════════
app.post('/v1/activate', async (req, res) => {
  const { installId, licenseKey } = req.body || {};
  log('ATIV', `installId=${installId || '?'} key=${licenseKey || '(vazia)'}`);
  if (!installId) return res.status(400).json({ error: 'missing_installId' });
  if (!PRIVATE_KEY) return res.status(500).json({ error: 'server_misconfigured' });
  if (!licenseKey) {
    const now = Math.floor(Date.now() / 1000);
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
  const now = Math.floor(Date.now() / 1000);
  const isLife = lic.plano === 'life';
  const expSec = isLife ? now + (100 * 365 * 24 * 60 * 60) : Math.floor(lic.expiraEm / 1000);
  const token = signToken({ sub: installId, tier: 'premium', plan: lic.plano, licenseKey: lic.chave, iat: now, exp: expSec });
  return res.json({ token, tier: 'premium', plan: lic.plano, expiresAt: lic.expiraEm, licenseKey: keyNorm });
});

app.post('/v1/verify', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok: false, error: 'missing_token' });
  try { return res.json({ ok: true, valido: true, dados: verifyToken(token) }); }
  catch (e) { return res.status(401).json({ ok: false, valido: false, erro: e.message }); }
});

app.get('/v1/campaign', (req, res) => res.json({ ok: true, campaign: null, serverTime: Date.now() }));

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

// ═══════════════════════════════════════════════════════════════
// 404 + BOOT
// ═══════════════════════════════════════════════════════════════
app.use((req, res) => res.status(404).json({ success: false, error: 'not_found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log('SYS', `Prolince v2.0.0 na porta ${PORT}`);
  log('SYS', `Redis: ${UPSTASH_URL ? 'OK' : 'FALTA'}`);
  log('SYS', `Chave EC: ${PRIVATE_KEY ? 'OK' : 'FALTA'}`);
  log('SYS', `Telegram: ${TELEGRAM_TOKEN ? 'OK' : 'FALTA'}`);
  log('SYS', `Owner ID: ${OWNER_ID || 'FALTA'}`);
  log('OK', `Rotas Jetix + Bot Telegram carregadas`);
});

process.on('uncaughtException', e => log('ERRO', 'Uncaught: ' + e.message));
process.on('unhandledRejection', e => log('ERRO', 'Rejection: ' + (e?.message || e)));
