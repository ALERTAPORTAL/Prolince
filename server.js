/* ═══════════════════════════════════════════════════════════════
   ✦ PROLINCE  ·  v1.0.0
   License Server · Telegram Bot · Chrome Extension API
   ═══════════════════════════════════════════════════════════════ */
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const UPSTASH_URL    = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN  = process.env.UPSTASH_REDIS_REST_TOKEN;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const OWNER_ID       = process.env.OWNER_ID;

// ── Chaves EC: Secret File primeiro, depois env, depois base64 ──
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
// REDIS — Upstash REST
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
  '15d':  { nome:'15 Dias',  dias:15,   preco:7,   emoji:'o', lifetime:false },
  '30d':  { nome:'30 Dias',  dias:30,   preco:12,  emoji:'o', lifetime:false },
  '45d':  { nome:'45 Dias',  dias:45,   preco:17,  emoji:'o', lifetime:false },
  '90d':  { nome:'3 Meses',  dias:90,   preco:30,  emoji:'*', lifetime:false },
  '180d': { nome:'6 Meses',  dias:180,  preco:45,  emoji:'*', lifetime:false },
  '1a':   { nome:'1 Ano',    dias:365,  preco:70,  emoji:'*', lifetime:false },
  'life': { nome:'LIFETIME', dias:36500, preco:190, emoji:'inf', lifetime:true },
};
const precoFmt = usd => `$${Number(usd).toFixed(2)}`;

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

const T = {
  pt: { menu_title:'PAINEL DE CONTROLE', menu_sub:'Selecione uma operação abaixo', online:'online', secure:'seguro', btn_generate:'Gerar Licenca', btn_mykeys:'Minhas Chaves', btn_stats:'Estatisticas', btn_link:'Vincular', btn_unlink:'Desvincular', btn_query:'Consultar', btn_prices:'Tabela de Precos', btn_support:'Suporte', btn_lang:'Idioma', btn_help:'Ajuda', btn_danger:'Zona de Perigo', btn_back:'Voltar', btn_menu:'Menu', btn_refresh:'Atualizar', btn_cancel:'Cancelar', welcome_title:'Bem-vindo ao Prolince', welcome_desc:'Para adquirir uma licenca premium, clique abaixo:', contact:'CONTACTAR SUPORTE', support_title:'Suporte', support_write:'Escreva sua mensagem agora:', support_sent:'MENSAGEM ENVIADA', support_cancelled:'Suporte cancelado', gen_title:'Gerar Licenca', gen_sub:'Escolha um plano abaixo:', gen_success:'LICENCA EMITIDA', gen_key:'Chave', gen_plan:'Plano', gen_price:'Preco', gen_issued:'Emitida', gen_expires:'Expira', gen_duration:'Duracao', gen_lifetime:'Lifetime', gen_never:'Nunca', list_title:'Minhas Licencas', list_empty:'Nenhuma licenca cadastrada.', stats_title:'Estatisticas', stats_total:'Total', stats_active:'Ativas', stats_expired:'Expiradas', stats_linked:'Vinculadas', stats_lifetime:'Lifetime', stats_revenue:'Receita', detail_title:'Detalhes da Licenca', detail_key:'Chave', detail_status:'Status', detail_active:'Ativa', detail_revoked:'Revogada', detail_install:'Install ID', detail_not_linked:'nao vinculada', detail_remaining:'Restante', act_link:'Vincular', act_unlink:'Desvincular', act_revoke:'Revogar', act_delete:'Deletar', prices_title:'Tabela de Precos', help_title:'Central de Ajuda' },
  en: { menu_title:'CONTROL PANEL', menu_sub:'Select an operation below', online:'online', secure:'secure', btn_generate:'Generate License', btn_mykeys:'My Keys', btn_stats:'Statistics', btn_link:'Link', btn_unlink:'Unlink', btn_query:'Query', btn_prices:'Price List', btn_support:'Support', btn_lang:'Language', btn_help:'Help', btn_danger:'Danger Zone', btn_back:'Back', btn_menu:'Menu', btn_refresh:'Refresh', btn_cancel:'Cancel', welcome_title:'Welcome to Prolince', welcome_desc:'To purchase a premium license, click below:', contact:'CONTACT SUPPORT', support_title:'Support', support_write:'Write your message now:', support_sent:'MESSAGE SENT', support_cancelled:'Support cancelled', gen_title:'Generate License', gen_sub:'Choose a plan below:', gen_success:'LICENSE ISSUED', gen_key:'Key', gen_plan:'Plan', gen_price:'Price', gen_issued:'Issued', gen_expires:'Expires', gen_duration:'Duration', gen_lifetime:'Lifetime', gen_never:'Never', list_title:'My Licenses', list_empty:'No licenses found.', stats_title:'Statistics', stats_total:'Total', stats_active:'Active', stats_expired:'Expired', stats_linked:'Linked', stats_lifetime:'Lifetime', stats_revenue:'Revenue', detail_title:'License Details', detail_key:'Key', detail_status:'Status', detail_active:'Active', detail_revoked:'Revoked', detail_install:'Install ID', detail_not_linked:'not linked', detail_remaining:'Remaining', act_link:'Link', act_unlink:'Unlink', act_revoke:'Revoke', act_delete:'Delete', prices_title:'Price List', help_title:'Help Center' }
};
function t(lang, key, vars={}) { let s = (T[lang] || T.pt)[key] || T.pt[key] || key; for (const k in vars) s = s.replace(`{${k}}`, vars[k]); return s; }

function menuPrincipal(lang='pt') {
  return { texto: `<b>PROLINCE  v1.0.0</b>\n<i>License Engine</i>\n\n<b>${t(lang,'menu_title')}</b>\n<code>----------------------</code>\n<i>${t(lang,'menu_sub')}</i>`, teclado: { inline_keyboard: [
    [{ text: t(lang,'btn_generate'), callback_data:'m_gerar' }],
    [{ text: t(lang,'btn_mykeys'), callback_data:'m_listar' }, { text: t(lang,'btn_stats'), callback_data:'m_stats' }],
    [{ text: t(lang,'btn_query'), callback_data:'m_consultar' }],
    [{ text: t(lang,'btn_prices'), callback_data:'m_precos' }],
    [{ text: t(lang,'btn_support'), callback_data:'m_contacto' }],
    [{ text: t(lang,'btn_lang'), callback_data:'m_lang' }],
    [{ text: t(lang,'btn_help'), callback_data:'m_ajuda' }, { text: t(lang,'btn_danger'), callback_data:'m_perigo' }]
  ] } };
}
async function cmdStart(chatId, msgId=null) { const lang = USER_LANG.get(String(chatId)) || 'pt'; const m = menuPrincipal(lang); if (msgId) await tgEdit(chatId, msgId, m.texto, m.teclado); else await tgSend(chatId, m.texto, m.teclado); }

async function handleCallback(cb) {
  const chatId = cb.message.chat.id, msgId = cb.message.message_id, data = cb.data, userId = String(cb.from.id);
  const isOwner = userId === String(OWNER_ID);
  const lang = USER_LANG.get(String(chatId)) || 'pt';

  if (data === 'm_lang') { await tgAnswer(cb.id); const kb = { inline_keyboard: [[{text:'Portugues',callback_data:'lang_pt'},{text:'English',callback_data:'lang_en'}],[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }; await tgEdit(chatId, msgId, `<b>PROLINCE</b>\n\n<b>Idioma / Language</b>`, kb); return; }
  if (data === 'lang_pt' || data === 'lang_en') { const novo = data === 'lang_pt' ? 'pt' : 'en'; USER_LANG.set(String(chatId), novo); await tgAnswer(cb.id, 'ok'); const m = menuPrincipal(novo); await tgEdit(chatId, msgId, m.texto, m.teclado); return; }

  if (!isOwner) {
    if (data === 'm_contacto') { SUPPORT_SESSIONS.set(String(chatId), { step:'waiting', ts: Date.now() }); await tgAnswer(cb.id, 'ok'); await tgEdit(chatId, msgId, `<b>${t(lang,'support_title')}</b>\n\n${t(lang,'support_write')}`, { inline_keyboard: [[{text:t(lang,'btn_cancel'),callback_data:'m_cancelar_suporte'}]] }); return; }
    if (data === 'm_cancelar_suporte') { SUPPORT_SESSIONS.delete(String(chatId)); await tgAnswer(cb.id, 'x'); await cmdStart(chatId, msgId); return; }
    if (data === 'm_home') { await tgAnswer(cb.id); await tgEdit(chatId, msgId, `<b>PROLINCE</b>\n\n${t(lang,'welcome_desc')}`, { inline_keyboard: [[{text:t(lang,'contact'),callback_data:'m_contacto'}]] }); return; }
    await tgAnswer(cb.id, 'x'); return;
  }

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
      kb.inline_keyboard.push([{ text: t(lang,'btn_back'), callback_data:'m_home' }]);
      await tgEdit(chatId, msgId, `<b>${t(lang,'gen_title')}</b>\n\n<i>${t(lang,'gen_sub')}</i>`, kb);
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
      await tgEdit(chatId, msgId, `<b>${t(lang,'gen_success')}</b>\n<code>----------------------</code>\n\n<b>${t(lang,'gen_key')}</b>\n<code>${chave}</code>\n\n<code>----------------------</code>\n<b>${p.nome}</b>\n<b>$</b> ${t(lang,'gen_price')}: ${precoFmt(p.preco)}\n<b>o</b> ${t(lang,'gen_issued')}: ${formatDate(agora)}\n<b>o</b> ${t(lang,'gen_expires')}: ${p.lifetime ? t(lang,'gen_never') : formatDate(expira)}`, { inline_keyboard: [[{text:t(lang,'btn_query'),callback_data:`c_${chave}`}],[{text:t(lang,'btn_menu'),callback_data:'m_home'}]] });
      return;
    }
    if (data === 'm_listar') { await tgAnswer(cb.id, 'ok'); const keys = await redisKeys('JETIX-*'); if (keys.length === 0) { await tgEdit(chatId, msgId, `<b>${t(lang,'list_title')}</b>\n\n<i>${t(lang,'list_empty')}</i>`, { inline_keyboard: [[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); return; } let txt = `<b>${t(lang,'list_title')} (${keys.length})</b>\n<code>----------------------</code>\n`; const inlineKb = []; for (let i = 0; i < Math.min(keys.length, 15); i++) { const l = await redisGet(keys[i]); if (!l) continue; const exp = l.lifetime ? 'inf' : humanTime((l.expiraEm||0) - Date.now()); txt += `<b>${l.ativa?'o':'x'}</b> <code>${keys[i]}</code>\n<i>${l.planoNome} - ${exp}</i>\n`; inlineKb.push([{text:`> ${keys[i].substring(0,18)}...`,callback_data:`c_${keys[i]}`}]); } inlineKb.push([{text:t(lang,'btn_refresh'),callback_data:'m_listar'},{text:t(lang,'btn_back'),callback_data:'m_home'}]); await tgEdit(chatId, msgId, txt, { inline_keyboard: inlineKb }); return; }
    if (data === 'm_stats') { await tgAnswer(cb.id, 'ok'); const keys = await redisKeys('JETIX-*'); let ativas=0, expiradas=0, vinc=0, life=0, receita=0; for (const k of keys) { const l = await redisGet(k); if (!l) continue; if (l.ativa) ativas++; if (!l.lifetime && l.expiraEm < Date.now()) expiradas++; if (l.installId) vinc++; if (l.lifetime) life++; if (l.preco) receita += Number(l.preco)||0; } const taxa = keys.length ? Math.round((ativas/keys.length)*100) : 0; await tgEdit(chatId, msgId, `<b>${t(lang,'stats_title')}</b>\n<code>----------------------</code>\n<b>#</b> ${t(lang,'stats_total')}: <code>${keys.length}</code>\n<b>o</b> ${t(lang,'stats_active')}: <code>${ativas}</code>\n<b>x</b> ${t(lang,'stats_expired')}: <code>${expiradas}</code>\n<b>*</b> ${t(lang,'stats_linked')}: <code>${vinc}</code>\n<b>inf</b> ${t(lang,'stats_lifetime')}: <code>${life}</code>\n<b>$</b> ${t(lang,'stats_revenue')}: <code>${precoFmt(receita)}</code>\n<code>${progressBar(taxa,15)}</code> ${taxa}%`, { inline_keyboard: [[{text:t(lang,'btn_refresh'),callback_data:'m_stats'},{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); return; }
    if (data === 'm_consultar') { await tgAnswer(cb.id); return tgEdit(chatId, msgId, `<b>${t(lang,'btn_query')}</b>\n<code>----------------------</code>\n<code>/status &lt;chave&gt;</code>`, { inline_keyboard: [[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); }
    if (data === 'm_precos') { await tgAnswer(cb.id); let txt = `<b>${t(lang,'prices_title')}</b>\n<code>----------------------</code>\n`; for (const [,p] of Object.entries(PACOTES)) { txt += `<b>${p.nome}</b> - <code>${precoFmt(p.preco)}</code>\n`; } await tgEdit(chatId, msgId, txt, { inline_keyboard: [[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); return; }
    if (data === 'm_contacto') { await tgAnswer(cb.id, 'ok'); SUPPORT_SESSIONS.set(String(chatId), { step:'waiting', ts: Date.now() }); await tgEdit(chatId, msgId, `<b>${t(lang,'support_title')}</b>\n\n${t(lang,'support_write')}`, { inline_keyboard: [[{text:t(lang,'btn_cancel'),callback_data:'m_cancelar_suporte'}]] }); return; }
    if (data === 'm_cancelar_suporte') { SUPPORT_SESSIONS.delete(String(chatId)); await tgAnswer(cb.id, 'x'); return cmdStart(chatId, msgId); }
    if (data === 'm_ajuda') { await tgAnswer(cb.id); await tgEdit(chatId, msgId, `<b>${t(lang,'help_title')}</b>\n<code>----------------------</code>\n<code>/start</code> Menu\n<code>/gerar</code> Gerar\n<code>/listar</code> Listar\n<code>/stats</code> Estatisticas\n<code>/status &lt;k&gt;</code>\n<code>/revogar &lt;k&gt;</code>\n<code>/deletar &lt;k&gt;</code>\n<code>/resp &lt;id&gt; &lt;msg&gt;</code>`, { inline_keyboard: [[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); return; }
    if (data === 'm_perigo') { await tgAnswer(cb.id, '!'); await tgEdit(chatId, msgId, `<b>${t(lang,'btn_danger')}</b>\n<code>----------------------</code>`, { inline_keyboard: [[{text:'Deletar ativas',callback_data:'danger_ativas'}],[{text:'Deletar TUDO',callback_data:'danger_tudo'}],[{text:t(lang,'btn_back'),callback_data:'m_home'}]] }); return; }
    if (data === 'danger_ativas') { await tgAnswer(cb.id); return tgEdit(chatId, msgId, `Confirmar: deletar ativas?`, { inline_keyboard: [[{text:'Sim',callback_data:'confirm_ativas'},{text:'Nao',callback_data:'m_perigo'}]] }); }
    if (data === 'danger_tudo') { await tgAnswer(cb.id); return tgEdit(chatId, msgId, `Confirmar: deletar TUDO?`, { inline_keyboard: [[{text:'Sim',callback_data:'confirm_tudo'},{text:'Nao',callback_data:'m_perigo'}]] }); }
    if (data === 'confirm_ativas') { await tgAnswer(cb.id); const keys = await redisKeys('JETIX-*'); let n=0; for (const k of keys) { const l = await redisGet(k); if (l && l.ativa) { await redisDel(k); n++; } } return tgEdit(chatId, msgId, `OK  ${n} licencas removidas.`, { inline_keyboard: [[{text:t(lang,'btn_menu'),callback_data:'m_home'}]] }); }
    if (data === 'confirm_tudo') { await tgAnswer(cb.id); const keys = await redisKeys('JETIX-*'); for (const k of keys) await redisDel(k); return tgEdit(chatId, msgId, `OK  ${keys.length} licencas removidas.`, { inline_keyboard: [[{text:t(lang,'btn_menu'),callback_data:'m_home'}]] }); }
    if (data.startsWith('c_')) { const k = data.substring(2), l = await redisGet(k); if (!l) { await tgAnswer(cb.id, 'x'); return; } await tgAnswer(cb.id); const resta = l.lifetime ? 'inf' : humanTime((l.expiraEm||0)-Date.now()); await tgEdit(chatId, msgId, `<b>${t(lang,'detail_title')}</b>\n<code>----------------------</code>\n<b>${t(lang,'detail_key')}</b>\n<code>${k}</code>\n<code>----------------------</code>\n<b>${l.planoNome}</b>\n<b>$</b> ${precoFmt(l.preco)}\n<b>o</b> ${formatDate(l.criadaEm)}\n<b>o</b> ${l.lifetime?t(lang,'gen_never'):formatDate(l.expiraEm)}\n<b>*</b> ${resta}\n<b>o</b> ${l.ativa?t(lang,'detail_active'):t(lang,'detail_revoked')}`, { inline_keyboard: [[{text:t(lang,'act_revoke'),callback_data:`rv_${k}`},{text:t(lang,'act_delete'),callback_data:`dl_${k}`}],[{text:t(lang,'btn_menu'),callback_data:'m_home'}]] }); return; }
    if (data.startsWith('rv_')) { const k = data.substring(3), l = await redisGet(k); if (l) { l.ativa = false; await redisSet(k, JSON.stringify(l)); } await tgAnswer(cb.id, 'x'); return tgEdit(chatId, msgId, `OK Revogada`, { inline_keyboard: [[{text:t(lang,'btn_back'),callback_data:`c_${k}`}]] }); }
    if (data.startsWith('dl_')) { const k = data.substring(3); await redisDel(k); await tgAnswer(cb.id, 'x'); return tgEdit(chatId, msgId, `OK Deletada`, { inline_keyboard: [[{text:t(lang,'btn_menu'),callback_data:'m_home'}]] }); }
    await tgAnswer(cb.id);
  } catch (e) { log('ERRO', 'Callback: ' + e.message); try { await tgAnswer(cb.id, 'x'); } catch {} }
}

async function handleMessage(msg) {
  const chatId = msg.chat.id, userId = String(msg.from.id);
  const texto = (msg.text || '').trim();
  const args = texto.replace(/\n/g,' ').split(' ').filter(a=>a.length>0);
  const cmd = (args[0] || '').toLowerCase();
  const isOwner = userId === String(OWNER_ID);
  const lang = USER_LANG.get(String(chatId)) || 'pt';
  const sessao = SUPPORT_SESSIONS.get(String(chatId));

  if (sessao && sessao.step === 'waiting') {
    if (cmd === '/cancelar') { SUPPORT_SESSIONS.delete(String(chatId)); await tgSend(chatId, t(lang,'support_cancelled')); return; }
    SUPPORT_SESSIONS.delete(String(chatId));
    const userInfo = `${msg.from.first_name||''} ${msg.from.last_name||''}`.trim() || 'Sem nome';
    await tgSend(chatId, `<b>${t(lang,'support_sent')}</b>`);
    if (!isOwner) await tgSend(OWNER_ID, `<b>NOVA MENSAGEM</b>\n<b>Nome:</b> ${userInfo}\n<b>Chat ID:</b> <code>${chatId}</code>\n\n${texto}\n\n<i>Responda com:</i>\n<code>/resp ${chatId} msg</code>`);
    return;
  }

  if (!isOwner) {
    if (cmd === '/start' || cmd === '/ajuda' || cmd === '/help' || cmd === '/lang') {
      if (cmd === '/lang') { await tgSend(chatId, `Idioma:`, { inline_keyboard: [[{text:'Portugues',callback_data:'lang_pt'},{text:'English',callback_data:'lang_en'}]] }); return; }
      await tgSend(chatId, `<b>PROLINCE</b>\n\n${t(lang,'welcome_desc')}`, { inline_keyboard: [[{text:t(lang,'contact'),callback_data:'m_contacto'}]] });
      return;
    }
    return;
  }

  try {
    if (cmd === '/start' || cmd === '/menu') { await cmdStart(chatId); return; }
    if (cmd === '/lang') { await tgSend(chatId, `Idioma:`, { inline_keyboard: [[{text:'Portugues',callback_data:'lang_pt'},{text:'English',callback_data:'lang_en'}]] }); return; }
    if (cmd === '/resp') { const target = args[1]; const resposta = args.slice(2).join(' '); if (!target || !resposta) { await tgSend(chatId, `/resp <chatId> <msg>`); return; } await tgSend(target, `<b>RESPOSTA DO SUPORTE</b>\n\n${resposta}`); await tgSend(chatId, `OK enviado para <code>${target}</code>`); return; }
    if (cmd === '/gerar') { const kb = { inline_keyboard: [] }; const entries = Object.entries(PACOTES); for (let i = 0; i < entries.length; i += 2) { const linha = [{text:`${entries[i][1].nome} - ${precoFmt(entries[i][1].preco)}`,callback_data:`g_${entries[i][0]}`}]; if (entries[i+1]) linha.push({text:`${entries[i+1][1].nome} - ${precoFmt(entries[i+1][1].preco)}`,callback_data:`g_${entries[i+1][0]}`}); kb.inline_keyboard.push(linha); } await tgSend(chatId, `<b>${t(lang,'gen_title')}</b>`, kb); return; }
    if (cmd === '/listar') { const keys = await redisKeys('JETIX-*'); if (keys.length === 0) { await tgSend(chatId, t(lang,'list_empty')); return; } let txt = `<b>${t(lang,'list_title')} (${keys.length})</b>\n`; for (let i = 0; i < Math.min(keys.length, 30); i++) { const l = await redisGet(keys[i]); if (!l) continue; const exp = l.lifetime ? 'inf' : humanTime((l.expiraEm||0)-Date.now()); txt += `<b>${l.ativa?'o':'x'}</b> <code>${keys[i]}</code>\n<i>${l.planoNome} - ${exp}</i>\n`; } await tgSend(chatId, txt); return; }
    if (cmd === '/status') { const k = args[1]; if (!k) { await tgSend(chatId, `/status <chave>`); return; } const l = await redisGet(k); if (!l) { await tgSend(chatId, `Nao encontrada`); return; } const resta = l.lifetime ? 'inf' : humanTime((l.expiraEm||0)-Date.now()); await tgSend(chatId, `<b>${t(lang,'detail_title')}</b>\n<b>${t(lang,'detail_key')}:</b> <code>${k}</code>\n<b>${l.planoNome}</b>\n<b>$</b> ${precoFmt(l.preco)}\n<b>o</b> ${formatDate(l.criadaEm)}\n<b>o</b> ${l.lifetime?t(lang,'gen_never'):formatDate(l.expiraEm)}\n<b>*</b> ${resta}\n<b>o</b> ${l.ativa?t(lang,'detail_active'):t(lang,'detail_revoked')}`); return; }
    if (cmd === '/revogar') { const k = args[1]; if (!k) return tgSend(chatId, `/revogar <chave>`); const l = await redisGet(k); if (!l) return tgSend(chatId, `Nao encontrada`); l.ativa = false; await redisSet(k, JSON.stringify(l)); await tgSend(chatId, `Revogada`); return; }
    if (cmd === '/deletar') { const k = args[1]; if (!k) return tgSend(chatId, `/deletar <chave>`); await redisDel(k); await tgSend(chatId, `Deletada: <code>${k}</code>`); return; }
    if (cmd === '/deletartudo') { const keys = await redisKeys('JETIX-*'); for (const k of keys) await redisDel(k); await tgSend(chatId, `<b>${keys.length}</b> licencas apagadas.`); return; }
    if (cmd === '/stats') { const keys = await redisKeys('JETIX-*'); let ativas=0, exp=0, vinc=0, life=0, receita=0; for (const k of keys) { const l = await redisGet(k); if (!l) continue; if (l.ativa) ativas++; if (!l.lifetime && l.expiraEm < Date.now()) exp++; if (l.installId) vinc++; if (l.lifetime) life++; if (l.preco) receita += Number(l.preco)||0; } await tgSend(chatId, `<b>${t(lang,'stats_title')}</b>\n<b>#</b> ${t(lang,'stats_total')}: <code>${keys.length}</code>\n<b>o</b> ${t(lang,'stats_active')}: <code>${ativas}</code>\n<b>x</b> ${t(lang,'stats_expired')}: <code>${exp}</code>\n<b>*</b> ${t(lang,'stats_linked')}: <code>${vinc}</code>\n<b>inf</b> ${t(lang,'stats_lifetime')}: <code>${life}</code>\n<b>$</b> ${t(lang,'stats_revenue')}: <code>${precoFmt(receita)}</code>`); return; }
    await tgSend(chatId, `Use /start`);
  } catch (e) { log('ERRO', 'Message: ' + e.message); }
}

// ═══════════════════════════════════════════════════════════════
// ROTAS HTTP
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ ok: true, service: 'prolince', version: '1.0.0' }));
app.get('/health', (req, res) => res.json({ ok: true, uptime: Math.floor(process.uptime()) }));
app.get('/v1/health', (req, res) => res.json({ ok: true, status: 'healthy', version: '1.0.0', timestamp: new Date().toISOString() }));

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
  log('OK',  `Bot Telegram completo (menu, gerar, listar, stats, /resp)`);
  log('OK',  `Rota /telegram-webhook ativa`);
});

process.on('uncaughtException', e => log('ERRO', 'Uncaught: ' + e.message));
process.on('unhandledRejection', e => log('ERRO', 'Rejection: ' + (e?.message || e)));
