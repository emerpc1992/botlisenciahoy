// ============================================================
// server.js  -- VIXPRO-BOT
// Servidor OAuth2 + PKCE para la API NUEVA de Deriv
// (developers.deriv.com / api.derivws.com)
// Desplegado en Render (servicio Web gratuito, Node persistente)
// ============================================================
//
// IMPORTANTE - version corregida conforme a la documentacion
// oficial de Deriv (developers.deriv.com/docs/intro/oauth/):
//
//   - Las apps OAuth2 de Deriv son CLIENTES PUBLICOS. NO usan
//     client_secret en ningun momento del flujo. La seguridad la
//     da PKCE (code_verifier / code_challenge), no un secreto
//     compartido. Por eso este archivo NO tiene ni necesita
//     DERIV_CLIENT_SECRET.
//   - El endpoint de autorizacion y el de intercambio de token
//     estan en el MISMO dominio: auth.deriv.com (no oauth.deriv.com).
//   - El access_token es de corta duracion (expires_in ~3600s) y
//     viene con un refresh_token para renovarlo sin pedir login de
//     nuevo. Este servidor expone /api/refresh para eso.
//   - Las llamadas REST a la API de trading requieren DOS headers:
//     "Deriv-App-ID: <client_id>" y "Authorization: Bearer <token>".
//     (Eso lo hace el bot Python directamente, este servidor solo
//     entrega el token).
//
// Endpoints:
//   GET  /                  -> pagina simple "VIXPRO-BOT"
//   GET  /health            -> chequeo de vida + redirect_uri calculada
//   GET  /auth/start.json   -> genera PKCE + state, devuelve auth_url
//   GET  /callback          -> Deriv redirige aca tras login/consentimiento
//   GET  /api/token         -> el bot Python hace polling aca
//   POST /api/refresh       -> renueva un access_token vencido
//   POST /api/v1/activate|validate, GET /api/v1/info -> licencias VIXPRO (bot)
//   /api/admin/ping|state|poll|answer|snapshot       -> licencias VIXPRO (panel)
//
// Variables de entorno a configurar en Render (Dashboard -> tu
// servicio -> Environment):
//   DERIV_CLIENT_ID   = 33AAhTttdb54bShIXnfqZ   (tu app_id real, publico)
//   PUBLIC_BASE_URL   = https://TU-SERVICIO.onrender.com
//                       (la URL real que asigna Render tras el
//                       primer deploy)
//
// YA NO HACE FALTA DERIV_CLIENT_SECRET. Si la tenes configurada en
// Render, podes borrarla o dejarla, no se usa en absoluto.
//
// Redirect URI a registrar en tu app de Deriv (Dashboard -> Applications):
//   https://TU-SERVICIO.onrender.com/callback
//
// ============================================================

import express from 'express';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

const DERIV_CLIENT_ID = process.env.DERIV_CLIENT_ID || 'TU_CLIENT_ID_AQUI';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://CAMBIAR-ESTO.onrender.com').replace(/\/+$/, '');
const REDIRECT_URI = `${PUBLIC_BASE_URL}/callback`;
const DERIV_SCOPE = 'trade account_manage'; // espacio normal, NO '+'

// Ambos endpoints viven en el mismo dominio: auth.deriv.com
const AUTH_URL = 'https://auth.deriv.com/oauth2/auth';
const TOKEN_URL = 'https://auth.deriv.com/oauth2/token';

// Almacenamiento temporal en memoria: state -> sesion.
// Se reinicia si Render reinicia el proceso (free tier duerme tras
// ~15 min sin trafico). No es grave: simplemente reintentas el login.
const sessions = new Map();

function log(...args) {
  console.log(new Date().toISOString(), '|', ...args);
}

if (DERIV_CLIENT_ID === 'TU_CLIENT_ID_AQUI') {
  log('ADVERTENCIA: DERIV_CLIENT_ID no esta configurado.');
}
if (PUBLIC_BASE_URL.includes('CAMBIAR-ESTO')) {
  log('ADVERTENCIA: PUBLIC_BASE_URL no esta configurado con tu URL real de Render.');
}

// Limpieza de sesiones viejas (>10 min)
setInterval(() => {
  const now = Date.now();
  for (const [state, session] of sessions.entries()) {
    if (now - session.createdAt > 10 * 60 * 1000) {
      sessions.delete(state);
      log('Sesion expirada eliminada:', state);
    }
  }
}, 60 * 1000);

function base64url(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier() {
  return base64url(crypto.randomBytes(48));
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64url(hash);
}

app.use(express.json({ limit: '5mb' })); // 5mb: la copia de licencias del panel VIXPRO puede ser grande

// ==============================================================
//  MODULO DE LICENCIAS -- DAKO-BOT
// ==============================================================
// Sistema simple de activacion por correo, controlado desde el
// Panel de Control (dako_admin_panel.py). Guarda todo en un JSON
// en disco. En el plan free de Render el disco es efimero (se
// pierde en cada redeploy), pero sobrevive mientras el servicio
// esta arriba -- igual que el Map de "sessions" de OAuth de mas
// arriba. Si mas adelante queres persistencia real, este es el
// unico lugar que habria que cambiar por una base de datos.
//
// Reglas de negocio:
//  - Un correo nuevo se registra ACTIVO, con N dias de vigencia desde
//    el momento del registro, donde N es "trial_days" (por defecto 7,
//    ver LICENSE_DAYS_DEFAULT mas abajo) -- editable en caliente desde
//    el Panel de Control ("🎓 Días de prueba" + GUARDAR), sin reiniciar
//    el servidor.
//  - Cada vez que el admin ACTIVA manualmente una cuenta, se le
//    recargan otros N dias completos desde ese momento (mismo N).
//  - Si el admin DESACTIVA manualmente, la cuenta queda inactiva
//    sin importar cuantos dias le quedaban.
//  - Si se cumplen los N dias sin intervencion del admin, la
//    cuenta pasa a inactiva sola (chequeo perezoso: se evalua
//    cada vez que se lee el estado).
// ==============================================================

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LICENSES_FILE = path.join(__dirname, 'data', 'licenses.json');
const ADMIN_KEY = process.env.ADMIN_KEY || 'dako-admin-2024';
// Valor de arranque si el archivo de datos todavia no tiene un ajuste
// guardado (primera vez que corre el servidor, o archivo viejo). A
// partir de ahi, el numero real que se usa es el que esta guardado en
// data.settings.trial_days, editable desde el Panel de Control
// (boton "🎓 Días de prueba" + GUARDAR) via /api/admin/settings.
const LICENSE_DAYS_DEFAULT = 7;

function loadLicenses() {
  try {
    if (!fs.existsSync(LICENSES_FILE)) {
      return { accounts: {}, messages: [], next_msg_id: 1, resets: {}, settings: { trial_days: LICENSE_DAYS_DEFAULT } };
    }
    const raw = fs.readFileSync(LICENSES_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (!data.accounts) data.accounts = {};
    if (!data.messages) data.messages = [];
    if (!data.next_msg_id) data.next_msg_id = 1;
    if (!data.resets) data.resets = {};
    if (!data.settings) data.settings = {};
    if (!data.settings.trial_days) data.settings.trial_days = LICENSE_DAYS_DEFAULT;
    return data;
  } catch (e) {
    log('Error leyendo licenses.json:', e.message);
    return { accounts: {}, messages: [], next_msg_id: 1, resets: {}, settings: { trial_days: LICENSE_DAYS_DEFAULT } };
  }
}

// Numero de dias de prueba que se le asigna a una cuenta NUEVA al
// registrarse, y el que se recarga cada vez que el admin ACTIVA
// manualmente una cuenta. Editable en caliente desde el panel, sin
// reiniciar el servidor ni tocar codigo.
function getTrialDays(data) {
  const n = Number(data && data.settings && data.settings.trial_days);
  return (Number.isFinite(n) && n > 0) ? n : LICENSE_DAYS_DEFAULT;
}

function saveLicenses(data) {
  try {
    fs.mkdirSync(path.dirname(LICENSES_FILE), { recursive: true });
    fs.writeFileSync(LICENSES_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    log('Error guardando licenses.json:', e.message);
  }
}

function normEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// Aplica la regla de expiracion automatica de 30 dias a una cuenta
// y devuelve si quedo activa. Muta el objeto "acc" si corresponde.
function applyExpiry(acc) {
  if (acc.active && acc.expires_at) {
    if (Date.now() > new Date(acc.expires_at).getTime()) {
      acc.active = false;
      acc.deactivated_reason = 'auto_expired';
    }
  }
  return acc.active;
}

function accountView(email, acc) {
  const now = Date.now();
  const expiresMs = acc.expires_at ? new Date(acc.expires_at).getTime() : null;
  const daysLeft = (acc.active && expiresMs) ? Math.max(0, Math.ceil((expiresMs - now) / 86400000)) : 0;
  return {
    email,
    active: acc.active,
    registered_at: acc.registered_at,
    activated_at: acc.activated_at,
    expires_at: acc.expires_at,
    days_left: daysLeft,
    deactivated_reason: acc.deactivated_reason || null,
  };
}

function requireAdmin(req, res, next) {
  const key = req.get('X-Admin-Key') || req.query.admin_key;
  if (key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'admin_key invalido' });
  }
  next();
}

// ------------------------------------------------------------
// Registro / login del bot con un correo. Idempotente: si el
// correo ya existe simplemente devuelve su estado actual (no
// reinicia los 30 dias).
// ------------------------------------------------------------
app.post('/api/license/register', (req, res) => {
  const email = normEmail(req.body && req.body.email);
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'correo invalido' });
  }
  const data = loadLicenses();
  if (!data.accounts[email]) {
    const now = new Date();
    const trialDays = getTrialDays(data);
    const expires = new Date(now.getTime() + trialDays * 86400000);
    data.accounts[email] = {
      registered_at: now.toISOString(),
      activated_at: now.toISOString(),
      expires_at: expires.toISOString(),
      active: true,
      deactivated_reason: null,
    };
    saveLicenses(data);
    log('Nuevo registro de licencia:', email, `(${trialDays} dias de prueba)`);
  }
  const acc = data.accounts[email];
  applyExpiry(acc);
  saveLicenses(data);
  res.json(accountView(email, acc));
});

// ------------------------------------------------------------
// El bot consulta periodicamente su propio estado con esto.
// ------------------------------------------------------------
app.get('/api/license/status', (req, res) => {
  const email = normEmail(req.query.email);
  const data = loadLicenses();

  // Si el admin pidio reiniciar esta cuenta desde el panel, avisamos
  // al bot con "reset: true" en lugar del estado normal. El bot,
  // al verlo, borra su correo guardado localmente y vuelve a pedirlo
  // como si fuera la primera vez. Se consume una sola vez (se borra
  // la marca apenas se entrega), asi el bot no queda reiniciandose
  // en cada poll.
  if (data.resets && data.resets[email]) {
    delete data.resets[email];
    saveLicenses(data);
    log('Reset entregado al bot:', email);
    return res.json({ email, reset: true, active: false });
  }

  const acc = data.accounts[email];
  if (!acc) return res.status(404).json({ error: 'correo no registrado', active: false });
  const wasActive = acc.active;
  applyExpiry(acc);
  if (wasActive !== acc.active) saveLicenses(data);
  res.json(accountView(email, acc));
});

// ------------------------------------------------------------
// El bot hace polling de mensajes nuevos dirigidos a su correo
// o de difusion general ("*"), pasando el ultimo id que ya vio.
// ------------------------------------------------------------
app.get('/api/license/messages', (req, res) => {
  const email = normEmail(req.query.email);
  const sinceId = parseInt(req.query.since_id || '0', 10) || 0;
  const data = loadLicenses();
  const msgs = data.messages.filter(
    (m) => m.id > sinceId && (m.to === '*' || m.to === email)
  );
  res.json({ messages: msgs });
});

// ------------------------------------------------------------
// Endpoints de administracion (protegidos con X-Admin-Key).
// Los usa dako_admin_panel.py.
// ------------------------------------------------------------
app.get('/api/admin/accounts', requireAdmin, (req, res) => {
  const data = loadLicenses();
  let changed = false;
  const list = Object.entries(data.accounts).map(([email, acc]) => {
    const before = acc.active;
    applyExpiry(acc);
    if (before !== acc.active) changed = true;
    return accountView(email, acc);
  });
  if (changed) saveLicenses(data);
  list.sort((a, b) => (a.registered_at < b.registered_at ? 1 : -1));
  res.json({ accounts: list });
});

// ------------------------------------------------------------
// Ajustes generales (por ahora solo los dias de prueba por
// defecto). Lo usa el boton "🎓 Días de prueba" + GUARDAR del panel
// de control. Afecta a las cuentas que se registren/activen de aca
// en adelante -- no toca la fecha de vencimiento de cuentas ya
// existentes.
// ------------------------------------------------------------
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  const data = loadLicenses();
  res.json({ trial_days: getTrialDays(data) });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const raw = req.body && req.body.trial_days;
  const days = Number(raw);
  if (!Number.isFinite(days) || days <= 0 || days > 3650) {
    return res.status(400).json({ error: 'trial_days invalido (debe ser un numero entre 1 y 3650)' });
  }
  const data = loadLicenses();
  if (!data.settings) data.settings = {};
  data.settings.trial_days = Math.round(days);
  saveLicenses(data);
  log('Dias de prueba actualizados desde el panel:', data.settings.trial_days);
  res.json({ ok: true, trial_days: data.settings.trial_days });
});

app.post('/api/admin/accounts/:email/activate', requireAdmin, (req, res) => {
  const email = normEmail(req.params.email);
  const data = loadLicenses();
  const now = new Date();
  const trialDays = getTrialDays(data);
  const expires = new Date(now.getTime() + trialDays * 86400000);
  if (!data.accounts[email]) {
    data.accounts[email] = { registered_at: now.toISOString() };
  }
  Object.assign(data.accounts[email], {
    active: true,
    activated_at: now.toISOString(),
    expires_at: expires.toISOString(),
    deactivated_reason: null,
  });
  saveLicenses(data);
  log('Cuenta activada manualmente:', email, `(+${trialDays} dias)`);
  res.json(accountView(email, data.accounts[email]));
});

app.post('/api/admin/accounts/:email/deactivate', requireAdmin, (req, res) => {
  const email = normEmail(req.params.email);
  const data = loadLicenses();
  if (!data.accounts[email]) return res.status(404).json({ error: 'correo no registrado' });
  data.accounts[email].active = false;
  data.accounts[email].deactivated_reason = 'manual';
  saveLicenses(data);
  log('Cuenta desactivada manualmente:', email);
  res.json(accountView(email, data.accounts[email]));
});

// ------------------------------------------------------------
// Editar manualmente la fecha de vencimiento/bloqueo de una
// cuenta (boton "FECHA" del panel de control). Esta ruta faltaba
// por completo -- por eso el boton nunca funcionaba (404).
// ------------------------------------------------------------
app.post('/api/admin/accounts/:email/expiry', requireAdmin, (req, res) => {
  const email = normEmail(req.params.email);
  const expiresAt = req.body && req.body.expires_at;
  if (!expiresAt) {
    return res.status(400).json({ error: 'falta expires_at en el body' });
  }
  const parsed = new Date(expiresAt);
  if (isNaN(parsed.getTime())) {
    return res.status(400).json({ error: 'expires_at invalido' });
  }
  const data = loadLicenses();
  const now = new Date();
  if (!data.accounts[email]) {
    data.accounts[email] = { registered_at: now.toISOString(), activated_at: now.toISOString() };
  }
  const acc = data.accounts[email];
  acc.expires_at = parsed.toISOString();
  // Si la nueva fecha esta en el futuro, la cuenta queda activa
  // (permite reactivar extendiendo la fecha directamente, sin
  // tener que pasar tambien por el boton ACTIVAR). Si la fecha
  // queda en el pasado, se bloquea de una vez.
  if (parsed.getTime() > now.getTime()) {
    acc.active = true;
    acc.deactivated_reason = null;
  } else {
    acc.active = false;
    acc.deactivated_reason = 'manual';
  }
  saveLicenses(data);
  log('Fecha de vencimiento editada manualmente:', email, '->', acc.expires_at);
  res.json(accountView(email, acc));
});

app.delete('/api/admin/accounts/:email', requireAdmin, (req, res) => {
  const email = normEmail(req.params.email);
  const data = loadLicenses();
  delete data.accounts[email];
  saveLicenses(data);
  res.json({ ok: true });
});

// ------------------------------------------------------------
// Reiniciar una cuenta desde el panel: borra el registro del
// servidor (vuelve a quedar "en 0", sin dias consumidos) y deja
// marcada la cuenta para que, la proxima vez que el bot de esa
// persona consulte su estado, se le pida el correo de nuevo (ver
// GET /api/license/status). No requiere que el bot este conectado
// en este momento: la marca queda guardada hasta que el bot haga
// su proximo chequeo periodico.
// ------------------------------------------------------------
app.post('/api/admin/accounts/:email/reset', requireAdmin, (req, res) => {
  const email = normEmail(req.params.email);
  const data = loadLicenses();
  delete data.accounts[email];
  data.resets[email] = true;
  saveLicenses(data);
  log('Reset solicitado desde el panel para:', email);
  res.json({ ok: true, email });
});

// ------------------------------------------------------------
// El admin envia un mensaje que aparecera en la ventana del bot.
// to = "*" para difundir a todos, o un correo especifico.
// ------------------------------------------------------------
app.post('/api/admin/message', requireAdmin, (req, res) => {
  const to = normEmail(req.body && req.body.to) || '*';
  const text = String((req.body && req.body.text) || '').trim();
  if (!text) return res.status(400).json({ error: 'mensaje vacio' });
  const data = loadLicenses();
  const msg = {
    id: data.next_msg_id++,
    to,
    text,
    created_at: new Date().toISOString(),
  };
  data.messages.push(msg);
  // Nos quedamos solo con los ultimos 300 mensajes para no crecer sin limite.
  if (data.messages.length > 300) data.messages = data.messages.slice(-300);
  saveLicenses(data);
  res.json({ ok: true, message: msg });
});

app.get('/api/admin/messages', requireAdmin, (req, res) => {
  const data = loadLicenses();
  res.json({ messages: data.messages.slice(-200) });
});

// ==============================================================
//  LICENCIAS VIXPRO -- RELE ENTRE LOS BOTS Y EL PANEL (vixpro_admin.py)
// ==============================================================
// Este servidor NO guarda las licencias de VIXPRO: la base de datos
// vive dentro del panel (vixpro_admin.py, en la PC del administrador).
// Aca solo se conectan los bots con el panel para verificar cuentas:
//
//   bot --(activate/validate)--> servidor --(cola)--> panel
//        (decide con su base de datos) --> servidor --> bot
//
//  - El panel mantiene una "larga espera" (POST /api/admin/poll) y
//    responde cada consulta con POST /api/admin/answer.
//  - Al conectarse (y tras cada cambio) el panel envia una COPIA de las
//    licencias (PUT /api/admin/snapshot) que se guarda SOLO en memoria.
//    Con el panel apagado, el servidor sigue verificando (validate) a
//    los clientes ya registrados con esa copia. Registrar clientes
//    nuevos requiere el panel encendido.
//  - Si Render reinicia el servicio se pierde la copia; el panel la
//    reenvia solo al detectarlo. Mientras tanto se responde
//    "unavailable" y el bot NO borra nada (usa su gracia sin conexion).
//  - Toda respuesta al bot va FIRMADA (HMAC-SHA256 con LICENSE_SECRET) y
//    repite el "nonce" que envio el bot.
//  - Solo puede haber UN panel conectado a la vez.
//
// Variables de entorno (Render -> Environment):
//   LICENSE_SECRET   = firma de las respuestas (igual que en ORO.py)
//   ADMIN_USER + ADMIN_PASSWORD = usuario y clave del panel
//   (o ADMIN_KEY, una sola clave: el panel la acepta con usuario vacio)
//
// Estas rutas (/api/v1/* y /api/admin/{ping,state,poll,answer,snapshot})
// NO tocan el OAuth de Deriv ni el modulo de licencias DAKO de arriba.
// ==============================================================

const V_LICENSE_SECRET = (process.env.LICENSE_SECRET || '').trim();
const V_ADMIN_USER = (process.env.ADMIN_USER || '').trim();
const V_ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();
const V_ADMIN_KEY = (process.env.ADMIN_KEY || '').trim(); // sin valor por defecto: si no esta en el entorno, no vale
const V_ADMIN_TTL_MS = Number(process.env.RELAY_ADMIN_TTL_MS) || 40000; // sin noticias del panel -> desconectado
const V_ANSWER_TIMEOUT_MS = Number(process.env.RELAY_ANSWER_TIMEOUT_MS) || 12000;

const V_DEFAULT_SETTINGS = {
  trial_days: '10',
  announcement: '',
  contact_phone: '50372997249',
  contact_email: 'vixprosv@gmail.com',
  grace_hours: '24',
};
const V_EMAIL_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
const V_DEVICE_RE = /^[0-9a-f]{16,64}$/;

class AdminConflict extends Error {}

const relay = {
  pending: [], // consultas de bots esperando al panel
  waiters: new Map(), // rid -> { resolve, timer }
  pollers: [], // largas esperas del panel { resolve, timer }
  adminId: '',
  adminSeen: 0,
  snapshot: null,
  snapshotVersion: 0,
  snapshotAt: 0,
  settings: { ...V_DEFAULT_SETTINGS },
  seen: new Map(), // conexiones atendidas con la copia mientras el panel estaba apagado
};

if (!V_LICENSE_SECRET) log('ADVERTENCIA: LICENSE_SECRET no esta configurado: las licencias VIXPRO responderan 503.');
if (!(V_ADMIN_KEY || (V_ADMIN_USER && V_ADMIN_PASSWORD))) {
  log('ADVERTENCIA: faltan ADMIN_USER y ADMIN_PASSWORD (o ADMIN_KEY): el panel VIXPRO no podra conectarse.');
}

// ---- limitador de solicitudes (en memoria) ----
const vHits = new Map();
function vPrune(key, windowMs) {
  const now = Date.now();
  const arr = (vHits.get(key) || []).filter((t) => now - t <= windowMs);
  vHits.set(key, arr);
  return arr;
}
function vAllow(key, limit, windowMs) {
  const arr = vPrune(key, windowMs);
  if (arr.length >= limit) return false;
  arr.push(Date.now());
  return true;
}
function vCount(key, windowMs) {
  return vPrune(key, windowMs).length;
}
setInterval(() => {
  for (const key of [...vHits.keys()]) if (vPrune(key, 600000).length === 0) vHits.delete(key);
}, 5 * 60 * 1000).unref();

function vIso(d = new Date()) {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function vClientIp(req) {
  const fwd = req.get('x-forwarded-for') || '';
  return (fwd ? fwd.split(',')[0].trim() : req.socket.remoteAddress || '').slice(0, 64);
}

// JSON "canonico" (claves ordenadas, sin espacios): debe coincidir con el del bot y el panel.
function vCanon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(vCanon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + vCanon(v[k])).join(',') + '}';
}
function vSign(body) {
  const rest = { ...body };
  delete rest.sig;
  return crypto.createHmac('sha256', V_LICENSE_SECRET).update(vCanon(rest), 'utf8').digest('hex');
}
function vSafeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function vMessage(status, cfg) {
  const contact = `Contacta a ${cfg.contact_phone} o ${cfg.contact_email}`;
  return (
    {
      expired: `Licencia expirada. ${contact}`,
      blocked: `Cuenta bloqueada. ${contact}`,
      no_trial: `La prueba gratis de este equipo ya fue utilizada. ${contact}`,
      device_limit: `Esta licencia ya está activa en otro equipo. ${contact}`,
      not_found: 'Licencia no encontrada. Registra tu correo para comenzar.',
      bad_request: 'Solicitud inválida.',
      unavailable:
        'El servidor de licencias está en mantenimiento en este momento (el administrador no está conectado). Inténtalo de nuevo en unos minutos.',
    }[status] || ''
  );
}

// Convierte la decision del panel en la respuesta FIRMADA que recibe el bot. El vencimiento y los
// dias restantes se calculan aqui, con la hora del servidor.
function vReply(res, result, nonce, http = 200, message = null) {
  const cfg = relay.settings;
  const now = new Date();
  let status = result.status;
  let kind = '';
  let expiresAt = '';
  let days = 0;
  if (status === 'license') {
    const left = (new Date(result.expires_at).getTime() - now.getTime()) / 1000;
    kind = result.kind || 'paid';
    if (left <= 0) {
      status = 'expired';
    } else {
      status = kind === 'trial' ? 'trial' : 'active';
      days = Math.ceil(left / 86400);
    }
    expiresAt = result.expires_at;
  }
  const body = {
    ok: status === 'trial' || status === 'active',
    status,
    email: result.email || '',
    kind,
    days_left: days,
    expires_at: expiresAt,
    server_time: vIso(now),
    nonce,
    message: message !== null ? message : vMessage(status, cfg),
    announcement: cfg.announcement,
    contact_phone: cfg.contact_phone,
    contact_email: cfg.contact_email,
    grace_hours: parseInt(cfg.grace_hours, 10) || 24,
  };
  body.sig = vSign(body);
  return res.status(http).json(body);
}

// Decide con la copia cuando el panel esta apagado. null = no puede decidir con seguridad.
function vSnapshotLookup(snap, email, deviceId) {
  if (!snap) return null;
  const blocked = Array.isArray(snap.blocked_devices) ? snap.blocked_devices : [];
  const bound = snap.bound || {};
  const lics = snap.licenses || {};
  if (blocked.includes(deviceId)) return { status: 'blocked', email: bound[deviceId] || email };
  const owner = bound[deviceId];
  const lic = owner ? lics[owner] : null;
  if (!lic) return null;
  if (lic.blocked) return { status: 'blocked', email: owner };
  return { status: 'license', email: owner, kind: lic.kind, expires_at: lic.expires_at };
}

// ---- cola entre los bots y el panel ----
function relayAdminOnline() {
  return Date.now() - relay.adminSeen < V_ADMIN_TTL_MS;
}
function relayTouch(adminId) {
  const now = Date.now();
  if (relay.adminId && relay.adminId !== adminId && now - relay.adminSeen < V_ADMIN_TTL_MS) {
    throw new AdminConflict('Ya hay otro panel de administración conectado (la base de datos es única).');
  }
  relay.adminId = adminId;
  relay.adminSeen = now;
}
function relayDrain() {
  return relay.pending.splice(0, 20);
}
function relayWake() {
  while (relay.pollers.length && relay.pending.length) {
    const p = relay.pollers.shift();
    clearTimeout(p.timer);
    p.resolve(relayDrain());
  }
}
// Pone una consulta en cola y espera la respuesta del panel (null si no llega a tiempo).
function relaySubmit(req, timeoutMs) {
  return new Promise((resolve) => {
    const rid = crypto.randomUUID().replace(/-/g, '');
    const timer = setTimeout(() => {
      relay.waiters.delete(rid);
      relay.pending = relay.pending.filter((p) => p.rid !== rid);
      resolve(null);
    }, timeoutMs);
    relay.waiters.set(rid, { resolve, timer });
    relay.pending.push({ ...req, rid });
    relayWake();
  });
}
function relayAnswer(rid, result) {
  const w = relay.waiters.get(rid);
  if (!w) return false;
  clearTimeout(w.timer);
  relay.waiters.delete(rid);
  w.resolve(result);
  return true;
}
// Larga espera del panel: devuelve { promise, cancel }.
function relayPollStart(adminId, waitMs) {
  relayTouch(adminId);
  for (const old of relay.pollers.splice(0)) {
    clearTimeout(old.timer);
    old.resolve([]); // un poll anterior colgado del mismo panel se cierra
  }
  const p = { resolve: null, timer: null };
  const promise = new Promise((resolve) => {
    p.resolve = resolve;
    if (relay.pending.length) return resolve(relayDrain());
    if (waitMs <= 0) return resolve([]);
    p.timer = setTimeout(() => {
      const i = relay.pollers.indexOf(p);
      if (i >= 0) relay.pollers.splice(i, 1);
      resolve([]);
    }, waitMs);
    relay.pollers.push(p);
  });
  const cancel = () => {
    const i = relay.pollers.indexOf(p);
    if (i >= 0) {
      relay.pollers.splice(i, 1);
      clearTimeout(p.timer);
      p.resolve([]);
    }
  };
  return { promise, cancel };
}
function relayMergeSettings(cfg) {
  if (!cfg || typeof cfg !== 'object') return;
  for (const k of Object.keys(V_DEFAULT_SETTINGS)) if (k in cfg) relay.settings[k] = String(cfg[k]);
}

// ---- API del bot ----
async function vClientCall(req, res, create) {
  try {
    if (!V_LICENSE_SECRET) {
      return res.status(503).json({ ok: false, status: 'server_error', message: 'Servidor sin LICENSE_SECRET' });
    }
    const ip = vClientIp(req);
    if (!vAllow('c:' + ip, 90, 60000)) {
      return res.status(429).json({ ok: false, status: 'rate_limited', message: 'Demasiadas solicitudes' });
    }
    const data = req.body || {};
    const email = String(data.email || '').trim().toLowerCase();
    const deviceId = String(data.device_id || '').trim().toLowerCase();
    const nonce = String(data.nonce || '').slice(0, 64);
    const hostname = String(data.hostname || '').slice(0, 80);
    const version = String(data.version || '').slice(0, 32);
    if (!V_DEVICE_RE.test(deviceId) || (create && !V_EMAIL_RE.test(email)) || email.length > 254) {
      return vReply(res, { status: 'bad_request' }, nonce, 400, create ? 'Correo o identificador de equipo inválido.' : null);
    }
    let result = null;
    if (relayAdminOnline()) {
      result = await relaySubmit(
        { kind: create ? 'activate' : 'validate', email, device_id: deviceId, hostname, version, ip },
        V_ANSWER_TIMEOUT_MS
      );
      if (result) relayMergeSettings(result.settings);
    }
    if (result === null && !create) {
      result = vSnapshotLookup(relay.snapshot, email, deviceId);
      if (result) {
        relay.seen.set(result.email || email, { email: result.email || email, ip, version, device_id: deviceId, ts: vIso() });
      }
    }
    if (result === null) return vReply(res, { status: 'unavailable' }, nonce);
    return vReply(res, result, nonce);
  } catch (e) {
    log('Error en licencia vixpro:', e && e.message);
    return res.status(500).json({ ok: false, status: 'server_error', message: 'Error interno' });
  }
}

app.post('/api/v1/activate', (req, res) => vClientCall(req, res, true));
app.post('/api/v1/validate', (req, res) => vClientCall(req, res, false));

app.get('/api/v1/info', (req, res) => {
  if (!V_LICENSE_SECRET) return res.status(503).json({ ok: false, status: 'server_error' });
  if (!vAllow('i:' + vClientIp(req), 60, 60000)) return res.status(429).json({ ok: false, status: 'rate_limited' });
  const cfg = relay.settings;
  const body = {
    ok: true,
    status: 'info',
    trial_days: parseInt(cfg.trial_days, 10) || 10,
    contact_phone: cfg.contact_phone,
    contact_email: cfg.contact_email,
    announcement: cfg.announcement,
    nonce: String(req.query.nonce || '').slice(0, 64),
    server_time: vIso(),
  };
  body.sig = vSign(body);
  res.json(body);
});

// ---- API del panel de administracion (usuario+clave o ADMIN_KEY) ----
function relayAdminAuth(req, res, next) {
  const ip = vClientIp(req);
  if (!(V_ADMIN_KEY || (V_ADMIN_USER && V_ADMIN_PASSWORD))) {
    return res.status(503).json({ error: 'Falta configurar ADMIN_USER y ADMIN_PASSWORD (o ADMIN_KEY) en el servidor' });
  }
  if (vCount('adm-fail:' + ip, 600000) >= 10) {
    return res.status(429).json({ error: 'Demasiados intentos fallidos. Espera 10 minutos.' });
  }
  const header = req.get('Authorization') || '';
  let ok = false;
  if (V_ADMIN_KEY && header.startsWith('Bearer ')) ok = vSafeEqual(header.slice(7), V_ADMIN_KEY);
  if (!ok && V_ADMIN_USER && V_ADMIN_PASSWORD && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    const user = i >= 0 ? decoded.slice(0, i) : '';
    const pwd = i >= 0 ? decoded.slice(i + 1) : '';
    ok = vSafeEqual(user, V_ADMIN_USER) & vSafeEqual(pwd, V_ADMIN_PASSWORD) ? true : false;
  }
  if (!ok) {
    vHits.set('adm-fail:' + ip, [...vPrune('adm-fail:' + ip, 600000), Date.now()]);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  next();
}

app.get('/api/admin/ping', relayAdminAuth, (req, res) => res.json({ ok: true, time: vIso() }));

app.get('/api/admin/state', relayAdminAuth, (req, res) => {
  res.json({
    admin_online: relayAdminOnline(),
    snapshot_version: relay.snapshotVersion,
    snapshot_age: relay.snapshot ? Math.floor((Date.now() - relay.snapshotAt) / 1000) : null,
    pending: relay.pending.length,
  });
});

app.post('/api/admin/poll', relayAdminAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const adminId = String(body.admin_id || '').slice(0, 64);
    if (!adminId) return res.status(400).json({ error: 'Falta admin_id' });
    const waitS = Number(body.wait === undefined ? 20 : body.wait);
    const waitMs = Math.min(25000, Math.max(0, (Number.isFinite(waitS) ? waitS : 20) * 1000));
    const { promise, cancel } = relayPollStart(adminId, waitMs);
    res.on('close', () => {
      if (!res.writableEnded) cancel(); // el panel cerro la conexion: no dejar la espera colgada
    });
    const items = await promise;
    relay.adminSeen = Date.now();
    const seen = [...relay.seen.values()];
    relay.seen.clear();
    if (!res.writableEnded && !res.destroyed) res.json({ requests: items, seen, snapshot_version: relay.snapshotVersion });
  } catch (e) {
    if (e instanceof AdminConflict) return res.status(409).json({ error: e.message });
    log('Error en poll vixpro:', e && e.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/admin/answer', relayAdminAuth, (req, res) => {
  try {
    const body = req.body || {};
    relayTouch(String(body.admin_id || '').slice(0, 64));
    const result = body.result;
    if (!result || typeof result !== 'object' || !('status' in result)) {
      return res.status(400).json({ error: 'Respuesta inválida' });
    }
    res.json({ ok: relayAnswer(String(body.rid || ''), result) });
  } catch (e) {
    if (e instanceof AdminConflict) return res.status(409).json({ error: e.message });
    res.status(500).json({ error: 'Error interno' });
  }
});

app.put('/api/admin/snapshot', relayAdminAuth, (req, res) => {
  try {
    const body = req.body || {};
    relayTouch(String(body.admin_id || '').slice(0, 64));
    const snap = body.snapshot;
    if (!snap || typeof snap !== 'object' || Array.isArray(snap)) return res.status(400).json({ error: 'Copia inválida' });
    relay.snapshot = snap;
    relay.snapshotVersion = parseInt(snap.version, 10) || 0;
    relay.snapshotAt = Date.now();
    relayMergeSettings(snap.settings);
    log('Copia de licencias VIXPRO recibida del panel. version=', relay.snapshotVersion);
    res.json({ ok: true, licenses: Object.keys(snap.licenses || {}).length });
  } catch (e) {
    if (e instanceof AdminConflict) return res.status(409).json({ error: e.message });
    res.status(500).json({ error: 'Error interno' });
  }
});

// ------------------------------------------------------------
// Pagina raiz
// ------------------------------------------------------------
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>VIXPRO-BOT</title></head>
<body style="background:#0d1117;color:#00e0ff;font-family:monospace;
             display:flex;align-items:center;justify-content:center;
             height:100vh;margin:0;font-size:2rem;letter-spacing:2px;">
  VIXPRO-BOT
</body>
</html>`);
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    redirect_uri: REDIRECT_URI,
    auth_url: AUTH_URL,
    token_url: TOKEN_URL,
    client_id_configurado: DERIV_CLIENT_ID !== 'TU_CLIENT_ID_AQUI',
    public_base_url_configurado: !PUBLIC_BASE_URL.includes('CAMBIAR-ESTO'),
    sessions_activas: sessions.size,
    service: 'vixpro-bot-oauth',
    licencias_vixpro: {
      secret_configured: !!V_LICENSE_SECRET,
      admin_configured: !!(V_ADMIN_KEY || (V_ADMIN_USER && V_ADMIN_PASSWORD)),
      admin_user_set: !!V_ADMIN_USER,
      admin_password_set: !!V_ADMIN_PASSWORD,
      admin_key_set: !!V_ADMIN_KEY,
      admin_online: relayAdminOnline(),
      snapshot: relay.snapshot !== null,
    },
  });
});

// ------------------------------------------------------------
// El bot Python pide esto para obtener la URL de autorizacion
// ------------------------------------------------------------
app.get('/auth/start.json', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString('hex');

  sessions.set(state, {
    codeVerifier,
    status: 'pending',
    token: null,
    error: null,
    createdAt: Date.now(),
  });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: DERIV_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: DERIV_SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  const authUrl = `${AUTH_URL}?${params.toString()}`;
  log('Nuevo flujo iniciado. state=', state);

  res.json({ state, auth_url: authUrl });
});

// ------------------------------------------------------------
// Deriv redirige aca despues del login/consentimiento
// ------------------------------------------------------------
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  log('Callback recibido. query=', JSON.stringify(req.query));

  if (error) {
    if (state && sessions.has(state)) {
      sessions.get(state).status = 'error';
      sessions.get(state).error = `${error}: ${error_description || ''}`;
    }
    log('Deriv devolvio error:', error, error_description);
    return res.send(htmlPage('Error de autorizacion', `Deriv devolvio: ${error} ${error_description || ''}`));
  }

  if (!state || !sessions.has(state)) {
    log('State invalido o no encontrado:', state);
    return res.status(400).send(htmlPage('Error', 'State invalido o expirado. Volve a intentar desde el bot.'));
  }

  const session = sessions.get(state);

  if (!code) {
    session.status = 'error';
    session.error = 'no_code';
    log('No llego code en el callback para state=', state);
    return res.send(htmlPage('Error', 'No se recibio el codigo de autorizacion.'));
  }

  try {
    const tokenData = await exchangeCodeForToken(code, session.codeVerifier);

    session.status = 'done';
    session.token = tokenData;

    return res.send(htmlPage('Listo', 'Autorizacion completada. Ya podes cerrar esta ventana y volver al bot.'));
  } catch (err) {
    session.status = 'error';
    session.error = String(err.message || err);
    log('Excepcion en intercambio de token:', err);
    return res.send(htmlPage('Error', 'Fallo el intercambio de token con Deriv. Revisa los logs del servidor.'));
  }
});

// ------------------------------------------------------------
// Helper: intercambia code -> token.
// Cliente PUBLICO: solo client_id + code_verifier, SIN client_secret.
// Endpoint correcto: https://auth.deriv.com/oauth2/token
// ------------------------------------------------------------
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenResp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: DERIV_CLIENT_ID,
      code: String(code),
      code_verifier: codeVerifier,
      redirect_uri: REDIRECT_URI,
    }),
  });

  const tokenData = await tokenResp.json();
  log('Respuesta de oauth2/token. status=', tokenResp.status);

  if (!tokenResp.ok) {
    throw new Error(JSON.stringify(tokenData));
  }

  return tokenData;
}

// ------------------------------------------------------------
// El bot Python hace polling aca hasta que status sea 'done'
// ------------------------------------------------------------
app.get('/api/token', (req, res) => {
  const { state } = req.query;

  if (!state || !sessions.has(state)) {
    return res.status(404).json({ status: 'not_found' });
  }

  const session = sessions.get(state);

  if (session.status === 'done') {
    const result = { status: 'done', token: session.token };
    sessions.delete(state);
    log('Token entregado al bot para state=', state);
    return res.json(result);
  }

  if (session.status === 'error') {
    const result = { status: 'error', error: session.error };
    sessions.delete(state);
    log('Error entregado al bot para state=', state, result.error);
    return res.json(result);
  }

  return res.json({ status: 'pending' });
});

// ------------------------------------------------------------
// Renovar token usando el refresh_token (la API nueva da tokens
// de corta duracion, esto evita pedirle login de nuevo al usuario).
// Tampoco lleva client_secret: cliente publico.
// ------------------------------------------------------------
app.post('/api/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ status: 'error', error: 'falta refresh_token en el body' });
  }

  try {
    const tokenResp = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: DERIV_CLIENT_ID,
        refresh_token,
      }),
    });

    const tokenData = await tokenResp.json();
    log('Refresh de token. status=', tokenResp.status);

    if (!tokenResp.ok) {
      return res.status(tokenResp.status).json({ status: 'error', error: tokenData });
    }

    return res.json({ status: 'done', token: tokenData });
  } catch (err) {
    log('Excepcion en refresh:', err);
    return res.status(500).json({ status: 'error', error: String(err) });
  }
});

function htmlPage(title, message) {
  return `<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>${title}</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 80px; background:#0d1117; color:#c9d1d9;">
  <h2>${title}</h2>
  <p>${message}</p>
  <p style="color:#00e0ff;">VIXPRO-BOT</p>
</body>
</html>`;
}

app.listen(PORT, () => {
  log(`Servidor VIXPRO-BOT escuchando en puerto ${PORT}`);
  log(`Redirect URI a registrar en Deriv: ${REDIRECT_URI}`);
  log(`Token endpoint usado: ${TOKEN_URL}`);
});
