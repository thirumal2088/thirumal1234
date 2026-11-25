const ownerHash = '9bc0ca9b11dad4bb41ac9c3a15504f8cb0ca6a5384e47870dd0318ab3f162a45';
const clock = new Intl.DateTimeFormat('en-IN', {
  timeZone: 'Asia/Kolkata', hour: 'numeric', minute: '2-digit', second: '2-digit'
});
const calendar = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Kolkata', dateStyle: 'short' });
const headers = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; media-src 'self' blob:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
};

async function digest(value) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}
function reply(data, status = 200, additional = {}) {
  return Response.json(data, { status, headers: { ...headers, ...additional } });
}
function error(message, status) {
  return reply({ error: message }, status);
}

const audioTypes = new Set(['audio/webm', 'audio/mp4', 'audio/ogg', 'audio/mpeg', 'audio/wav', 'audio/x-m4a', 'audio/aac']);
function validBase64(value, limit) {
  return typeof value === 'string' && value.length > 0 && value.length <= limit &&
    value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}
function media(encoded, type, range) {
  const bytes = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
  const responseHeaders = { ...headers, 'Content-Type': type, 'Accept-Ranges': 'bytes' };
  const match = range?.match(/^bytes=(\d*)-(\d*)$/);
  if (match && (match[1] || match[2])) {
    const start = match[1] ? Number(match[1]) : Math.max(0, bytes.length - Number(match[2]));
    const end = match[1] && match[2] ? Math.min(Number(match[2]), bytes.length - 1) : bytes.length - 1;
    if (start > end || start >= bytes.length) {
      return new Response(null, { status: 416, headers: { ...responseHeaders, 'Content-Range': 'bytes */' + bytes.length } });
    }
    return new Response(bytes.slice(start, end + 1), { status: 206, headers: {
      ...responseHeaders, 'Content-Range': 'bytes ' + start + '-' + end + '/' + bytes.length
    } });
  }
  return new Response(bytes, { headers: responseHeaders });
}

const validTime = value => typeof value === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
const indiaMinute = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
function workDay(row) {
  const actualIn = new Date(row.time_in);
  const actualOut = row.time_out ? new Date(row.time_out) : null;
  const plannedIn = new Date(row.day + 'T' + row.planned_in + ':00+05:30');
  const plannedOut = row.planned_out ? new Date(row.day + 'T' + row.planned_out + ':00+05:30') : null;
  return {
    day: row.day,
    start: indiaMinute.format(actualIn), end: actualOut ? indiaMinute.format(actualOut) : '',
    worked: actualOut ? Math.max(0, Math.floor((actualOut - actualIn) / 60000)) : null,
    late: Math.max(0, Math.floor((actualIn - plannedIn) / 60000)),
    exitDelta: actualOut && plannedOut ? Math.trunc((actualOut - plannedOut) / 60000) : null
  };
}

const adminName = 'thirumal';
const adminCookie = '__Host-rainbow-admin';
const adminCookieOptions = '; Path=/; Secure; HttpOnly; SameSite=Strict';

async function adminSignature(secret, value) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
  return Array.from(signature, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function verifyAdminCookie(request, secret) {
  const token = request.headers.get('Cookie')?.match(/(?:^|; )__Host-rainbow-admin=(\d{13})\.([a-f0-9]{64})(?:;|$)/);
  return Boolean(token && Number(token[1]) > Date.now() &&
    token[2] === await adminSignature(secret, token[1]));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (method === 'GET' && ['/', '/admin'].includes(path)) {
      return new Response(page(path === '/admin'), {
        headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    if (!path.startsWith('/api/')) return error('பக்கம் கிடைக்கவில்லை.', 404);
    if (method === 'POST' && request.headers.get('Origin') !== url.origin) {
      return error('இந்த கோரிக்கையை அனுமதிக்க முடியவில்லை.', 403);
    }
    const isAdminRoute = path.startsWith('/api/admin/');
    try {
      const db = env.DB;
      if (isAdminRoute) {
        const email = request.headers.get('oai-authenticated-user-email');
        if (!email || await digest(email.trim().toLowerCase() + '\n') !== ownerHash) {
          return error('Admin கணக்கில் உள்நுழையவும்.', 401);
        }
        if (method === 'POST' && path === '/api/admin/lock') {
          return reply({ ok: true }, 200, { 'Set-Cookie': adminCookie + '=' + adminCookieOptions + '; Max-Age=0' });
        }
        const [secret, password] = (env.RAINBOW_ADMIN_CREDENTIAL || '').split(':');
        if (!secret || !password) return error('Admin login அமைப்பு தயாராகவில்லை.', 503);
        if (method === 'POST' && path === '/api/admin/unlock') {
          const raw = await request.text();
          if (raw.length > 512) return error('Login விவரங்களைச் சரிபார்க்கவும்.', 400);
          let credentials;
          try { credentials = JSON.parse(raw); } catch { return error('Login விவரங்களைச் சரிபார்க்கவும்.', 400); }
          if (credentials?.username?.trim?.().toLowerCase() !== adminName || credentials?.password !== password) {
            return error('Admin பெயர் அல்லது password தவறு.', 403);
          }
          const expires = String(Date.now() + 30 * 60 * 1000);
          const token = expires + '.' + await adminSignature(secret, expires);
          return reply({ ok: true }, 200, {
            'Set-Cookie': adminCookie + '=' + token + adminCookieOptions + '; Max-Age=1800'
          });
        }
        if (!await verifyAdminCookie(request, secret)) {
          return error('Admin பெயர் மற்றும் password உள்ளிடவும்.', 403);
        }
      } else {
        const token = request.headers.get('Cookie')?.match(/(?:^|; )__Host-rainbow-kiosk=([0-9a-f-]{36})(?:;|$)/)?.[1];
        if (!token || !await db.prepare('SELECT id FROM kiosk WHERE id = 1 AND token_hash = ?')
            .bind(await digest(token)).first()) {
          return error('இந்த போனை Admin முதலில் செயல்படுத்த வேண்டும்.', 401);
        }
      }

      const now = new Date();
      const day = calendar.format(now);
      if (method === 'GET' && path === '/api/admin/today') {
        const staff = await db.prepare(`SELECT s.id, s.name, s.work, COALESCE(h.time_in,s.regular_time) AS regular_time, COALESCE(h.time_out,s.regular_out) AS regular_out, p.time_in, p.time_out, EXISTS (SELECT 1 FROM staff_photos f WHERE f.staff_id = s.id) AS has_photo
          FROM staff s LEFT JOIN punches p ON p.staff_id = s.id AND p.day = ?
          LEFT JOIN staff_schedules h ON h.staff_id = s.id AND h.effective_day = (
            SELECT MAX(effective_day) FROM staff_schedules WHERE staff_id = s.id AND effective_day <= ?
          ) ORDER BY s.name, s.id`).bind(day, day).all();
        return reply({ day, staff: staff.results.map(person => ({
          ...person, time_in: person.time_in ? clock.format(new Date(person.time_in)) : null,
          time_out: person.time_out ? clock.format(new Date(person.time_out)) : null
        })) });
      }
      if (method === 'GET' && path === '/api/admin/team-report') {
        const month = url.searchParams.get('month') || '';
        if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) return error('மாதத்தைத் தேர்வு செய்யவும்.', 400);
        const first = month + '-01';
        const last = month + '-31';
        const [attendance, advances] = await db.batch([
          db.prepare(`SELECT s.id, s.name, s.work, p.day, p.time_in, p.time_out,
            COALESCE(h.time_in,s.regular_time) AS planned_in,
            COALESCE(h.time_out,s.regular_out) AS planned_out,
            EXISTS (SELECT 1 FROM staff_photos f WHERE f.staff_id = s.id) AS has_photo
            FROM staff s LEFT JOIN punches p ON p.staff_id = s.id AND p.day BETWEEN ? AND ?
            LEFT JOIN staff_schedules h ON h.staff_id = s.id AND h.effective_day = (
              SELECT MAX(effective_day) FROM staff_schedules WHERE staff_id = s.id AND effective_day <= p.day
            ) ORDER BY s.name, s.id, p.day`).bind(first, last),
          db.prepare(`SELECT staff_id, SUM(paise) AS paise FROM staff_advances
            WHERE day BETWEEN ? AND ? GROUP BY staff_id`).bind(first, last)
        ]);
        const amounts = new Map(advances.results.map(row => [row.staff_id, row.paise]));
        const staff = new Map();
        for (const row of attendance.results) {
          if (!staff.has(row.id)) staff.set(row.id, {
            id: row.id, name: row.name, work: row.work, hasPhoto: Boolean(row.has_photo),
            advance: amounts.get(row.id) || 0, entries: []
          });
          if (row.day) staff.get(row.id).entries.push(workDay(row));
        }
        return reply({ staff: Array.from(staff.values()) });
      }
      if (method === 'GET' && path === '/api/admin/month') {
        const month = url.searchParams.get('month') || '';
        const id = Number(url.searchParams.get('staff'));
        if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month) || !Number.isSafeInteger(id) || id < 1) {
          return error('மாதத்தையும் பணியாளரையும் தேர்வு செய்யவும்.', 400);
        }
        const rows = await db.prepare(`SELECT p.day, p.time_in, p.time_out,
          COALESCE(h.time_in, s.regular_time) AS planned_in,
          COALESCE(h.time_out, s.regular_out) AS planned_out
          FROM punches p JOIN staff s ON s.id = p.staff_id
          LEFT JOIN staff_schedules h ON h.staff_id = p.staff_id AND h.effective_day = (
            SELECT MAX(effective_day) FROM staff_schedules WHERE staff_id = p.staff_id AND effective_day <= p.day
          ) WHERE p.staff_id = ? AND p.day BETWEEN ? AND ? ORDER BY p.day`)
          .bind(id, month + '-01', month + '-31').all();
        const entries = rows.results.map(workDay);
        return reply({ entries, total: entries.reduce((sum, entry) => sum + (entry.worked ?? 0), 0) });
      }
      const hoursRoute = path.match(/^\/api\/admin\/staff\/(\d+)\/(schedule|punch)$/);
      if (hoursRoute && method === 'POST') {
        const id = Number(hoursRoute[1]);
        if (!Number.isSafeInteger(id) || !await db.prepare('SELECT id FROM staff WHERE id = ?').bind(id).first()) {
          return error('பணியாளர் கிடைக்கவில்லை.', 404);
        }
        const raw = await request.text();
        if (raw.length > 1024) return error('பதிவைச் சரிபார்க்கவும்.', 400);
        let data;
        try { data = JSON.parse(raw); } catch { return error('பதிவைச் சரிபார்க்கவும்.', 400); }
        const { start, end, date } = data || {};
        if (!validTime(start) || (end !== '' && (!validTime(end) || end <= start))) {
          return error('புறப்பாடு நேரம் வருகை நேரத்துக்குப் பிறகு இருக்க வேண்டும்.', 400);
        }
        if (hoursRoute[2] === 'schedule') {
          if (!end) return error('வழக்கமான புறப்பாடு நேரத்தை உள்ளிடவும்.', 400);
          await db.prepare(`INSERT INTO staff_schedules(staff_id,effective_day,time_in,time_out) VALUES (?,?,?,?)
            ON CONFLICT(staff_id,effective_day) DO UPDATE SET time_in=excluded.time_in,time_out=excluded.time_out`)
            .bind(id, day, start, end).run();
          return reply({ ok: true });
        }
        if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) || date > day) {
          return error('சரியான தேதியை உள்ளிடவும்.', 400);
        }
        const arrival = new Date(date + 'T' + start + ':00+05:30');
        const departure = end ? new Date(date + 'T' + end + ':00+05:30') : null;
        if (!Number.isFinite(arrival.getTime()) || calendar.format(arrival) !== date || arrival > now || departure > now) {
          return error('பதிவுக்கான தேதி மற்றும் நேரத்தைச் சரிபார்க்கவும்.', 400);
        }
        const result = await db.prepare(`INSERT INTO punches(staff_id,day,time_in,time_out) VALUES (?,?,?,?)
          ON CONFLICT(staff_id,day) DO UPDATE SET time_in=excluded.time_in,
          time_out=COALESCE(excluded.time_out,punches.time_out)
          WHERE excluded.time_out IS NOT NULL OR punches.time_out IS NULL OR punches.time_out > excluded.time_in`)
          .bind(id, date, arrival.toISOString(), departure?.toISOString() ?? null).run();
        return result.meta.changes ? reply({ ok: true }) :
          error('வருகை நேரம் ஏற்கெனவே உள்ள புறப்பாடு நேரத்துக்கு முன் இருக்க வேண்டும்.', 409);
      }
      if (method === 'POST' && path === '/api/admin/kiosk') {
        const token = crypto.randomUUID();
        await db.prepare(`INSERT INTO kiosk (id, token_hash) VALUES (1, ?)
          ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash`).bind(await digest(token)).run();
        return reply({ ok: true }, 200, {
          'Set-Cookie': '__Host-rainbow-kiosk=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000'
        });
      }
      const staffRecords = path.match(/^\/api\/admin\/staff\/(\d+)\/(photo|advances)$/);
      const voiceRoute = path.match(/^\/api\/admin\/advances\/(\d+)\/voice$/);
      if (voiceRoute && method === 'GET') {
        const entry = await db.prepare('SELECT voice, voice_type FROM staff_advances WHERE id = ?')
          .bind(Number(voiceRoute[1])).first();
        if (!entry?.voice) return error('Voice note கிடைக்கவில்லை.', 404);
        return media(entry.voice, entry.voice_type, request.headers.get('Range'));
      }
      if (staffRecords) {
        const staffId = Number(staffRecords[1]);
        if (!Number.isSafeInteger(staffId) || !await db.prepare('SELECT id FROM staff WHERE id = ?').bind(staffId).first()) {
          return error('பணியாளர் கிடைக்கவில்லை.', 404);
        }
        const photo = staffRecords[2] === 'photo';
        if (method === 'GET') {
          if (photo) {
            const entry = await db.prepare('SELECT jpeg FROM staff_photos WHERE staff_id = ?').bind(staffId).first();
            return entry ? media(entry.jpeg, 'image/jpeg') : error('போட்டோ கிடைக்கவில்லை.', 404);
          }
          const result = await db.prepare(`SELECT id, day, paise, reason, voice IS NOT NULL AS has_voice
            FROM staff_advances WHERE staff_id = ? ORDER BY id DESC`).bind(staffId).all();
          return reply({ entries: result.results });
        }
        if (method !== 'POST') return error('பக்கம் கிடைக்கவில்லை.', 404);
        const raw = await request.text();
        if (raw.length > 850000) return error('கோப்பு அளவு அதிகமாக உள்ளது.', 413);
        let data;
        try { data = JSON.parse(raw); } catch { return error('பதிவைச் சரிபார்க்கவும்.', 400); }
        if (!data || typeof data !== 'object') return error('பதிவைச் சரிபார்க்கவும்.', 400);
        if (photo) {
          if (!validBase64(data.jpeg, 270000) || !data.jpeg.startsWith('/9j/')) {
            return error('செல்லுபடியாகும் போட்டோவைத் தேர்வு செய்யவும்.', 400);
          }
          const result = await db.prepare('INSERT INTO staff_photos (staff_id, jpeg) VALUES (?, ?) ON CONFLICT DO NOTHING')
            .bind(staffId, data.jpeg).run();
          return result.meta.changes ? reply({ ok: true }, 201) : error('இந்தப் பணியாளருக்கு போட்டோ ஏற்கனவே உள்ளது.', 409);
        }
        const { paise, reason, voice, voiceType, requestId } = data;
        if (!Number.isSafeInteger(paise) || paise < 1 || paise > 99999999 ||
            typeof reason !== 'string' || reason.length > 500 ||
            typeof requestId !== 'string' || !/^[0-9a-f-]{36}$/.test(requestId) ||
            (voice !== null && (!validBase64(voice, 800000) || !audioTypes.has(voiceType)))) {
          return error('தொகை, காரணம் அல்லது voice note விவரத்தைச் சரிபார்க்கவும்.', 400);
        }
        await db.prepare(`INSERT INTO staff_advances (staff_id, day, paise, reason, voice, voice_type, request_id)
          VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_id) DO NOTHING`)
          .bind(staffId, day, paise, reason.trim(), voice, voice ? voiceType : null, requestId).run();
        return reply({ ok: true }, 201);
      }

      if (method === 'GET' && path === '/api/staff') {
        const staff = await db.prepare('SELECT id, name FROM staff ORDER BY name, id').all();
        return reply({ staff: staff.results });
      }
      if (method !== 'POST' || !['/api/admin/staff', '/api/punch'].includes(path)) {
        return error('பக்கம் கிடைக்கவில்லை.', 404);
      }

      const raw = await request.text();
      if (raw.length > 2048) return error('பதிவு மிக நீளமாக உள்ளது.', 413);
      let body;
      try { body = JSON.parse(raw); } catch { return error('பதிவைச் சரிபார்க்கவும்.', 400); }
      if (!body || typeof body !== 'object') return error('பதிவைச் சரிபார்க்கவும்.', 400);
      if (path === '/api/admin/staff') {
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        const work = typeof body.work === 'string' ? body.work.trim() : '';
        const regular = typeof body.regular === 'string' ? body.regular : '';
        const regularOut = body.regularOut;
        if (!validTime(regularOut) || regularOut <= regular) return error('வழக்கமான புறப்பாடு நேரத்தைச் சரிபார்க்கவும்.', 400);
        if (!name || name.length > 80 || work.length > 120 || !/^([01]\d|2[0-3]):[0-5]\d$/.test(regular)) {
          return error('பெயர் மற்றும் வழக்கமான வருகை நேரத்தைச் சரிபார்க்கவும்.', 400);
        }
        await db.prepare('INSERT INTO staff (name, work, regular_time, regular_out) VALUES (?, ?, ?, ?)')
          .bind(name, work, regular, regularOut).run();
        return reply({ ok: true }, 201);
      }

      const { id, action } = body;
      if (!Number.isSafeInteger(id) || id < 1 || !['in', 'out'].includes(action)) {
        return error('பெயர் மற்றும் பதிவைச் சரிபார்க்கவும்.', 400);
      }
      if (!await db.prepare('SELECT id FROM staff WHERE id = ?').bind(id).first()) {
        return error('இந்தப் பெயர் கிடைக்கவில்லை.', 404);
      }
      const stamp = now.toISOString();
      if (action === 'in') {
        const result = await db.prepare(`INSERT INTO punches (staff_id, day, time_in) VALUES (?, ?, ?)
          ON CONFLICT(staff_id, day) DO NOTHING`).bind(id, day, stamp).run();
        if (!result.meta.changes) return error('இன்றைய வருகை ஏற்கனவே பதிவாகிவிட்டது.', 409);
      } else {
        const result = await db.prepare(`UPDATE punches SET time_out = ?
          WHERE staff_id = ? AND day = ? AND time_out IS NULL`).bind(stamp, id, day).run();
        if (!result.meta.changes) {
          const earlier = await db.prepare('SELECT time_in FROM punches WHERE staff_id = ? AND day = ?')
            .bind(id, day).first();
          return error(earlier ? 'இன்றைய புறப்பாடு ஏற்கனவே பதிவாகிவிட்டது.' :
            'முதலில் வருகையைப் பதிவு செய்யவும்.', 409);
        }
      }
      return reply({ time: clock.format(now) });
    } catch (cause) {
      console.error(cause);
      return error('இப்போது பதிவைத் திறக்க முடியவில்லை. மீண்டும் முயற்சிக்கவும்.', 503);
    }
  }
};

function page(admin) {
  return `<!doctype html>
<html lang="ta"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rainbow Sports Attendance</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#edf3ef;color:#172820;font:16px system-ui,sans-serif}
main{max-width:680px;margin:auto;padding:16px}header{background:#142e24;color:white;padding:20px;border-radius:16px}
header p{margin:0;color:#b6e5ca}h1{font-size:1.6rem;margin:6px 0 0}h2{font-size:1.15rem;margin:0 0 14px}
nav{display:flex;gap:18px;margin:16px 0}a{color:#165838;font-weight:700}
section{background:white;padding:16px;border-radius:14px;margin:14px 0}
label{display:grid;gap:6px;margin:0 0 12px}input,button,select,textarea{font:inherit;min-height:46px;border-radius:9px;padding:8px 12px}
input,select,textarea{border:1px solid #84988b;width:100%}button{border:0;background:#dcebe2;color:#17442c;font-weight:650;cursor:pointer}
button.primary,button[aria-pressed=true]{background:#176444;color:white}button:disabled{opacity:.55;cursor:default}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:9px}.actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
ul{padding:0;list-style:none;margin:0}li{border-top:1px solid #dce8df;padding:12px 0;overflow-wrap:anywhere}
#team-results details{border-top:1px solid #dce8df;padding:12px 0}#team-results summary{cursor:pointer}#team-results img{vertical-align:middle;margin-right:8px}img{object-fit:cover;border-radius:12px}audio{display:block;max-width:100%;margin:8px 0}form button{margin-bottom:8px}small{display:block;font-size:.875rem;line-height:1.55;color:#365749}[hidden]{display:none!important}
</style></head><body><main><header><p>RAINBOW SPORTS</p><h1>${admin ? 'Admin · வருகைப் பதிவு' : 'ஸ்டாஃப் வருகைப் பதிவு'}</h1></header>
<nav><a href="/">ஸ்டாஃப் பதிவு</a><a href="/admin">Admin</a></nav>
${admin ? `<section id="signin" hidden><a href="/signin-with-chatgpt?return_to=%2Fadmin">ChatGPT கணக்கில் உள்நுழைய</a></section>
<section id="admin-unlock" hidden><h2>Admin Login</h2>
<form id="admin-login">
<label>Admin பெயர்<input name="username" autocomplete="username" autocapitalize="none" required></label>
<label>Password<input name="password" type="password" inputmode="numeric" autocomplete="current-password" required></label>
<button class="primary">உள்ளே செல்ல</button>
</form></section>
<div id="admin-panel" hidden>
<section><h2>பணியாளரைச் சேர்க்க</h2><form id="add">
<label>பெயர்<input name="name" maxlength="80" required></label>
<label>பணி (விருப்பம்)<input name="work" maxlength="120" placeholder="உதா. டைலர்"></label>
<label>வழக்கமான வருகை நேரம்<input name="regular" type="time" required></label>
<label>வழக்கமான மாலை புறப்பாடு<input name="regularOut" type="time" required></label>
<button class="primary">சேர்க்க</button></form></section>
<section id="reports"><h2>Reports · மாத அறிக்கை</h2>
<label>மாதம்<input id="team-month" type="month" required></label>
<p id="team-summary" role="status"></p>
<div id="team-results"></div></section>
<section><h2>வேலை நேரம் &amp; மாதக் கணக்கு</h2>
<label>பணியாளர்<select id="hours-person"><option value="">பெயரைத் தேர்வு செய்யவும்</option></select></label>
<div id="hours-panel" hidden>
<h3>வழக்கமான நேரம்</h3>
<form id="shift-form">
<label>காலை வருகை<input name="start" type="time" required></label>
<label>மாலை புறப்பாடு<input name="end" type="time" required></label>
<button class="primary">வழக்கமான நேரத்தைச் சேமி</button>
</form>
<h3>உண்மையான வருகை / புறப்பாடு பதிவு</h3>
<form id="punch-form">
<label>தேதி<input name="date" type="date" required></label>
<label>வருகை நேரம்<input name="start" type="time" required></label>
<label>புறப்பாடு நேரம் (விருப்பம்)<input name="end" type="time"></label>
<button>தினசரிப் பதிவைச் சேமி</button>
</form>
<p id="hours-status" role="status"></p>
<h3>மாதக் கணக்கு</h3>
<label>மாதம்<input id="hours-month" type="month" required></label>
<p id="hours-total" aria-live="polite"></p>
<ul id="hours-days"></ul>
</div></section>
<section><h2>போட்டோ &amp; அட்வான்ஸ்</h2>
<label>பணியாளர்<select id="person-records"><option value="">பெயரைத் தேர்வு செய்யவும்</option></select></label>
<div id="staff-records" hidden>
<img id="portrait" alt="பணியாளர் போட்டோ" width="96" height="96" hidden>
<form id="photo-form" hidden>
<label>கேலரியில் இருந்து போட்டோ<input id="gallery" type="file" accept="image/*"></label>
<label>அல்லது கேமராவில் எடுக்க<input id="camera" type="file" accept="image/*" capture="user"></label>
<button type="submit">போட்டோ சேமி</button>
</form>
<h3>அட்வான்ஸ் பதிவு</h3>
<form id="advance-form">
<label>தொகை (₹)<input name="amount" type="number" inputmode="decimal" min="0.01" max="999999.99" step="0.01" required></label>
<label>காரணம் (விருப்பம்)<textarea name="reason" rows="2" maxlength="500"></textarea></label>
<button type="button" id="record">Voice note பதிவு (20 விநாடி வரை)</button>
<label>அல்லது ஆடியோ கோப்பு (விருப்பம்)<input id="audio-file" type="file" accept="audio/*,video/mp4"></label>
<audio id="preview-audio" controls hidden></audio>
<button type="button" id="remove-audio" hidden>Voice note நீக்கு</button>
<button type="submit" class="primary">அட்வான்ஸ் சேமி</button>
</form>
<p id="record-status" role="status"></p>
<h3>அட்வான்ஸ் வரலாறு</h3><ul id="ledger"></ul>
</div></section>
<section><h2>கடை போன்</h2><button id="activate" type="button">இந்த போனை செயல்படுத்து</button>
<p>கடை போனில் ஒருமுறை செயல்படுத்திய பின், Admin கணக்கிலிருந்து வெளியேறி ஸ்டாஃப் பதிவைத் திறக்கவும்.</p>
<a id="admin-signout" href="/signout-with-chatgpt?return_to=%2F">Admin கணக்கிலிருந்து வெளியேறு</a></section>
<section><h2>இன்றைய பதிவுகள்</h2><p id="report-day"></p><ul id="report"></ul></section></div>` :
`<section><h2>உங்கள் பெயரைத் தொடவும்</h2><div id="staff" class="grid"></div>
<div id="actions" class="actions" hidden><button class="primary" id="in">வருகை</button><button id="out">புறப்பாடு</button></div></section>`}
<p id="status" role="status" aria-live="polite"></p></main>
<script>
const element = id => document.getElementById(id);
const statusLine = element('status');
async function api(path, data) {
  const response = await fetch('/api/' + path, data === undefined ? {} : {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw Object.assign(new Error(result.error), { status: response.status });
  return result;
}
function showError(error) {
  statusLine.textContent = error.message || 'மீண்டும் முயற்சிக்கவும்.';
}
let roster = [];
let refreshTeamReport;
async function loadReport() {
  const data = await api('admin/today');
  roster = data.staff;
  for (const id of ['person-records', 'hours-person']) {
    const picker = element(id);
    const picked = picker.value;
    picker.replaceChildren(new Option('பெயரைத் தேர்வு செய்யவும்', ''), ...roster.map(person =>
      new Option(person.name + ' · #' + person.id, person.id)
    ));
    picker.value = picked;
  }
  const date = element('punch-form').elements.namedItem('date');
  date.max = data.day;
  if (!date.value) date.value = data.day;
  const month = element('hours-month');
  if (!month.value) month.value = data.day.slice(0, 7);
  const teamMonth = element('team-month');
  if (!teamMonth.value) teamMonth.value = data.day.slice(0, 7);
  refreshTeamReport();
  element('report-day').textContent = data.day;
  element('report').replaceChildren(...data.staff.map(person => {
    const row = document.createElement('li');
    const name = document.createElement('strong');
    name.textContent = person.name + ' · #' + person.id + (person.work ? ' · ' + person.work : '');
    const schedule = document.createElement('small');
    schedule.textContent = 'வழக்கமான நேரம் ' + person.regular_time + ' – ' + (person.regular_out || 'புறப்பாடு அமைக்கவும்');
    const actual = document.createElement('small');
    actual.textContent = 'வருகை ' + (person.time_in || '—') + ' · புறப்பாடு ' + (person.time_out || '—');
    row.append(name, schedule, actual);
    return row;
  }));
}
function setupTeamReport() {
  const month = element('team-month');
  const summary = element('team-summary');
  const results = element('team-results');
  const money = new Intl.NumberFormat('en-IN', {style: 'currency', currency: 'INR'});
  let latest = 0;
  const duration = minutes => Math.floor(minutes / 60) + ' ம. ' + minutes % 60 + ' நி.';
  return async function refreshReport() {
    const request = ++latest;
    results.replaceChildren();
    summary.textContent = '';
    if (!month.value) return;
    summary.textContent = 'அறிக்கை ஏற்றப்படுகிறது…';
    try {
      const data = await api('admin/team-report?month=' + encodeURIComponent(month.value));
      if (request !== latest) return;
      let teamMinutes = 0;
      let teamAdvance = 0;
      for (const person of data.staff) {
        const details = document.createElement('details');
        const heading = document.createElement('summary');
        if (person.hasPhoto) {
          const photo = document.createElement('img');
          photo.alt = person.name;
          photo.width = photo.height = 42;
          photo.loading = 'lazy';
          photo.src = '/api/admin/staff/' + person.id + '/photo';
          heading.append(photo);
        }
        const name = document.createElement('strong');
        name.textContent = person.name + ' · #' + person.id + (person.work ? ' · ' + person.work : '');
        heading.append(name);
        const totals = document.createElement('p');
        const worked = person.entries.reduce((sum, row) => sum + (row.worked ?? 0), 0);
        const missing = person.entries.filter(row => row.worked === null).length;
        teamMinutes += worked;
        teamAdvance += person.advance;
        totals.textContent = 'பதிவு நாட்கள் ' + person.entries.length + ' · வேலை நேரம் ' + duration(worked) +
          ' · அட்வான்ஸ் ' + money.format(person.advance / 100) + (missing ? ' · புறப்பாடு நிலுவை ' + missing : '');
        const days = document.createElement('ul');
        for (const row of person.entries) {
          const item = document.createElement('li');
          const timing = document.createElement('strong');
          timing.textContent = row.day + ' · ' + row.start + ' – ' + (row.end || 'புறப்பாடு நிலுவை');
          const detail = document.createElement('small');
          const exit = row.exitDelta === null ? '' : row.exitDelta === 0 ? ' · நேரத்திற்குப் புறப்பாடு' :
            ' · ' + (row.exitDelta > 0 ? 'தாமதப் புறப்பாடு ' : 'முன்கூட்டிய புறப்பாடு ') + duration(Math.abs(row.exitDelta));
          detail.textContent = (row.worked === null ? 'வேலை நேரம் நிலுவை' : 'வேலை நேரம் ' + duration(row.worked)) +
            ' · வருகை தாமதம் ' + duration(row.late) + exit;
          item.append(timing, detail);
          days.append(item);
        }
        if (!person.entries.length) days.textContent = 'இந்த மாதத்தில் வருகைப் பதிவு இல்லை.';
        details.append(heading, totals, days);
        results.append(details);
      }
      summary.textContent = data.staff.length ? data.staff.length + ' பணியாளர்கள் · மொத்த வேலை நேரம் ' +
        duration(teamMinutes) + ' · மொத்த அட்வான்ஸ் ' + money.format(teamAdvance / 100) : 'பணியாளர்கள் சேர்க்கப்படவில்லை.';
    } catch (error) {
      if (request === latest) summary.textContent = error.message;
    }
  };
}

function setupHours() {
  const person = element('hours-person');
  const panel = element('hours-panel');
  const shift = element('shift-form');
  const punch = element('punch-form');
  const dateField = punch.elements.namedItem('date');
  const month = element('hours-month');
  const message = element('hours-status');
  const total = element('hours-total');
  const days = element('hours-days');
  const label = minutes => Math.floor(minutes / 60) + ' ம. ' + (minutes % 60) + ' நி.';
  let reportRequest = 0;
  let punchRequest = 0;
  const report = (staff, period) => api('admin/month?staff=' + staff + '&month=' + encodeURIComponent(period));
  async function showMonth() {
    const request = ++reportRequest;
    total.textContent = '';
    days.replaceChildren();
    if (!person.value || !month.value) return;
    try {
      const result = await report(person.value, month.value);
      if (request !== reportRequest) return;
      const missing = result.entries.filter(entry => entry.worked === null).length;
      total.textContent = 'மாத மொத்தம் · ' + label(result.total) +
        (missing ? ' · புறப்பாடு நிலுவை: ' + missing : '');
      for (const entry of result.entries) {
        const row = document.createElement('li');
        const times = document.createElement('strong');
        times.textContent = entry.day + ' · ' + entry.start + ' – ' + (entry.end || 'புறப்பாடு இல்லை');
        const detail = document.createElement('small');
        const late = entry.late ? 'வருகை தாமதம் ' + label(entry.late) : 'வருகை தாமதம் இல்லை';
        const exit = entry.exitDelta === null ? '' : entry.exitDelta === 0 ? ' · சரியான நேரத்தில் புறப்பாடு' :
          ' · ' + (entry.exitDelta > 0 ? 'தாமதப் புறப்பாடு ' : 'முன்கூட்டிய புறப்பாடு ') +
          label(Math.abs(entry.exitDelta));
        detail.textContent = (entry.worked === null ? 'வேலை நேரம் நிலுவை' : 'வேலை நேரம் ' + label(entry.worked)) +
          ' · ' + late + exit;
        row.append(times, detail);
        days.append(row);
      }
      if (!result.entries.length) days.textContent = 'இந்த மாதத்தில் வருகைப் பதிவு இல்லை.';
    } catch (error) {
      if (request === reportRequest) total.textContent = error.message;
    }
  }
  async function showPunch() {
    const request = ++punchRequest;
    const date = dateField.value;
    punch.elements.namedItem('start').value = '';
    punch.elements.namedItem('end').value = '';
    if (!person.value || !date) return;
    try {
      const result = await report(person.value, date.slice(0, 7));
      if (request !== punchRequest) return;
      const entry = result.entries.find(item => item.day === date);
      const start = punch.elements.namedItem('start');
      const end = punch.elements.namedItem('end');
      if (entry && !start.value && !end.value) {
        start.value = entry.start;
        end.value = entry.end;
      }
    } catch (error) {
      if (request === punchRequest) message.textContent = error.message;
    }
  }
  person.onchange = () => {
    const selected = roster.find(item => String(item.id) === person.value);
    panel.hidden = !selected;
    message.textContent = '';
    shift.elements.namedItem('start').value = selected?.regular_time || '';
    shift.elements.namedItem('end').value = selected?.regular_out || '';
    showMonth();
    showPunch();
  };
  dateField.onchange = showPunch;
  month.onchange = showMonth;
  for (const [form, kind] of [[shift, 'schedule'], [punch, 'punch']]) {
    form.onsubmit = async event => {
      event.preventDefault();
      if (!person.value) return;
      const data = Object.fromEntries(new FormData(form));
      const controls = [person, ...shift.elements, ...punch.elements];
      controls.forEach(control => { control.disabled = true; });
      try {
        await api('admin/staff/' + person.value + '/' + kind, data);
        message.textContent = kind === 'schedule' ? 'வழக்கமான நேரம் இன்று முதல் சேமிக்கப்பட்டது.' : 'தினசரிப் பதிவு சேமிக்கப்பட்டது.';
        await loadReport();
        await showMonth();
      } catch (error) { message.textContent = error.message; }
      finally { controls.forEach(control => { control.disabled = false; }); }
    };
  }
}

function setupRecords() {
  const picker = element('person-records');
  const message = element('record-status');
  const photo = element('photo-form');
  const advance = element('advance-form');
  const record = element('record');
  const audioFile = element('audio-file');
  const player = element('preview-audio');
  const ledger = element('ledger');
  const portrait = element('portrait');
  let busy = false;
  let voice = null;
  let preview;
  let microphone;
  let timer;
  let requestId = crypto.randomUUID();
  const route = (person, kind) => 'admin/staff/' + person.id + '/' + kind;
  const selected = () => roster.find(person => String(person.id) === picker.value);
  const money = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' });
  function fail(error) { message.textContent = error.message || 'மீண்டும் முயற்சிக்கவும்.'; }
  function lock(value) {
    busy = value;
    for (const control of [picker, ...photo.elements, ...advance.elements]) control.disabled = value;
  }
  function setVoice(file) {
    if (preview) URL.revokeObjectURL(preview);
    preview = file ? URL.createObjectURL(file) : undefined;
    voice = file;
    requestId = crypto.randomUUID();
    player.hidden = element('remove-audio').hidden = !file;
    if (preview) player.src = preview;
    else {
      player.removeAttribute('src');
      player.load();
    }
  }
  async function loadLedger(person) {
    const data = await api(route(person, 'advances'));
    if (selected()?.id !== person.id) return;
    const rows = data.entries.map(entry => {
      const row = document.createElement('li');
      const amount = document.createElement('strong');
      amount.textContent = money.format(entry.paise / 100) + ' · ' + entry.day;
      row.append(amount);
      if (entry.reason) {
        const reason = document.createElement('div');
        reason.textContent = entry.reason;
        row.append(reason);
      }
      if (entry.has_voice) {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.preload = 'none';
        audio.src = '/api/admin/advances/' + entry.id + '/voice';
        row.append(audio);
      }
      return row;
    });
    ledger.replaceChildren(...rows);
    if (!rows.length) ledger.textContent = 'அட்வான்ஸ் பதிவு இல்லை.';
  }
  function showPortrait(person) {
    portrait.hidden = !person.has_photo;
    photo.hidden = Boolean(person.has_photo);
    if (person.has_photo) portrait.src = '/api/' + route(person, 'photo');
    else portrait.removeAttribute('src');
  }
  picker.onchange = () => {
    const person = selected();
    message.textContent = '';
    ledger.replaceChildren();
    advance.reset();
    photo.reset();
    setVoice(null);
    element('staff-records').hidden = !person;
    if (person) {
      showPortrait(person);
      loadLedger(person).catch(error => { if (selected()?.id === person.id) fail(error); });
    }
  };
  element('gallery').onchange = () => { if (element('gallery').files.length) element('camera').value = ''; };
  element('camera').onchange = () => { if (element('camera').files.length) element('gallery').value = ''; };
  photo.onsubmit = async event => {
    event.preventDefault();
    const person = selected();
    const file = element('camera').files[0] || element('gallery').files[0];
    if (!person || busy) return;
    if (!file) return fail(new Error('ஒரு போட்டோவைத் தேர்வு செய்யவும்.'));
    lock(true);
    try {
      const picture = await createImageBitmap(file);
      const canvas = document.createElement('canvas');
      const scale = Math.min(1, 480 / Math.max(picture.width, picture.height));
      canvas.width = Math.max(1, Math.round(picture.width * scale));
      canvas.height = Math.max(1, Math.round(picture.height * scale));
      canvas.getContext('2d').drawImage(picture, 0, 0, canvas.width, canvas.height);
      picture.close();
      const jpeg = canvas.toDataURL('image/jpeg', 0.8).split(',')[1];
      await api(route(person, 'photo'), { jpeg });
      person.has_photo = 1;
      showPortrait(person);
      photo.reset();
      message.textContent = 'போட்டோ சேமிக்கப்பட்டது.';
      refreshTeamReport();
    } catch (error) { fail(error); }
    finally { lock(false); }
  };
  audioFile.onchange = () => {
    const file = audioFile.files[0];
    if (!file) return;
    if (file.size > 600000) {
      audioFile.value = '';
      return fail(new Error('600 KB-க்குள் உள்ள ஆடியோ கோப்பைத் தேர்வு செய்யவும்.'));
    }
    setVoice(file);
    message.textContent = 'Voice note தயார்.';
  };
  element('remove-audio').onclick = () => {
    audioFile.value = '';
    setVoice(null);
    message.textContent = '';
  };
  record.onclick = async () => {
    if (microphone?.state === 'recording') return microphone.stop();
    if (!window.MediaRecorder || !navigator.mediaDevices?.getUserMedia) {
      return fail(new Error('இந்த browser-ல் நேரடியாக பதிவு செய்ய முடியவில்லை. ஆடியோ கோப்பு சேர்க்கலாம்.'));
    }
    let stream;
    lock(true);
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const type = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/ogg;codecs=opus']
        .find(value => MediaRecorder.isTypeSupported(value));
      microphone = new MediaRecorder(stream, { ...(type ? { mimeType: type } : {}), audioBitsPerSecond: 32000 });
      const chunks = [];
      let failed = false;
      microphone.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
      microphone.onerror = () => { failed = true; };
      microphone.onstop = () => {
        clearTimeout(timer);
        stream.getTracks().forEach(track => track.stop());
        const clip = new Blob(chunks, { type: microphone.mimeType || chunks[0]?.type || '' });
        microphone = undefined;
        record.textContent = 'Voice note பதிவு (20 விநாடி வரை)';
        lock(false);
        if (failed || !clip.size || clip.size > 600000) {
          return fail(new Error('Voice note சேமிக்க முடியவில்லை. மீண்டும் முயற்சிக்கவும்.'));
        }
        audioFile.value = '';
        setVoice(clip);
        message.textContent = 'Voice note தயார்.';
      };
      microphone.start();
      record.disabled = false;
      record.textContent = 'பதிவை நிறுத்து';
      timer = setTimeout(() => { if (microphone?.state === 'recording') microphone.stop(); }, 20000);
      message.textContent = 'குரல் பதிவு நடக்கிறது.';
    } catch {
      stream?.getTracks().forEach(track => track.stop());
      microphone = undefined;
      lock(false);
      fail(new Error('Mic அனுமதியைச் சரிபார்க்கவும் அல்லது ஆடியோ கோப்பு சேர்க்கவும்.'));
    }
  };
  advance.onsubmit = async event => {
    event.preventDefault();
    const person = selected();
    if (!person || busy) return;
    const data = new FormData(advance);
    lock(true);
    try {
      let encoded = null;
      let voiceType = null;
      if (voice) {
        voiceType = voice.type.split(';')[0];
        if (voiceType === 'video/mp4') voiceType = 'audio/mp4';
        encoded = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result.split(',')[1]);
          reader.onerror = () => reject(new Error('ஆடியோ கோப்பைத் திறக்க முடியவில்லை.'));
          reader.readAsDataURL(voice);
        });
      }
      await api(route(person, 'advances'), {
        paise: Math.round(Number(data.get('amount')) * 100),
        reason: data.get('reason'), voice: encoded, voiceType, requestId
      });
      advance.reset();
      setVoice(null);
      message.textContent = 'அட்வான்ஸ் சேமிக்கப்பட்டது.';
      refreshTeamReport();
      await loadLedger(person);
    } catch (error) { fail(error); }
    finally { lock(false); }
  };
}

if (element('add')) {
  setupRecords();
  setupHours();
  refreshTeamReport = setupTeamReport();
  element('team-month').onchange = refreshTeamReport;
  loadReport().then(() => { element('admin-panel').hidden = false; }).catch(error => {
    if (error.status === 401) element('signin').hidden = false;
    if (error.status === 403) element('admin-unlock').hidden = false;
    showError(error);
  });
  element('admin-login').onsubmit = async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      await api('admin/unlock', Object.fromEntries(new FormData(form)));
      form.reset();
      await loadReport();
      element('admin-unlock').hidden = true;
      element('admin-panel').hidden = false;
      statusLine.textContent = '';
    } catch (error) { showError(error); }
    finally { button.disabled = false; }
  };
  element('admin-signout').onclick = async event => {
    event.preventDefault();
    const target = event.currentTarget.href;
    try {
      await api('admin/lock', {});
      location.assign(target);
    } catch (error) { showError(error); }
  };
  element('add').onsubmit = async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      await api('admin/staff', Object.fromEntries(new FormData(form)));
      form.reset();
      statusLine.textContent = 'பணியாளர் சேர்க்கப்பட்டார்.';
      await loadReport();
    } catch (error) { showError(error); }
    finally { button.disabled = false; }
  };
  element('activate').onclick = async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api('admin/kiosk', {});
      statusLine.textContent = 'இந்த போன் செயல்படுத்தப்பட்டது. Admin கணக்கிலிருந்து வெளியேறலாம்.';
    } catch (error) { showError(error); }
    finally { button.disabled = false; }
  };
} else {
  let selected;
  let busy = false;
  const list = element('staff');
  api('staff').then(data => {
    if (!data.staff.length) statusLine.textContent = 'Admin முதலில் பணியாளர்களைச் சேர்க்க வேண்டும்.';
    for (const person of data.staff) {
      const button = document.createElement('button');
      button.textContent = person.name + ' · #' + person.id;
      button.setAttribute('aria-pressed', 'false');
      button.onclick = () => {
        if (busy) return;
        selected = person;
        for (const item of list.children) item.setAttribute('aria-pressed', String(item === button));
        element('actions').hidden = false;
        statusLine.textContent = person.name + ' · வருகை அல்லது புறப்பாடு தேர்வு செய்யவும்.';
      };
      list.append(button);
    }
  }).catch(showError);
  for (const action of ['in', 'out']) element(action).onclick = async () => {
    if (!selected || busy) return;
    busy = true;
    element('in').disabled = element('out').disabled = true;
    try {
      const result = await api('punch', { id: selected.id, action });
      statusLine.textContent = selected.name + ' · ' + (action === 'in' ? 'வருகை' : 'புறப்பாடு') + ' · ' + result.time;
      selected = undefined;
      element('actions').hidden = true;
      for (const item of list.children) item.setAttribute('aria-pressed', 'false');
    } catch (error) { showError(error); }
    finally {
      busy = false;
      element('in').disabled = element('out').disabled = false;
    }
  };
}
</script></body></html>`;
}
