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
        const staff = await db.prepare(`SELECT s.id, s.name, s.work, s.regular_time, p.time_in, p.time_out, EXISTS (SELECT 1 FROM staff_photos f WHERE f.staff_id = s.id) AS has_photo
          FROM staff s LEFT JOIN punches p ON p.staff_id = s.id AND p.day = ?
          ORDER BY s.name, s.id`).bind(day).all();
        return reply({ day, staff: staff.results.map(person => ({
          ...person, time_in: person.time_in ? clock.format(new Date(person.time_in)) : null,
          time_out: person.time_out ? clock.format(new Date(person.time_out)) : null
        })) });
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
        if (!name || name.length > 80 || work.length > 120 || !/^([01]\d|2[0-3]):[0-5]\d$/.test(regular)) {
          return error('பெயர் மற்றும் வழக்கமான வருகை நேரத்தைச் சரிபார்க்கவும்.', 400);
        }
        await db.prepare('INSERT INTO staff (name, work, regular_time) VALUES (?, ?, ?)')
          .bind(name, work, regular).run();
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
img{object-fit:cover;border-radius:12px}audio{display:block;max-width:100%;margin:8px 0}form button{margin-bottom:8px}small{display:block;font-size:.875rem;line-height:1.55;color:#365749}[hidden]{display:none!important}
</style></head><body><main><header><p>RAINBOW SPORTS</p><h1>${admin ? 'Admin · வருகைப் பதிவு' : 'ஸ்டாஃப் வருகைப் பதிவு'}</h1></header>
<nav><a href="/">ஸ்டாஃப் பதிவு</a><a href="/admin">Admin</a></nav>
${admin ? `<section id="signin" hidden><a href="/signin-with-chatgpt?return_to=%2Fadmin">ChatGPT கணக்கில் உள்நுழைய</a></section>
<div id="admin-panel" hidden>
<section><h2>பணியாளரைச் சேர்க்க</h2><form id="add">
<label>பெயர்<input name="name" maxlength="80" required></label>
<label>பணி (விருப்பம்)<input name="work" maxlength="120" placeholder="உதா. டைலர்"></label>
<label>வழக்கமான வருகை நேரம்<input name="regular" type="time" required></label>
<button class="primary">சேர்க்க</button></form></section>
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
<a href="/signout-with-chatgpt?return_to=%2F">Admin கணக்கிலிருந்து வெளியேறு</a></section>
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
async function loadReport() {
  const data = await api('admin/today');
  roster = data.staff;
  const picker = element('person-records');
  const picked = picker.value;
  picker.replaceChildren(new Option('பெயரைத் தேர்வு செய்யவும்', ''), ...roster.map(person =>
    new Option(person.name + ' · #' + person.id, person.id)
  ));
  picker.value = picked;
  element('report-day').textContent = data.day;
  element('report').replaceChildren(...data.staff.map(person => {
    const row = document.createElement('li');
    const name = document.createElement('strong');
    name.textContent = person.name + ' · #' + person.id + (person.work ? ' · ' + person.work : '');
    const schedule = document.createElement('small');
    schedule.textContent = 'வழக்கமான வருகை ' + person.regular_time;
    const actual = document.createElement('small');
    actual.textContent = 'வருகை ' + (person.time_in || '—') + ' · புறப்பாடு ' + (person.time_out || '—');
    row.append(name, schedule, actual);
    return row;
  }));
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
      await loadLedger(person);
    } catch (error) { fail(error); }
    finally { lock(false); }
  };
}

if (element('add')) {
  setupRecords();
  loadReport().then(() => { element('admin-panel').hidden = false; }).catch(error => {
    if (error.status === 401) element('signin').hidden = false;
    showError(error);
  });
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
