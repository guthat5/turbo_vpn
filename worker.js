// VPN admin panel + API for Cloudflare Workers.
// Needs: KV binding named DB, secrets ADMIN_PASSWORD and APP_KEY.

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a || '')),
    crypto.subtle.digest('SHA-256', enc.encode(b || '')),
  ]);
  return crypto.subtle.timingSafeEqual(x, y);
}

async function load(env) {
  const raw = await env.DB.get('servers');
  return raw ? JSON.parse(raw) : [];
}
async function save(env, list) {
  await env.DB.put('servers', JSON.stringify(list));
}

const PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'ss://'];

function clean(b) {
  const name = String(b.name || '').trim().slice(0, 60);
  const country = String(b.country || '').trim().toUpperCase().slice(0, 3);
  const link = String(b.link || '').trim();
  if (!name) return { error: 'Enter a name' };
  if (!PROTOCOLS.some((p) => link.startsWith(p)) || link.length > 4000) {
    return { error: 'Link must start with vless://, vmess://, trojan:// or ss://' };
  }
  return { name, country, link };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!env.DB) return json({ error: 'KV binding DB is missing' }, 500);

    // ---- Public API for the app ----
    if (path === '/api/servers' && request.method === 'GET') {
      const ok =
        env.APP_KEY && (await safeEqual(request.headers.get('X-App-Key'), env.APP_KEY));
      if (!ok) return json({ error: 'Unauthorized' }, 401);
      const list = (await load(env))
        .filter((s) => s.active)
        .map(({ id, name, country, link }) => ({ id, name, country, link }));
      return json({ servers: list });
    }

    // ---- Admin page ----
    if (path === '/admin') {
      return new Response(ADMIN_HTML, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        },
      });
    }

    // ---- Admin API ----
    const m = path.match(/^\/admin\/api\/servers(?:\/([\w-]+))?$/);
    if (m) {
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
      const ok = env.ADMIN_PASSWORD && (await safeEqual(token, env.ADMIN_PASSWORD));
      if (!ok) return json({ error: 'Wrong password' }, 401);

      const id = m[1];
      const list = await load(env);

      if (request.method === 'GET' && !id) return json({ servers: list });

      let body = {};
      if (request.method === 'POST' || request.method === 'PUT') {
        try {
          body = await request.json();
        } catch (_) {
          return json({ error: 'Bad request' }, 400);
        }
      }

      if (request.method === 'POST' && !id) {
        const c = clean(body);
        if (c.error) return json({ error: c.error }, 400);
        if (list.length >= 100) return json({ error: 'Too many servers' }, 400);
        const item = { id: crypto.randomUUID(), ...c, active: true };
        list.push(item);
        await save(env, list);
        return json({ server: item });
      }

      const idx = list.findIndex((s) => s.id === id);
      if (idx < 0) return json({ error: 'Not found' }, 404);

      if (request.method === 'PUT') {
        const merged = {
          name: body.name ?? list[idx].name,
          country: body.country ?? list[idx].country,
          link: body.link ?? list[idx].link,
        };
        const c = clean(merged);
        if (c.error) return json({ error: c.error }, 400);
        list[idx] = {
          ...list[idx],
          ...c,
          active: typeof body.active === 'boolean' ? body.active : list[idx].active,
        };
        await save(env, list);
        return json({ server: list[idx] });
      }

      if (request.method === 'DELETE') {
        list.splice(idx, 1);
        await save(env, list);
        return json({ ok: true });
      }
    }

    return new Response('OK');
  },
};

const ADMIN_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>VPN admin</title>
<style>
:root{--bg:#fff;--card:#f4f4f2;--text:#1a1a1a;--muted:#666;--line:#d9d9d4;--accent:#1a73e8;--danger:#c62828;--ok:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b1f25;--text:#eee;--muted:#9aa3ad;--line:#2c323a;--accent:#6ea8fe;--danger:#ff8a8a;--ok:#66bb6a}}
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--text)}
.wrap{max-width:560px;margin:0 auto;padding:16px}
h1{font-size:20px;font-weight:500;margin:0}
h2{font-size:15px;font-weight:500;margin:24px 0 8px;color:var(--muted)}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
input,textarea{width:100%;padding:10px 12px;margin:0 0 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font:inherit}
textarea{min-height:96px;font-family:ui-monospace,monospace;font-size:13px}
button{padding:9px 14px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--text);font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--danger)}
.row{display:flex;gap:8px;flex-wrap:wrap}
.card{background:var(--card);border-radius:12px;padding:12px 14px;margin-bottom:10px}
.name{font-weight:500}
.sub{font-size:13px;color:var(--muted);word-break:break-all}
.on{color:var(--ok)}.off{color:var(--muted)}
.err{color:var(--danger);font-size:14px;min-height:20px;margin:0 0 8px}
.hidden{display:none}
</style></head><body><div class="wrap">

<div id="login">
  <h1>VPN admin</h1>
  <h2>Sign in</h2>
  <input id="pw" type="password" placeholder="Admin password" autocomplete="current-password">
  <p class="err" id="lerr"></p>
  <button class="primary" id="lbtn">Sign in</button>
</div>

<div id="main" class="hidden">
  <div class="top"><h1>Servers</h1><button id="out">Sign out</button></div>
  <div id="list"></div>

  <h2 id="ftitle">Add a server</h2>
  <input id="fname" placeholder="Name, for example Singapore 1">
  <input id="fcountry" placeholder="Country code, for example SG" maxlength="3">
  <textarea id="flink" placeholder="vless://..."></textarea>
  <p class="err" id="ferr"></p>
  <div class="row">
    <button class="primary" id="fsave">Add server</button>
    <button id="fcancel" class="hidden">Cancel</button>
  </div>
</div>

</div>
<script>
var pw = sessionStorage.getItem('pw') || '';
var servers = [];
var editing = null;
function $(id){return document.getElementById(id);}

function api(method, suffix, body){
  return fetch('/admin/api/servers' + (suffix || ''), {
    method: method,
    headers: {'Authorization': 'Bearer ' + pw, 'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined
  }).then(function(r){
    return r.json().then(function(d){
      if(!r.ok) throw new Error(d.error || 'Something went wrong');
      return d;
    });
  });
}

function el(tag, text, cls){
  var e = document.createElement(tag);
  if(text !== undefined) e.textContent = text;
  if(cls) e.className = cls;
  return e;
}

function render(){
  var box = $('list');
  box.textContent = '';
  if(!servers.length){
    box.appendChild(el('p', 'No servers yet. Add your first one below.', 'sub'));
  }
  servers.forEach(function(s){
    var c = el('div', undefined, 'card');
    c.appendChild(el('div', s.name + (s.country ? '  (' + s.country + ')' : ''), 'name'));
    c.appendChild(el('div', s.active ? 'Visible in app' : 'Hidden', s.active ? 'sub on' : 'sub off'));
    c.appendChild(el('div', s.link.slice(0, 60) + (s.link.length > 60 ? '...' : ''), 'sub'));
    var r = el('div', undefined, 'row');
    r.style.marginTop = '10px';
    var t = el('button', s.active ? 'Hide' : 'Show');
    t.onclick = function(){ api('PUT', '/' + s.id, {active: !s.active}).then(load).catch(showErr); };
    var e = el('button', 'Edit');
    e.onclick = function(){ startEdit(s); };
    var d = el('button', 'Delete', 'danger');
    d.onclick = function(){
      if(confirm('Delete ' + s.name + '?')) api('DELETE', '/' + s.id).then(load).catch(showErr);
    };
    r.appendChild(t); r.appendChild(e); r.appendChild(d);
    c.appendChild(r);
    box.appendChild(c);
  });
}

function showErr(e){ $('ferr').textContent = e.message; }

function load(){
  return api('GET').then(function(d){
    servers = d.servers;
    $('login').classList.add('hidden');
    $('main').classList.remove('hidden');
    render();
  });
}

function resetForm(){
  editing = null;
  $('fname').value = ''; $('fcountry').value = ''; $('flink').value = '';
  $('ferr').textContent = '';
  $('ftitle').textContent = 'Add a server';
  $('fsave').textContent = 'Add server';
  $('fcancel').classList.add('hidden');
}

function startEdit(s){
  editing = s.id;
  $('fname').value = s.name; $('fcountry').value = s.country; $('flink').value = s.link;
  $('ftitle').textContent = 'Edit server';
  $('fsave').textContent = 'Save changes';
  $('fcancel').classList.remove('hidden');
  window.scrollTo(0, document.body.scrollHeight);
}

$('fsave').onclick = function(){
  var body = {name: $('fname').value, country: $('fcountry').value, link: $('flink').value};
  var p = editing ? api('PUT', '/' + editing, body) : api('POST', '', body);
  p.then(function(){ resetForm(); return load(); }).catch(showErr);
};
$('fcancel').onclick = resetForm;

$('lbtn').onclick = function(){
  pw = $('pw').value;
  $('lerr').textContent = '';
  load().then(function(){ sessionStorage.setItem('pw', pw); })
        .catch(function(e){ $('lerr').textContent = e.message; });
};
$('pw').addEventListener('keydown', function(e){ if(e.key === 'Enter') $('lbtn').click(); });
$('out').onclick = function(){ sessionStorage.removeItem('pw'); location.reload(); };

if(pw){ load().catch(function(){ sessionStorage.removeItem('pw'); }); }
</script></body></html>`;
