const { spawn, execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const net = require('net');

const PORT = 8001;
const HOST = '127.0.0.1';
const DATA = '/data';
const CFG_UG = '/cfg/ugb/config.json';
const CFG_STORE = '/cfg/appstore/config.json';
const CHECKUPK = '/cfg/appstore/.check-upk';
const MARK_RESTART = DATA + '/.fixer-last-restart';
const MARK_PATCHED = DATA + '/.fixer-patched';
const PORT_INFO = '"portInfo": {"httpsEnable": false, "port": "8000", "httpsPort": "", "urlPath": ""},';
const HOSTS = ['*.ugdocker.link', '*.ugapp.link', '*.ug.link', '*.windtech.top'];
const SKIP_FIXER = process.env.WS_SKIP_FIXER === '1';

function log(m) { console.log('[ws] ' + m); }

// ---- 1. 数据卷初始化（root 身份，替代镜像 entrypoint 的 chown 阶段）----
try {
  ['dependencies', 'home', 'logs'].forEach(function (d) { fs.mkdirSync(DATA + '/' + d, { recursive: true }); });
  execSync('chown -R 1000:1000 ' + DATA, { stdio: 'ignore' });
  fs.mkdirSync(DATA + '/dependencies/adb', { recursive: true });
  if (!fs.existsSync(DATA + '/dependencies/adb/adb')) fs.symlinkSync('/usr/bin/adb', DATA + '/dependencies/adb/adb');
  log('data volume prepared');
} catch (e) { log('init failed: ' + e.message); }

// ---- 2. 真实服务子进程（uid 1000）----
let child = null;
let restarting = false;
function startWs() {
  const env = Object.assign({}, process.env, { PORT: String(PORT), WS_SCRCPY_WEB_PORT: String(PORT), HOME: DATA + '/home' });
  child = spawn('/bin/bash', ['/app/start.sh'], { env: env, stdio: 'inherit', uid: 1000, gid: 1000 });
  child.on('exit', function (code) {
    child = null;
    if (!restarting) { log('ws service exited (' + code + '), restarting'); setTimeout(startWs, 3000); }
  });
  log('ws service started');
}
startWs();

// ---- 3. 前置代理（UGOS 探测端点、跨源嵌入、cookie 代持）----
const ALLOW = "frame-ancestors 'self' https://*.ug.link https://*.ugapp.link https://*.ugdocker.link https://*.fnos.net http://*:8000";
let gateToken = null;

function originHost(origin) {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    return { host: u.host, proto: u.protocol.replace(':', '') };
  } catch (e) { return null; }
}

function needCross(req) {
  const h = String(req.headers.host || '').split(':')[0];
  return h.indexOf('.ugapp.link') > -1 || h.indexOf('.ugdocker.link') > -1 || h.indexOf('.ug.link') > -1 || h.indexOf('.fnos.net') > -1;
}

function fwdHeaders(req) {
  const h = Object.assign({}, req.headers);
  const o = originHost(req.headers.origin);
  if (o) {
    h.host = o.host;
    h['x-forwarded-host'] = o.host;
    h['x-forwarded-proto'] = o.proto;
  }
  if (gateToken && !/ws_scrcpy_token=/.test(String(h.cookie || ''))) {
    h.cookie = (h.cookie ? h.cookie + '; ' : '') + 'ws_scrcpy_token=' + gateToken;
  }
  return h;
}

function learnToken(r) {
  const sc = r.headers['set-cookie'];
  if (!sc) return;
  const arr = Array.isArray(sc) ? sc : [sc];
  for (let i = 0; i < arr.length; i++) {
    const m = /ws_scrcpy_token=([^;]+)/i.exec(arr[i]);
    if (m && m[1] && m[1] !== gateToken) gateToken = m[1];
  }
}

function refreshToken() {
  const q = http.request({ host: HOST, port: PORT, path: '/', method: 'GET', headers: { host: 'localhost' } }, function (r) {
    learnToken(r); r.resume();
  });
  q.on('error', function () {});
  q.end();
}

function reCookies(v, cross) {
  const arr = Array.isArray(v) ? v : [v];
  return arr.map(function (c) {
    if (!cross) return c;
    let s = c.replace(/SameSite=Strict/gi, 'SameSite=None').replace(/SameSite=Lax/gi, 'SameSite=None');
    if (!/SameSite=None/i.test(s)) s = s + '; SameSite=None';
    if (!/Secure/i.test(s)) s = s + '; Secure';
    return s;
  });
}

function fixHeaders(h, req) {
  const out = {};
  const origin = req.headers.origin;
  const cross = needCross(req);
  for (const k in h) {
    const lk = k.toLowerCase();
    if (lk === 'x-frame-options') continue;
    if (lk === 'set-cookie') { out[k] = reCookies(h[k], cross); continue; }
    out[k] = h[k];
  }
  out['content-security-policy'] = ALLOW;
  if (origin) {
    out['access-control-allow-origin'] = origin;
    out['access-control-allow-credentials'] = 'true';
    out['access-control-allow-methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
    out['access-control-allow-headers'] = req.headers['access-control-request-headers'] || 'content-type,authorization';
    out['access-control-expose-headers'] = 'content-type';
    out['access-control-max-age'] = '86400';
    out['vary'] = 'Origin';
  }
  return out;
}

const srv = http.createServer(function (req, res) {
  const origin = req.headers.origin;
  if (req.method === 'OPTIONS') {
    const hdr = {
      'content-security-policy': ALLOW,
      'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'access-control-allow-headers': req.headers['access-control-request-headers'] || 'content-type,authorization',
      'access-control-max-age': '86400'
    };
    if (origin) { hdr['access-control-allow-origin'] = origin; hdr['access-control-allow-credentials'] = 'true'; }
    res.writeHead(204, hdr);
    return res.end();
  }
  if (req.url.indexOf('/api/ugreen/auth') === 0) {
    const hdr = { 'Content-Type': 'application/json', 'content-security-policy': ALLOW };
    if (origin) { hdr['access-control-allow-origin'] = origin; hdr['access-control-allow-credentials'] = 'true'; }
    res.writeHead(200, hdr);
    return res.end('{"code":0,"success":true}');
  }
  const o = http.request({ host: HOST, port: PORT, path: req.url, method: req.method, headers: fwdHeaders(req) }, function (r) {
    learnToken(r);
    res.writeHead(r.statusCode, fixHeaders(r.headers, req));
    r.pipe(res);
  });
  o.on('error', function () { res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('gateway error'); });
  req.pipe(o);
});

srv.on('upgrade', function (req, sock, head) {
  const up = net.connect(PORT, HOST, function () {
    let h = req.method + ' ' + req.url + ' HTTP/1.1\r\n';
    const fh = fwdHeaders(req);
    for (const k in fh) { h += k + ': ' + fh[k] + '\r\n'; }
    h += '\r\n';
    up.write(h);
    if (head && head.length) up.write(head);
    up.pipe(sock); sock.pipe(up);
  });
  up.on('error', function () { sock.destroy(); });
});

refreshToken();
srv.listen(8000, function () { log('gate listening on 8000'); });

// ---- 4. 安装补丁（原 ws-open-fixer 逻辑）----
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
function readSafe(p) { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } }
function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }

async function waitStable() {
  let last = -1, same = 0;
  const deadline = Date.now() + 70000;
  while (Date.now() < deadline) {
    let mt = 0;
    [CFG_UG, CFG_STORE].forEach(function (p) {
      try { mt = Math.max(mt, fs.statSync(p).mtimeMs); } catch (e) { }
    });
    if (mt === last) { same++; if (same >= 2) return; } else { same = 0; last = mt; }
    await sleep(3000);
  }
}

function patchPortInfo(p, label) {
  const s = readSafe(p);
  if (!s || s.indexOf('"portInfo"') > -1) return false;
  const out = s.replace('"baseAccessInfo":{', '"baseAccessInfo":{' + PORT_INFO);
  if (out === s) return false;
  fs.writeFileSync(p, out);
  log('portInfo patched: ' + label);
  return true;
}

function syncCheckUpk() {
  const s = readSafe(CFG_STORE);
  const c = readSafe(CHECKUPK);
  if (!s || !c) return false;
  const h = md5(s);
  const out = c.replace(/"config.json":\{"hash":"[a-f0-9]{32}"/, '"config.json":{"hash":"' + h + '"');
  if (out === c) return false;
  fs.writeFileSync(CHECKUPK, out);
  log('check-upk hash synced');
  return true;
}

function restartAppServ() {
  try {
    execSync('nsenter -t 1 -m -u -i -n -p systemctl restart app_serv.service', { stdio: 'ignore', timeout: 30000 });
    fs.writeFileSync(MARK_RESTART, String(Date.now()));
    log('app_serv restarted');
    return true;
  } catch (e) { log('app_serv restart failed: ' + e.message); return false; }
}

function syncAllowedHosts() {
  const p = DATA + '/config.json';
  const s = readSafe(p);
  if (!s) return false;
  let d = null;
  try { d = JSON.parse(s); } catch (e) { return false; }
  const before = JSON.stringify(d.allowedHosts || []);
  const set = new Set(d.allowedHosts || []);
  HOSTS.forEach(function (h) { set.add(h); });
  d.allowedHosts = Array.from(set);
  const after = JSON.stringify(d.allowedHosts);
  if (before === after) { log('allowedHosts unchanged'); return false; }
  fs.writeFileSync(p, JSON.stringify(d, null, 2));
  log('allowedHosts updated');
  return true;
}

function restartWsService() {
  if (!child) { startWs(); return; }
  restarting = true;
  log('restarting ws service to apply config');
  child.once('exit', function () { restarting = false; startWs(); });
  child.kill('SIGTERM');
}

async function fixer() {
  try {
    if (SKIP_FIXER) { log('fixer skipped by env'); return; }
    await waitStable();
    let patched = fs.existsSync(MARK_PATCHED);
    if (patchPortInfo(CFG_UG, 'ugb') || patchPortInfo(CFG_STORE, 'appstore')) {
      patched = true;
      fs.writeFileSync(MARK_PATCHED, '1');
      syncCheckUpk();
    }
    if (patched) {
      let recent = false;
      try { recent = (Date.now() - Number(fs.readFileSync(MARK_RESTART, 'utf8'))) < 180000; } catch (e) { }
      if (recent) log('app_serv restarted within 3 min, skip');
      else restartAppServ();
    } else {
      log('portInfo present, no app_serv restart needed');
    }
    if (syncAllowedHosts()) restartWsService();
    log('fixer done');
  } catch (e) { log('fixer error: ' + e.message); }
}

setTimeout(fixer, 6000);

process.on('SIGTERM', function () {
  if (child) child.kill('SIGTERM');
  process.exit(0);
});
