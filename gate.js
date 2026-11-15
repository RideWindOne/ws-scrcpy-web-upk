const http = require('http');
const net = require('net');
const HOST = 'ws-scrcpy-web';
const PORT = 8001;
const ALLOW = "frame-ancestors 'self' https://*.ug.link https://*.ugapp.link https://*.ugdocker.link https://*.fnos.net http://*:8000";

function originHost(origin) {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    return { host: u.host, proto: u.protocol.replace(':', '') };
  } catch (e) {
    return null;
  }
}

function fwdHeaders(req) {
  const h = Object.assign({}, req.headers);
  const o = originHost(req.headers.origin);
  if (o) {
    h.host = o.host;
    h['x-forwarded-host'] = o.host;
    h['x-forwarded-proto'] = o.proto;
    h['x-forwarded-origin'] = req.headers.origin;
  }
  if (gateToken && !/ws_scrcpy_token=/.test(String(h.cookie || ''))) {
    h.cookie = (h.cookie ? h.cookie + '; ' : '') + 'ws_scrcpy_token=' + gateToken;
  }
  return h;
}

let gateToken = null;
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
    learnToken(r);
    r.resume();
  });
  q.on('error', function () {});
  q.end();
}

function reCookies(v, cross) {
  const arr = Array.isArray(v) ? v : [v];
  return arr.map(function (c) {
    if (!cross) return c;
    let s = c.replace(/SameSite=Strict/gi, 'SameSite=None');
    s = s.replace(/SameSite=Lax/gi, 'SameSite=None');
    if (!/SameSite=None/i.test(s)) s = s + '; SameSite=None';
    if (!/Secure/i.test(s)) s = s + '; Secure';
    return s;
  });
}

function needCross(req) {
  const h = String(req.headers.host || '').split(':')[0];
  return h.indexOf('.ugapp.link') > -1 || h.indexOf('.ugdocker.link') > -1 || h.indexOf('.ug.link') > -1 || h.indexOf('.fnos.net') > -1;
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
    if (origin) {
      hdr['access-control-allow-origin'] = origin;
      hdr['access-control-allow-credentials'] = 'true';
    }
    res.writeHead(204, hdr);
    return res.end();
  }
  if (req.url.indexOf('/api/ugreen/auth') === 0) {
    const hdr = { 'Content-Type': 'application/json', 'content-security-policy': ALLOW };
    if (origin) {
      hdr['access-control-allow-origin'] = origin;
      hdr['access-control-allow-credentials'] = 'true';
    }
    res.writeHead(200, hdr);
    return res.end('{"code":0,"success":true}');
  }
  const opts = { host: HOST, port: PORT, path: req.url, method: req.method, headers: fwdHeaders(req) };
  const o = http.request(opts, function (r) {
    learnToken(r);
    res.writeHead(r.statusCode, fixHeaders(r.headers, req));
    r.pipe(res);
  });
  o.on('error', function () {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('gateway error');
  });
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
    up.pipe(sock);
    sock.pipe(up);
  });
  up.on('error', function () { sock.destroy(); });
});

refreshToken();
srv.listen(8000);
