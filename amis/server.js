// AMIS 前端开发服务器（零依赖，仅用 Node 内置模块）
//  - 静态托管本目录下的页面与资源（login.html / index.html / pages / sdk ...）
//  - 把 /auth /capt /api /health /uploads 反向代理到后端，使浏览器同源访问，
//    session Cookie 与登录态无需 CORS 即可工作。
// 环境变量：PORT（默认 3000）、API_TARGET（默认 http://127.0.0.1:22222）
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const target = new URL(process.env.API_TARGET || 'http://127.0.0.1:22222');
const ROOT = __dirname;
const PROXY_PREFIXES = ['/auth', '/capt', '/api', '/health', '/uploads', '/refapi', '/account'];
const DENY = new Set(['server.js', 'package.json', 'package-lock.json', 'nodemon.json', 'README.md']);
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.eot': 'application/vnd.ms-fontobject',
};

function isProxied(pathname) {
  return PROXY_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

function proxy(req, res) {
  const headers = { ...req.headers, host: target.host };
  delete headers.origin; // 同源转发，避免后端按 Origin 判定跨域
  const up = http.request(
    { hostname: target.hostname, port: target.port || 80, method: req.method, path: req.url, headers },
    (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }
  );
  up.on('error', (e) => {
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ status: 502, message: '后端不可达: ' + e.code }));
  });
  req.pipe(up);
}

function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch (e) { rel = null; }
  if (rel === null || rel.includes('\0')) { res.writeHead(400); return res.end('Bad Request'); }
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(ROOT, rel));
  const within = file.startsWith(ROOT + path.sep);
  const parts = path.relative(ROOT, file).split(path.sep);
  if (!within || DENY.has(parts[0]) || parts.some((s) => s.startsWith('.') || s === 'node_modules')) {
    res.writeHead(404); return res.end('Not Found');
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('Not Found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
}

http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://x').pathname;
  if (isProxied(pathname)) return proxy(req, res);
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  serveStatic(req, res, pathname);
}).listen(PORT, '127.0.0.1', () => {
  console.log('AMIS 前端: http://127.0.0.1:' + PORT + '/login.html  (后端代理 -> ' + target.origin + ')');
});
