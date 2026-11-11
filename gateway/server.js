#!/usr/bin/env node
'use strict';

/**
 * 12179 gateway
 *  - 浏览器 / CloudRein API / 静态资源 -> CloudRein (12151)
 *  - WebDAV 协议方法 / Basic 认证的 GET -> rclone (12150)
 */

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '12179', 10);
const CLOUD = {
  host: process.env.CLOUDREIN_HOST || '127.0.0.1',
  port: parseInt(process.env.CLOUDREIN_PORT || '12151', 10),
};
const RCLONE = {
  host: process.env.RCLONE_HOST || '127.0.0.1',
  port: parseInt(process.env.RCLONE_PORT || '12150', 10),
};
const ASSETS_DIR = path.resolve(process.env.ASSETS_DIR || '/opt/cloudrein/app/assets');
const DEBUG = !!process.env.LOG_REQUESTS;

const DAV_METHODS = new Set([
  'PROPFIND', 'PROPPATCH', 'MKCOL', 'LOCK', 'UNLOCK', 'MOVE', 'COPY', 'OPTIONS',
]);

const MIME = {
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

function upstreamFor(req) {
  const url = (req.url || '/').split('?')[0];
  const method = (req.method || 'GET').toUpperCase();
  const auth = String(req.headers.authorization || '').toLowerCase();

  if (url.startsWith('/assets/')) return 'assets';
  if (DAV_METHODS.has(method)) return 'rclone';
  if (method === 'PUT' || method === 'DELETE' || method === 'PATCH') return 'rclone';
  if (url.startsWith('/api/') || url.startsWith('/socket.io/')) return 'cloud';
  if (method === 'GET' || method === 'HEAD') {
    if (url === '/' || url === '/files' || url === '/monitor' || url === '/tools') return 'cloud';
    if (url === '/logo.svg' || url === '/favicon.svg') return 'cloud';
    if (auth.startsWith('basic ')) return 'rclone';
    return 'cloud';
  }
  return 'cloud';
}

function serveAsset(req, res, urlPath) {
  let rel;
  try {
    rel = decodeURIComponent(urlPath.slice('/assets/'.length));
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }
  const file = path.resolve(ASSETS_DIR, rel);
  if (file !== ASSETS_DIR && !file.startsWith(ASSETS_DIR + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Forbidden');
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not Found');
    }
    const headers = {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Last-Modified': st.mtime.toUTCString(),
      'X-Content-Type-Options': 'nosniff',
    };
    res.writeHead(200, headers);
    if ((req.method || 'GET').toUpperCase() === 'HEAD') return res.end();
    const stream = fs.createReadStream(file);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
}

function proxy(req, res, target) {
  const headers = Object.assign({}, req.headers);
  headers.host = `${target.host}:${target.port}`;
  headers['x-forwarded-for'] = (req.headers['x-forwarded-for'] || '') +
    (req.headers['x-forwarded-for'] ? ', ' : '') + (req.socket.remoteAddress || '');
  headers['x-forwarded-proto'] = req.headers['x-forwarded-proto'] || 'http';
  headers['x-forwarded-host'] = req.headers.host || '';

  const upstreamReq = http.request({
    hostname: target.host,
    port: target.port,
    method: req.method,
    path: req.url,
    headers,
    timeout: 0,
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
    upstreamRes.pipe(res);
    upstreamRes.on('error', () => res.destroy());
  });

  upstreamReq.on('error', (err) => {
    console.error('[gateway] upstream error', target.host + ':' + target.port, req.method, req.url, err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('Bad Gateway');
  });

  req.on('aborted', () => upstreamReq.destroy());
  req.pipe(upstreamReq);
}

const server = http.createServer((req, res) => {
  const where = upstreamFor(req);
  if (DEBUG) console.log('[gateway]', req.method, req.url, '->', where);
  if (where === 'assets') return serveAsset(req, res, (req.url || '/').split('?')[0]);
  proxy(req, res, where === 'rclone' ? RCLONE : CLOUD);
});

// WebSocket passthrough (CloudRein SocketIO if ever used; WebDAV does not use WS)
server.on('upgrade', (req, socket, head) => {
  const isCloud = (req.url || '').startsWith('/socket.io/');
  const target = isCloud ? CLOUD : RCLONE;
  const conn = net.connect(target.port, target.host, () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const key = req.rawHeaders[i];
      const value = req.rawHeaders[i + 1];
      if (key.toLowerCase() === 'host') lines.push(`Host: ${target.host}:${target.port}`);
      else lines.push(`${key}: ${value}`);
    }
    conn.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) conn.write(head);
    conn.pipe(socket);
    socket.pipe(conn);
  });
  conn.on('error', () => socket.destroy());
  socket.on('error', () => conn.destroy());
});

server.requestTimeout = 0;
server.headersTimeout = 65000;
server.keepAliveTimeout = 65000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[gateway] listening on 0.0.0.0:${PORT} cloud=${CLOUD.host}:${CLOUD.port} rclone=${RCLONE.host}:${RCLONE.port}`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));