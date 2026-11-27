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
const TRUST_PROXY = process.env.CLOUDREIN_TRUST_PROXY === '1';
const PUBLIC_SCHEME = process.env.CLOUDREIN_PUBLIC_SCHEME === 'https' ? 'https' : 'http';
const SENSITIVE_PARAMS = new Set([
  'k', 'key', 'token', 'jd_ticket', 'access_token', 'refresh_token',
  'password', 'passwd', 'secret', 'signature', 'sig',
]);
const NESTED_URL_PARAMS = new Set(['return', 'return_to', 'redirect', 'redirect_uri', 'url', 'next']);

function sanitizeUrl(raw, depth = 0) {
  if (depth > 4) return '[redacted]';
  try {
    const url = new URL(String(raw || '/'), 'http://local');
    const sanitize = (value) => sanitizeUrl(value, depth + 1);
    for (const [name, value] of [...url.searchParams]) {
      const normalized = name.toLowerCase();
      if (SENSITIVE_PARAMS.has(normalized)) {
        url.searchParams.set(name, '[redacted]');
      } else if (NESTED_URL_PARAMS.has(normalized)
        && (value.startsWith('/') || /^[a-z][a-z\d+.-]*:\/\//i.test(value))) {
        url.searchParams.set(name, sanitize(value));
      }
    }
    url.username = '';
    url.password = '';
    url.hash = '';
    return url.pathname + url.search;
  } catch {
    return '/[invalid-url]';
  }
}

function forwardedProto(req, options = {}) {
  const trustProxy = options.trustProxy === undefined ? TRUST_PROXY : options.trustProxy;
  const publicScheme = options.publicScheme || PUBLIC_SCHEME;
  if (trustProxy) {
    const value = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    if (value === 'http' || value === 'https') return value;
  }
  return req.socket.encrypted ? 'https' : publicScheme;
}

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

function serveAsset(req, res, urlPath, assetsDir = ASSETS_DIR) {
  let rel;
  try {
    rel = decodeURIComponent(urlPath.slice('/assets/'.length));
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }
  const file = path.resolve(assetsDir, rel);
  if (file !== assetsDir && !file.startsWith(assetsDir + path.sep)) {
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

function proxy(req, res, target, options = {}) {
  const headers = Object.assign({}, req.headers);
  headers.host = `${target.host}:${target.port}`;
  headers['x-forwarded-for'] = (req.headers['x-forwarded-for'] || '') +
    (req.headers['x-forwarded-for'] ? ', ' : '') + (req.socket.remoteAddress || '');
  headers['x-forwarded-proto'] = options.forwardedProto || forwardedProto(req);
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
    console.error('[gateway] upstream error', target.host + ':' + target.port, req.method, sanitizeUrl(req.url), err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('Bad Gateway');
  });

  req.on('aborted', () => upstreamReq.destroy());
  req.pipe(upstreamReq);
}

function createServer(options = {}) {
  const cloud = options.cloud || CLOUD;
  const rclone = options.rclone || RCLONE;
  const assetsDir = options.assetsDir || ASSETS_DIR;
  const debug = Boolean(options.debug);
  const trustProxy = options.trustProxy === undefined ? TRUST_PROXY : Boolean(options.trustProxy);
  const publicScheme = options.publicScheme || PUBLIC_SCHEME;

  const server = http.createServer((req, res) => {
    const where = upstreamFor(req);
    if (debug) console.log('[gateway]', req.method, sanitizeUrl(req.url), '->', where);
    if (where === 'assets') return serveAsset(req, res, (req.url || '/').split('?')[0], assetsDir);
    const forwarded = forwardedProto(req, { trustProxy, publicScheme });
    proxy(req, res, where === 'rclone' ? rclone : cloud, { forwardedProto: forwarded });
  });

  server.on('upgrade', (req, socket, head) => {
    const isCloud = (req.url || '').startsWith('/socket.io/');
    const target = isCloud ? cloud : rclone;
    const conn = net.connect(target.port, target.host, () => {
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const key = req.rawHeaders[i];
        const value = req.rawHeaders[i + 1];
        if (key.toLowerCase() === 'host') lines.push(`Host: ${target.host}:${target.port}`);
        else if (key.toLowerCase() !== 'x-forwarded-proto') lines.push(`${key}: ${value}`);
      }
      lines.push(`X-Forwarded-Proto: ${forwardedProto(req, { trustProxy, publicScheme })}`);
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
  return server;
}

if (require.main === module) {
  const server = createServer();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[gateway] listening on 0.0.0.0:${PORT} cloud=${CLOUD.host}:${CLOUD.port} rclone=${RCLONE.host}:${RCLONE.port}`);
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { createServer, sanitizeUrl, forwardedProto, upstreamFor };