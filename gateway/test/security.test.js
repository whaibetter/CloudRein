'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { createServer, sanitizeUrl, forwardedProto } = require('../server');

test('request log sanitizer removes credentials and nested tokens', () => {
  const value = sanitizeUrl('/?k=master-value&token=abc-value&return=' + encodeURIComponent('https://user:password-value@example.com/a?jd_ticket=ticket-value#fragment-value'));
  assert.equal(value.includes('master-value'), false);
  assert.equal(value.includes('abc-value'), false);
  assert.equal(value.includes('ticket-value'), false);
  assert.equal(value.includes('password-value'), false);
  assert.equal(value.includes('fragment-value'), false);
  assert.match(value, /redacted/);
});

test('request log sanitizer handles encoded names and malformed URLs', () => {
  const value = sanitizeUrl('/?%6bey=hidden-value&next=/auth?access_token=token-value');
  assert.equal(value.includes('hidden-value'), false);
  assert.equal(value.includes('token-value'), false);
  assert.equal(sanitizeUrl('http://[broken?key=hidden'), '/[invalid-url]');
});

test('forwarded scheme ignores client header unless proxy is trusted', () => {
  const req = { headers: { 'x-forwarded-proto': 'https' }, socket: {} };
  assert.equal(forwardedProto(req, { trustProxy: false, publicScheme: 'http' }), 'http');
  assert.equal(forwardedProto(req, { trustProxy: true, publicScheme: 'http' }), 'https');
  assert.equal(forwardedProto({ ...req, headers: { 'x-forwarded-proto': 'javascript' } }, { trustProxy: true, publicScheme: 'http' }), 'http');
});

test('gateway overwrites forwarded scheme and preserves routing', async () => {
  let received;
  const upstream = http.createServer((req, res) => {
    received = { url: req.url, headers: req.headers };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const gateway = createServer({
    cloud: { host: '127.0.0.1', port: upstream.address().port },
    rclone: { host: '127.0.0.1', port: upstream.address().port },
    trustProxy: false,
    publicScheme: 'http',
  });
  await new Promise((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  try {
    const response = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: gateway.address().port,
        path: '/api/session?token=private',
        headers: { 'X-Forwarded-Proto': 'https' },
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body }));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(response.status, 200);
    assert.equal(received.url, '/api/session?token=private');
    assert.equal(received.headers['x-forwarded-proto'], 'http');
    assert.equal(received.headers.host, `127.0.0.1:${upstream.address().port}`);
  } finally {
    await new Promise((resolve) => gateway.close(resolve));
    await new Promise((resolve) => upstream.close(resolve));
  }
});
