'use strict';

const express = require('express');
const { readFile } = require('fs/promises');
const { join } = require('path');
const { createShield, apiKeyAuth, signToken, jwtAuth, comparePassword, hashPassword } = require('iri-shield');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'iri-test-dev-secret';
const apiKey = process.env.API_KEY || 'iri-demo-key';

app.use(express.json({ limit: '200kb' }));

// ---------------------------------------------------------------------------
// iri-shield setup
// ---------------------------------------------------------------------------

const shield = createShield({
  appName: 'iri-test',
  security: 'medium',       // 'low' | 'medium' | 'high'
  cors: true,
  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'sqlite',
    sqliteFile: process.env.IRI_SQLITE_FILE || './data/iri-shield.sqlite'
  },
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,
    max: 60
  },
  block: {
    enabled: true,
    threshold: 75,
    durationMs: 24 * 60 * 60 * 1000
  },
  alert: {
    enabled: true,
    threshold: 30
  },
  testing: {
    enabled: true,              // enable testing mode — allows header/body overrides
    allowClientOverrides: true
  },
  dashboard: {
    username: 'admin',
    password: 'admin',
    refreshMs: 30 * 1000     // refresh every 30s in dev
  },
  anomaly: {
    sensitiveEndpoints: ['/admin', '/internal', '/.env', '/config', '/debug', '/backup']
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

let adminHashPromise = hashPassword('admin');

app.get('/', (req, res) => {
  res.json({
    name: 'iri-test',
    package: 'iri-shield',
    dashboard: '/iri-shield',
    credentials: { username: 'admin', password: 'admin' },
    endpoints: [
      'GET  /api/public',
      'GET  /api/private   (x-api-key: iri-demo-key)',
      'GET  /api/jwt-profile (Bearer token)',
      'GET  /api/products',
      'GET  /api/users/:id',
      'GET  /api/search?q=...',
      'POST /login',
      'POST /api/upload',
      'GET  /admin/reports',
      'GET  /internal/health',
      'GET  /.env',
      'GET  /metrics',
      'POST /research/replay'
    ]
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const adminHash = await adminHashPromise;
  const valid = username === 'admin' && (await comparePassword(password || '', adminHash));
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  return res.json({
    token: signToken({ sub: 'admin', role: 'admin' }, jwtSecret),
    email: 'admin@example.com'
  });
});

// ---------------------------------------------------------------------------
// Public API endpoints
// ---------------------------------------------------------------------------

app.get('/api/public', (req, res) => {
  res.json({ ok: true, message: 'Public endpoint monitored by iri-shield', ts: new Date().toISOString() });
});

app.get('/api/products', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  res.json({
    ok: true,
    page,
    products: [
      { id: 1, name: 'Widget A', price: 9.99 },
      { id: 2, name: 'Widget B', price: 19.99 }
    ]
  });
});

app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;
  res.json({
    ok: true,
    user: { id, name: 'Test User', email: 'user@example.com' }
  });
});

app.get('/api/search', (req, res) => {
  res.json({ q: req.query.q || '', result: 'Search endpoint for anomaly testing', total: 0 });
});

// ---------------------------------------------------------------------------
// Protected API endpoints
// ---------------------------------------------------------------------------

app.get('/api/private', apiKeyAuth(apiKey), (req, res) => {
  res.json({
    ok: true,
    message: 'API key accepted',
    token: 'sample-sensitive-token',
    email: 'researcher@example.com',
    phone: '9876543210'
  });
});

app.get('/api/jwt-profile', jwtAuth(jwtSecret), (req, res) => {
  res.json({
    ok: true,
    user: req.user,
    accessToken: 'sample-access-token',
    apiKey: apiKey
  });
});

app.post('/api/upload', (req, res) => {
  const body = req.body || {};
  res.json({ ok: true, received: Object.keys(body).length + ' fields', size: JSON.stringify(body).length });
});

// ---------------------------------------------------------------------------
// Sensitive endpoints (for testing detection)
// ---------------------------------------------------------------------------

app.get('/admin/reports', (req, res) => {
  res.json({ report: 'sensitive endpoint access should be logged', secret: 'admin-only-data' });
});

app.get('/internal/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), memory: process.memoryUsage() });
});

app.get('/.env', (req, res) => {
  // Intentionally return something to test detection (should be flagged)
  res.json({ note: 'This access is flagged by iri-shield' });
});

app.get('/config', (req, res) => {
  res.json({ note: 'Config probe endpoint — should trigger alert' });
});

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------

app.get('/metrics', (req, res) => {
  res.json(shield.getStats());
});

// ---------------------------------------------------------------------------
// Dataset replay
// ---------------------------------------------------------------------------

app.post('/research/replay', async (req, res, next) => {
  try {
    const result = await replayDataset();
    res.json(result);
  } catch (error) {
    next(error);
  }
});

async function replayDataset() {
  const datasetPath = join(__dirname, 'client_requests.json');
  const rows = JSON.parse(await readFile(datasetPath, 'utf8'));
  const results = [];

  for (const row of rows) {
    const url = `http://localhost:${port}${row.url}`;
    const headers = {
      ...(row.headers || {}),
      'user-agent': row.userAgent || row.headers?.['user-agent'] || 'iri-dataset-client',
      'x-iri-test-ip': row.ip,
      'x-iri-test-user-agent': row.userAgent || '',
      'x-iri-test-user-id': row.userId || '',
      'x-iri-test-client-id': row.clientId || '',
      'x-iri-test-device-id': row.deviceId || '',
      'x-iri-test-session-id': row.sessionId || ''
    };
    if (row.cookie) headers['x-iri-test-cookie'] = row.cookie;
    if (row.body) headers['content-type'] = 'application/json';

    const startedAt = Date.now();
    let status = 0;
    let error = null;
    try {
      const response = await fetch(url, {
        method: row.method || 'GET',
        headers,
        body: row.body ? JSON.stringify(row.body) : undefined
      });
      status = response.status;
    } catch (err) {
      error = err.message;
    }

    results.push({
      id: row.id,
      scenario: row.scenario,
      expected: row.expected,
      status,
      error: error || undefined,
      durationMs: Date.now() - startedAt
    });
  }

  return {
    total: rows.length,
    blocked: results.filter(r => r.status === 403 || r.status === 429).length,
    passed: results.filter(r => r.status >= 200 && r.status < 300).length,
    results
  };
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(port, () => {
  console.log(`\n🛡️  iri-test running on http://localhost:${port}`);
  console.log(` Dashboard: http://localhost:${port}/iri-shield`);
  console.log(`   Credentials: admin / admin`);
  console.log(`   Storage: ${process.env.IRI_STORAGE_MODE || 'sqlite'}`);
  console.log(`   Security mode: medium`);
  console.log(`   Testing mode: ON (IP overrides via headers enabled)\n`);
});
