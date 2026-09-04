'use strict';

const express = require('express');
const { readFile } = require('fs/promises');
const { join } = require('path');
const { createShield, apiKeyAuth, signToken, jwtAuth, comparePassword, hashPassword } = require('iri-shield');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'iri-test-dev-secret';
const apiKey = process.env.API_KEY || 'iri-example-key';
const isVercel = Boolean(process.env.VERCEL);
const storageMode = process.env.IRI_STORAGE_MODE || 'sqlite';
const sqliteFile = process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite');
const mongoUrl = process.env.IRI_MONGO_URL;

app.use(express.json({ limit: '200kb' }));

// ---------------------------------------------------------------------------
// iri-shield setup
// ---------------------------------------------------------------------------

const shield = createShield({
  appName: 'iri-test',
  security: 'medium',       // 'low' | 'medium' | 'high'
  cors: true,
  storage: {
    mode: storageMode,
    sqliteFile,
    mongoUrl
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
const adminApiAuth = jwtAuth(jwtSecret);

app.get('/', (req, res) => {
  res.type('html').send(renderHome(req));
});

app.post('/login', async (req, res) => {
  res.locals.iriShieldSkipRedaction = true;
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

app.get('/api/stats', adminApiAuth, (req, res) => {
  res.json(shield.getStats());
});

app.get('/metrics', adminApiAuth, (req, res) => {
  res.json(shield.getStats());
});

// ---------------------------------------------------------------------------
// Dataset replay
// ---------------------------------------------------------------------------

app.post('/research/replay', adminApiAuth, async (req, res, next) => {
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

function renderHome(req) {
  const origin = `${req.protocol}://${req.get('host')}`;
  const endpoints = [
    ['GET', '/api/public', 'Public monitored endpoint'],
    ['GET', '/api/products', 'Public sample endpoint'],
    ['GET', '/api/users/1', 'Public endpoint with PII redaction example'],
    ['GET', '/api/search?q=%27%20or%201%3D1', 'Threat detection test'],
    ['POST', '/login', 'Returns admin JWT for private APIs'],
    ['GET', '/api/private', 'Requires x-api-key: iri-example-key'],
    ['GET', '/api/jwt-profile', 'Requires Bearer token'],
    ['GET', '/api/stats', 'Private stats API, requires Bearer token'],
    ['GET', '/metrics', 'Private metrics API, requires Bearer token'],
    ['POST', '/research/replay', 'Private dataset replay, requires Bearer token'],
    ['GET', '/iri-shield', 'Private dashboard, admin/admin']
  ];

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --ink: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      --brand: #059669;
      --brand-dark: #047857;
      --warn: #b45309;
      --danger: #be123c;
      --code: #f1f5f9;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #dcfce7 0, transparent 28rem), var(--bg);
      color: var(--ink);
      line-height: 1.5;
    }
    a { color: var(--brand-dark); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }
    header { padding: 28px 0 18px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .mark { width: 44px; height: 44px; border-radius: 12px; background: var(--brand); color: white; display: grid; place-items: center; font-weight: 800; }
    nav { display: flex; gap: 10px; flex-wrap: wrap; }
    .btn { border: 1px solid var(--line); background: var(--panel); border-radius: 8px; padding: 10px 14px; font-weight: 650; color: var(--ink); }
    .btn.primary { background: var(--brand); border-color: var(--brand); color: white; }
    .hero { padding: 52px 0 36px; display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 28px; align-items: center; }
    h1 { font-size: clamp(2.4rem, 5vw, 5rem); line-height: 0.98; margin: 0; letter-spacing: 0; }
    .lead { margin: 20px 0 0; color: var(--muted); font-size: 1.08rem; max-width: 66ch; }
    .status { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .card { background: rgba(255,255,255,0.86); border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: 0 10px 30px rgba(15,23,42,0.06); }
    .label { color: var(--muted); font-size: 0.85rem; margin: 0 0 6px; }
    .value { margin: 0; font-size: 1.4rem; font-weight: 750; }
    main { padding-bottom: 56px; }
    .grid { display: grid; gap: 18px; grid-template-columns: repeat(3, 1fr); margin-top: 22px; }
    section { margin-top: 34px; }
    h2 { font-size: 1.55rem; margin: 0 0 12px; }
    .endpoint-table { width: 100%; border-collapse: collapse; font-size: 0.94rem; }
    th, td { border-bottom: 1px solid var(--line); padding: 12px 10px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.04em; }
    code, pre { background: var(--code); border-radius: 8px; }
    code { padding: 2px 6px; }
    pre { overflow: auto; padding: 14px; border: 1px solid var(--line); }
    .pill { display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 9px; font-size: 0.8rem; font-weight: 750; background: #ecfdf5; color: var(--brand-dark); }
    .private { background: #fff7ed; color: var(--warn); }
    .danger { background: #fff1f2; color: var(--danger); }
    .two { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    footer { color: var(--muted); padding: 24px 0 40px; border-top: 1px solid var(--line); }
    @media (max-width: 860px) {
      header, .hero, .two { grid-template-columns: 1fr; display: grid; }
      nav { justify-content: flex-start; }
      .grid, .status { grid-template-columns: 1fr; }
      h1 { font-size: 2.7rem; }
    }
  </style>
</head>
<body>
  <header class="shell">
    <div class="brand">
      <div class="mark">IS</div>
      <div>
        <strong>Iri Shield</strong>
        <div class="label">Multi-Layer API Security</div>
      </div>
    </div>
    <nav>
      <a class="btn" href="/iri-shield">Dashboard</a>
      <a class="btn" href="https://iri-shield.vercel.app/">Live Site</a>
      <a class="btn primary" href="/api/public">Try Public API</a>
    </nav>
  </header>

  <main class="shell">
    <section class="hero">
      <div>
        <span class="pill">Research prototype</span>
        <h1>API security middleware for Node.js apps.</h1>
        <p class="lead"><code>iri-shield</code> monitors API traffic, detects suspicious behaviour, tracks client identity drift, redacts sensitive response data, stores events, and provides a dashboard for research evaluation.</p>
      </div>
      <div class="status">
        <div class="card"><p class="label">Package</p><p class="value">iri-shield</p></div>
        <div class="card"><p class="label">Author</p><p class="value">ansari-in</p></div>
        <div class="card"><p class="label">Dashboard</p><p class="value">admin/admin</p></div>
        <div class="card"><p class="label">Storage</p><p class="value">${escapeHtml(storageMode)}</p></div>
      </div>
    </section>

    <section class="grid">
      <div class="card"><h2>Monitoring</h2><p>Captures IP, URL, method, user-agent, cookies, sessions, client id, device id, status and latency.</p></div>
      <div class="card"><h2>Detection</h2><p>Flags SQL injection, XSS, path traversal, sensitive endpoint probes, rate abuse and identity changes.</p></div>
      <div class="card"><h2>Research Data</h2><p>Use <code>client_requests.json</code> and replay scripts to generate normal and fake attacker traffic for evaluation.</p></div>
    </section>

    <section class="two">
      <div class="card">
        <h2>Private Admin APIs</h2>
        <p class="label">Stats and metrics are not public. First login, then use the Bearer token.</p>
        <pre>curl -X POST ${escapeHtml(origin)}/login \\
  -H "content-type: application/json" \\
  -d "{\\"username\\":\\"admin\\",\\"password\\":\\"admin\\"}"

curl ${escapeHtml(origin)}/api/stats \\
  -H "authorization: Bearer YOUR_TOKEN"</pre>
      </div>
      <div class="card">
        <h2>Useful URLs</h2>
        <p><strong>Dashboard:</strong> <a href="/iri-shield">/iri-shield</a></p>
        <p><strong>Live docs/site:</strong> <a href="https://iri-shield.vercel.app/">https://iri-shield.vercel.app/</a></p>
        <p><strong>Package docs:</strong> <a href="https://github.com/ansari-in/iri-shield#readme">GitHub README</a></p>
        <p><strong>NPM package:</strong> <a href="https://www.npmjs.com/package/iri-shield">npmjs.com/package/iri-shield</a></p>
      </div>
    </section>

    <section class="card">
      <h2>API Routes</h2>
      <table class="endpoint-table">
        <thead><tr><th>Method</th><th>URL</th><th>Purpose</th><th>Access</th></tr></thead>
        <tbody>
          ${endpoints.map(([method, url, purpose]) => renderEndpointRow(method, url, purpose)).join('')}
        </tbody>
      </table>
    </section>
  </main>

  <footer class="shell">
    iri-shield research is Security telemetry endpoints are private and require authenticated access.
  </footer>
</body>
</html>`;
}

function renderEndpointRow(method, url, purpose) {
  const privateRoute = url.includes('stats') || url.includes('metrics') || url.includes('replay') || url.includes('jwt') || url.includes('private') || url.includes('iri-shield');
  const risky = url.includes('admin') || url.includes('.env') || url.includes('search?q=');
  const access = privateRoute ? '<span class="pill private">authenticated</span>' : risky ? '<span class="pill danger">test threat</span>' : '<span class="pill">public</span>';
  return `<tr><td><code>${escapeHtml(method)}</code></td><td><a href="${escapeHtml(url)}">${escapeHtml(url)}</a></td><td>${escapeHtml(purpose)}</td><td>${access}</td></tr>`;
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[char]));
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(port, () => {
  console.log(`\n🛡️  iri-test running on http://localhost:${port}`);
  console.log(` Dashboard: http://localhost:${port}/iri-shield`);
  console.log(`   Credentials: admin / admin`);
  console.log(`   Storage: ${storageMode}${storageMode === 'sqlite' ? ` (${sqliteFile})` : ''}`);
  console.log(`   Security mode: medium`);
  console.log(`   Testing mode: ON (IP overrides via headers enabled)\n`);
});
