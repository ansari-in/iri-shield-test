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
const mongoUrl = process.env.IRI_MONGO_URL;
const storageMode = process.env.IRI_STORAGE_MODE || (isVercel && mongoUrl ? 'mongodb' : 'sqlite');
const sqliteFile = process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite');
const dashboardUser = process.env.SHIELD_ADMIN_USER || 'admin';
const dashboardPassword = process.env.SHIELD_ADMIN_PASSWORD || 'admin';
const dashboardSessionSecret = process.env.IRI_SHIELD_DASHBOARD_SECRET || process.env.SESSION_SECRET || jwtSecret;


if (isVercel) {
  app.set('trust proxy', true);
}

app.use(express.json({ limit: '200kb' }));

// Serve static files from the 'public' folder
app.use(express.static(join(__dirname, 'public')));
console.log('Serving static files from:', join(__dirname, 'public'));

// Public research pages stay outside iri-shield blocking so visitors can always
// read the project site even if their IP is blocked from the demo API.
app.get('/', (req, res) => {
  res.type('html').send(renderHome(req));
});

app.get('/Generate_Media.md', async (_req, res, next) => {
  try {
    const markdown = await readFile(join(__dirname, 'Generate_Media.md'), 'utf8');
    res.type('text/markdown').send(markdown);
  } catch (error) {
    next(error);
  }
});

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
    username: dashboardUser,
    password: dashboardPassword,
    sessionSecret: dashboardSessionSecret,
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

app.get('/api/stats', adminApiAuth, async (req, res) => {
  res.json(await shield.getStats());
});

app.get('/metrics', adminApiAuth, async (req, res) => {
  res.json(await shield.getStats());
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
    ['GET', '/api/public', 'Public monitored endpoint', 'public'],
    ['GET', '/api/products', 'Public product API used for normal traffic', 'public'],
    ['GET', '/api/users/1', 'PII response example for redaction testing', 'public'],
    ['GET', '/api/search?q=%27%20or%201%3D1', 'SQL injection detection test', 'threat'],
    ['GET', '/admin/reports', 'Sensitive endpoint probe scenario', 'threat'],
    ['GET', '/.env', 'Secret discovery probe scenario', 'threat'],
    ['POST', '/login', 'Returns admin JWT for protected APIs', 'auth'],
    ['GET', '/api/private', 'Requires x-api-key header', 'auth'],
    ['GET', '/api/jwt-profile', 'Requires Bearer token', 'auth'],
    ['GET', '/api/stats', 'Private telemetry API', 'auth'],
    ['POST', '/research/replay', 'Controlled dataset replay', 'auth'],
    ['GET', '/iri-shield', 'Research dashboard', 'auth']
  ];
  const dashboardLabel = dashboardPassword === 'admin' ? `${dashboardUser}/admin` : `${dashboardUser}/configured`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Iri-Shield - API Security Research Middleware</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
            display: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
            Hero: ['Caveat','cursive'],
            mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
          },
          colors: {
            ink: '#111827',
            paper: '#fbfbf8',
            line: '#e5e7eb',
            cobalt: '#1d4ed8',
            ember: '#b45309',
            pine: '#047857',
            rose: '#be123c'
          }
        }
      }
    };
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
</head>
<body class="bg-paper text-ink antialiased">
  <header class="fixed inset-x-0 top-0 z-50 border-b border-line/80 bg-paper/90 backdrop-blur">
    <div class="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-5">
      <a class="flex items-center gap-3" href="#top" aria-label="Iri-Shield home">
        <span class="grid h-9 w-9 place-items-center rounded-md bg-cobalt text-sm font-black text-white shadow-sm">IS</span>
        <span>
          <span class="block text-sm font-extrabold tracking-tight">Iri-Shield</span>
          <span class="block text-[11px] font-medium uppercase tracking-[0.18em] text-slate-500">API Security Research</span>
        </span>
      </a>
      <nav class="hidden items-center gap-6 text-sm font-semibold text-slate-600 md:flex">
        <a class="hover:text-cobalt" href="#method">Method</a>
        <a class="hover:text-cobalt" href="#figures">Figures</a>
        <a class="hover:text-cobalt" href="#results">Results</a>
        <a class="hover:text-cobalt" href="#demo">Demo API</a>
        <a class="rounded-md border border-line bg-white px-3 py-2 text-slate-900 shadow-sm hover:border-cobalt" href="/iri-shield">Dashboard</a>
      </nav>
    </div>
  </header>

  <main id="top" class="pt-16">
    <section class="border-b border-line bg-white">
      <div class="mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-6xl grid-cols-1 gap-10 px-5 py-16 md:grid-cols-[1.05fr_0.95fr] md:items-center">
      <div>
          <p class="mb-5 inline-flex rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.18em] text-cobalt">Express.js middleware - research project</p>
          <h1 class="font-Hero mb-6 text-5xl font-extrabold leading-[0.96] tracking-normal text-slate-950 md:text-7xl" style="background: linear-gradient(90deg,#ff66c4,#ffc259); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">iri-shield</h1>
          <h1 class="font-display mb-6 text-xl font-bold leading-[0.96] tracking-normal text-slate-950">Practical API threat detection inside Node.js.</h1>
          <p class="mt-6 max-w-2xl text-lg leading-8 text-slate-600">Iri-Shield combines request hardening, multi-signal identity continuity, static attack rules, behavioral anomaly scoring, attack sequence correlation, automated mitigation, and recursive PII redaction in one Express.js middleware.</p>
          <div class="mt-8 flex flex-wrap gap-3">
            <a class="rounded-md bg-cobalt px-5 py-3 text-sm font-bold text-white shadow-sm hover:bg-blue-700" href="/iri-shield">Open dashboard</a>
            <a class="rounded-md border border-line bg-white px-5 py-3 text-sm font-bold text-slate-900 shadow-sm hover:border-cobalt" href="#demo">Explore demo routes</a>
            <a class="rounded-md border border-line bg-white px-5 py-3 text-sm font-bold text-slate-900 shadow-sm hover:border-cobalt" href="/api/public">Call public API</a>
          </div>
          <div class="mt-8 grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
            ${metricTile('97.3%', 'Attack detection', '214 of 220 controlled attacks')}
            ${metricTile('0.00%', 'False positives', 'Observed on evaluated legitimate traffic')}
            ${metricTile('100%', 'Identity accuracy', '500 controlled transition scenarios')}
            ${metricTile('100%', 'Redaction success', '500 sensitive payload tests')}
          </div>
        </div>
        <div class="relative">
          <div class="rounded-lg border border-slate-200 bg-slate-950 p-5 text-white shadow-2xl">
            <div class="mb-4 flex items-center justify-between border-b border-white/10 pb-3">
              <span class="font-mono text-xs text-slate-300">live-pipeline.json</span>
              <span class="rounded bg-emerald-400/15 px-2 py-1 text-[11px] font-bold text-emerald-300">MONITORED</span>
            </div>
            <pre class="overflow-hidden whitespace-pre-wrap font-mono text-[12px] leading-6 text-slate-200"><code>{
  "request": "GET /api/search?q=' or 1=1",
  "signals": ["sql_injection", "identity", "rate"],
  "riskScore": 82,
  "action": "blocked",
  "explainability": [
    "+30 SQL injection pattern",
    "+20 sensitive query context",
    "+12 sequence correlation"
  ],
  "response": "PII fields redacted before logging"
}</code></pre>
          </div>
          <div class="mt-4 rounded-lg border border-dashed border-slate-300 bg-slate-50 p-5">
            <p class="text-xs font-bold uppercase tracking-[0.18em] text-slate-500">Hero media slot</p>
            <p class="mt-2 text-sm leading-6 text-slate-600">Place a 20-30 second teaser video or animated dashboard capture here: incoming normal traffic, malicious payload detection, risk score breakdown, automated block, and redacted response shown as one smooth flow.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="border-b border-line">
      <div class="mx-auto grid w-full max-w-6xl grid-cols-1 gap-8 px-5 py-14 md:grid-cols-[0.35fr_0.65fr]">
        <div>
          <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">TL;DR</p>
          <h2 class="mt-3 font-display text-3xl font-bold tracking-normal text-slate-950">Seven security layers, one installable middleware.</h2>
        </div>
        <div class="space-y-5 text-base leading-8 text-slate-600">
          <p>Traditional API protection often depends on separate controls for authentication, rate limiting, signature matching, logging, and response masking. Iri-Shield studies whether these controls can be combined into a lightweight in-process middleware that produces explainable security decisions for Express.js APIs.</p>
          <p>The research evaluation reports strong controlled results: 214/220 attack scenarios detected, no observed false-positive blocks in evaluated legitimate traffic, complete identity-continuity classification in 500 scenarios, and complete required redaction across 500 structured JSON payloads.</p>
        </div>
      </div>
    </section>

    <section id="method" class="border-b border-line bg-white">
      <div class="mx-auto w-full max-w-6xl px-5 py-16">
        <div class="max-w-3xl">
          <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">01 / Method</p>
          <h2 class="mt-3 font-display text-4xl font-bold tracking-normal text-slate-950">Request processing pipeline</h2>
          <p class="mt-4 text-lg leading-8 text-slate-600">Every request passes through a sequential security pipeline before the application response is returned.</p>
        </div>
        <div class="mt-10 grid grid-cols-1 gap-3 md:grid-cols-7">
          ${pipelineStep('01', 'Hardening', 'Helmet/CORS headers and baseline HTTP protection.')}
          ${pipelineStep('02', 'Identity', 'Client continuity from IP, user agent, sessions, device hints, and fingerprints.')}
          ${pipelineStep('03', 'Rules', 'SQLi, XSS, traversal, command injection, scanners, secret probes, and more.')}
          ${pipelineStep('04', 'Behavior', 'Rate windows, endpoint flood signals, unusual methods, and failed auth.')}
          ${pipelineStep('05', 'Correlation', 'Stateful multi-step attack sequence recognition.')}
          ${pipelineStep('06', 'Risk', 'Explainable score, action decision, alerting, and automated blocking.')}
          ${pipelineStep('07', 'Redaction', 'Recursive sensitive-field masking before response/log exposure.')}
        </div>
      </div>
    </section>

    <section id="figures" class="border-b border-line">
      <div class="mx-auto w-full max-w-6xl px-5 py-16">
        <div class="flex flex-col justify-between gap-5 md:flex-row md:items-end">
          <div class="max-w-3xl">
            <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">02 / Figures and media</p>
            <h2 class="mt-3 font-display text-4xl font-bold tracking-normal text-slate-950">Visual slots for the final research site</h2>
            <p class="mt-4 text-lg leading-8 text-slate-600">These are intentional placeholders. Generate polished figures later and replace each block with an image, GIF, or video.</p>
          </div>
          <a class="rounded-md border border-line bg-white px-4 py-2 text-sm font-bold text-slate-900 shadow-sm hover:border-cobalt" href="/Generate_Media.md">Media brief</a>
        </div>
        <div class="mt-10 grid grid-cols-1 gap-5 md:grid-cols-2">

<article class="rounded-lg border border-dashed border-slate-300 bg-white p-5 shadow-sm">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="font-mono text-xs font-bold uppercase tracking-[0.14em] text-cobalt">Figure A</p>
        <h3 class="mt-2 text-xl font-extrabold text-slate-950">Overall system architecture</h3>
      </div>
      <span class="rounded bg-slate-100 px-2 py-1 text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500"> placeholder </span>
    </div>
    <div class="mt-5 grid min-h-44 place-items-center rounded-md border border-slate-200 bg-slate-50 p-1 text-center">
      <img src="/media/fig-overall-system-architecture.png" alt="Overall system architecture diagram" class="max-h-94 object-fit" />
    </div>
</article>

<article class="rounded-lg border border-dashed border-slate-300 bg-white p-5 shadow-sm">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="font-mono text-xs font-bold uppercase tracking-[0.14em] text-cobalt">Figure B</p>
        <h3 class="mt-2 text-xl font-extrabold text-slate-950">Seven-layer request flow</h3>
      </div>
      <span class="rounded bg-slate-100 px-2 py-1 text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">placeholder</span>
    </div>
    <div class="mt-5 grid min-h-44 place-items-center rounded-md border border-slate-200 bg-slate-50 p-1 text-center">
      <img src="/media/fig-seven-layer-flow.png" alt="Seven-layer request flow diagram" class="max-h-94 object-fit" />
    </div>
</article>
        
          ${mediaCard('Figure A', 'Overall system architecture', 'Create a clean architecture diagram showing Client/API Request -> Express app -> Iri-Shield middleware -> protected route -> response redaction -> dashboard/storage. Include Storage Abstraction branching to Memory, SQLite, and MongoDB. Use blue for trusted app flow, amber for suspicious signals, and red for mitigation.')}
          ${mediaCard('Figure B', 'Seven-layer request flow', 'Create a horizontal or vertical flowchart for the seven layers: hardening, identity, static rules, behavior, sequence correlation, risk/mitigation, redaction. Show risk score accumulating across stages.')}
          ${mediaCard('Figure C', 'Attack sequence correlation', 'Create a timeline showing failed authentication, endpoint enumeration, SQL injection, secret probe, and block decision from the same client. Use timestamps and small request cards.')}
          ${mediaCard('Figure D', 'Dashboard overview screenshot', 'Capture the real dashboard after replaying the dataset. Show stat cards, threat distribution, alerts, blocked IPs, and event detail breakdown. Prefer a crisp browser screenshot at 1440px wide.')}
          ${mediaCard('Video 1', 'End-to-end demo teaser', 'A 30-45 second video: start from home page, open dashboard, send safe request, send SQL injection request, show alert/event creation, show blocked IP and explainable score, then show redacted sensitive API response.')}
          ${mediaCard('Video 2', 'Research evaluation walkthrough', 'A narrated screen recording explaining the benchmark dataset, category-wise detection chart, false-positive result, identity-drift test, redaction test, and Vercel/MongoDB persistence setup.')}
        </div>
      </div>
    </section>

    <section id="results" class="border-b border-line bg-white">
      <div class="mx-auto w-full max-w-6xl px-5 py-16">
        <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">03 / Experimental results</p>
        <h2 class="mt-3 font-display text-4xl font-bold tracking-normal text-slate-950">Controlled evaluation summary</h2>
        <div class="mt-8 grid grid-cols-1 gap-4 md:grid-cols-4">
          ${resultCard('220', 'Attack scenarios', 'SQLi, XSS, traversal, command injection, SSTI, NoSQL, scanner bots, secret probes, brute force, and sensitive endpoints.')}
          ${resultCard('2,000+', 'Legitimate requests', 'Used to observe false-positive behavior under normal application traffic.')}
          ${resultCard('500', 'Identity scenarios', 'Controlled IP, user-agent, session, device, and fingerprint continuity transitions.')}
          ${resultCard('500', 'Redaction cases', 'Nested JSON payloads, tokens, emails, phones, secrets, and decoy non-sensitive fields.')}
        </div>
        <div class="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <div class="rounded-lg border border-line bg-slate-50 p-6">
            <p class="text-sm font-bold uppercase tracking-[0.18em] text-slate-500">Chart slot</p>
            <h3 class="mt-3 text-xl font-extrabold text-slate-950">Threat detection by category</h3>
            <p class="mt-3 text-sm leading-6 text-slate-600">Replace this with a bar chart using the research results CSV/SVG. It should show category-wise detection rates, highlight the 97.3% overall result, and annotate categories where detection was not complete.</p>
          </div>
          <div class="rounded-lg border border-line bg-slate-950 p-6 text-white">
            <p class="text-sm font-bold uppercase tracking-[0.18em] text-blue-200">Performance note</p>
            <h3 class="mt-3 text-xl font-extrabold">Security coverage adds measurable overhead.</h3>
            <p class="mt-3 text-sm leading-6 text-slate-300">The report notes lower throughput and higher latency compared with vanilla Express.js, especially under higher concurrency. Present this honestly as a security/performance trade-off, not as a hidden cost.</p>
          </div>
        </div>
      </div>
    </section>

    <section id="demo" class="border-b border-line">
      <div class="mx-auto w-full max-w-6xl px-5 py-16">
        <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">04 / Demo API</p>
        <h2 class="mt-3 font-display text-4xl font-bold tracking-normal text-slate-950">Routes protected by this middleware</h2>
        <div class="mt-8 overflow-hidden rounded-lg border border-line bg-white shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full min-w-[760px] border-collapse text-sm">
              <thead class="bg-slate-50 text-xs uppercase tracking-[0.12em] text-slate-500">
                <tr><th class="px-4 py-3 text-left">Method</th><th class="px-4 py-3 text-left">URL</th><th class="px-4 py-3 text-left">Purpose</th><th class="px-4 py-3 text-left">Access</th></tr>
              </thead>
              <tbody class="divide-y divide-line">
                ${endpoints.map(([method, url, purpose, access]) => renderEndpointRow(method, url, purpose, access)).join('')}
              </tbody>
            </table>
          </div>
        </div>
        <div class="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-2">
          <div class="rounded-lg border border-line bg-white p-6 shadow-sm">
            <h3 class="text-lg font-extrabold">Private admin APIs</h3>
            <p class="mt-2 text-sm leading-6 text-slate-600">Stats and metrics require a Bearer token from the demo login endpoint.</p>
            <pre class="mt-4 overflow-x-auto rounded-md bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-100"><code>curl -X POST ${escapeHtml(origin)}/login \\
  -H "content-type: application/json" \\
  -d "{\\"username\\":\\"admin\\",\\"password\\":\\"admin\\"}"

curl ${escapeHtml(origin)}/api/stats \\
  -H "authorization: Bearer YOUR_TOKEN"</code></pre>
          </div>
          <div class="rounded-lg border border-line bg-white p-6 shadow-sm">
            <h3 class="text-lg font-extrabold">Current deployment settings</h3>
            <dl class="mt-4 grid grid-cols-1 gap-3 text-sm">
              <div class="flex justify-between gap-4 border-b border-line pb-2"><dt class="text-slate-500">Storage</dt><dd class="font-mono font-semibold">${escapeHtml(storageMode)}</dd></div>
              <div class="flex justify-between gap-4 border-b border-line pb-2"><dt class="text-slate-500">Dashboard</dt><dd class="font-mono font-semibold">${escapeHtml(dashboardLabel)}</dd></div>
              <div class="flex justify-between gap-4 border-b border-line pb-2"><dt class="text-slate-500">Security mode</dt><dd class="font-mono font-semibold">medium</dd></div>
              <div class="flex justify-between gap-4"><dt class="text-slate-500">Testing mode</dt><dd class="font-mono font-semibold">enabled</dd></div>
            </dl>
          </div>
        </div>
      </div>
    </section>

    <section class="bg-white">
      <div class="mx-auto grid w-full max-w-6xl grid-cols-1 gap-8 px-5 py-16 md:grid-cols-[0.7fr_0.3fr]">
        <div>
          <p class="text-sm font-bold uppercase tracking-[0.18em] text-cobalt">05 / Deployment</p>
          <h2 class="mt-3 font-display text-4xl font-bold tracking-normal text-slate-950">Vercel-ready with persistent storage guidance</h2>
          <p class="mt-4 max-w-3xl text-lg leading-8 text-slate-600">Use MongoDB for persistent dashboard history on Vercel. SQLite in <code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-sm">/tmp</code> is only scratch storage and may reset when function instances recycle.</p>
        </div>
        <div class="rounded-lg border border-line bg-slate-50 p-5">
          <p class="text-sm font-bold text-slate-900">Useful links</p>
          <div class="mt-4 grid gap-2 text-sm font-semibold text-cobalt">
            <a href="/iri-shield">Dashboard</a>
            <a href="https://iri-shield.vercel.app/">Live docs/site</a>
            <a href="https://github.com/ansari-in/iri-shield#readme">Package README</a>
            <a href="https://www.npmjs.com/package/iri-shield">NPM package</a>
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="border-t border-line">
    <div class="mx-auto flex w-full max-w-6xl flex-col gap-2 px-5 py-8 text-sm text-slate-500 md:flex-row md:items-center md:justify-between">
      <p>Iri-Shield - multi-layer API security middleware for Express.js research and demos.</p>
      <p>Security telemetry endpoints are private and require authenticated access.</p>
    </div>
  </footer>
</body>
</html>`;
}

function metricTile(value, label, note) {
  return `<div class="rounded-lg border border-line bg-slate-50 p-4">
    <p class="font-display text-2xl font-extrabold text-slate-950">${escapeHtml(value)}</p>
    <p class="mt-1 text-xs font-bold uppercase tracking-[0.12em] text-slate-500">${escapeHtml(label)}</p>
    <p class="mt-2 text-xs leading-5 text-slate-500">${escapeHtml(note)}</p>
  </div>`;
}

function pipelineStep(index, title, text) {
  return `<article class="rounded-lg border border-line bg-white p-4 shadow-sm">
    <p class="font-mono text-xs font-bold text-cobalt">${escapeHtml(index)}</p>
    <h3 class="mt-3 text-sm font-extrabold text-slate-950">${escapeHtml(title)}</h3>
    <p class="mt-2 text-xs leading-5 text-slate-600">${escapeHtml(text)}</p>
  </article>`;
}

function mediaCard(label, title, description) {
  return `<article class="rounded-lg border border-dashed border-slate-300 bg-white p-5 shadow-sm">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="font-mono text-xs font-bold uppercase tracking-[0.14em] text-cobalt">${escapeHtml(label)}</p>
        <h3 class="mt-2 text-xl font-extrabold text-slate-950">${escapeHtml(title)}</h3>
      </div>
      <span class="rounded bg-slate-100 px-2 py-1 text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">placeholder</span>
    </div>
    <div class="mt-5 grid min-h-44 place-items-center rounded-md border border-slate-200 bg-slate-50 p-5 text-center">
      <p class="max-w-md text-sm leading-6 text-slate-600">${escapeHtml(description)}</p>
    </div>
  </article>`;
}

function resultCard(value, label, text) {
  return `<article class="rounded-lg border border-line bg-white p-5 shadow-sm">
    <p class="font-display text-4xl font-extrabold text-slate-950">${escapeHtml(value)}</p>
    <h3 class="mt-2 text-sm font-extrabold uppercase tracking-[0.12em] text-slate-500">${escapeHtml(label)}</h3>
    <p class="mt-3 text-sm leading-6 text-slate-600">${escapeHtml(text)}</p>
  </article>`;
}

function renderEndpointRow(method, url, purpose, accessType) {
  const accessClass = accessType === 'threat'
    ? 'bg-rose-50 text-rose border-rose-200'
    : accessType === 'auth'
      ? 'bg-amber-50 text-ember border-amber-200'
      : 'bg-emerald-50 text-pine border-emerald-200';
  const accessLabel = accessType === 'threat' ? 'test threat' : accessType === 'auth' ? 'authenticated' : 'public';
  return `<tr class="hover:bg-slate-50">
    <td class="px-4 py-3"><code class="rounded bg-slate-100 px-2 py-1 font-mono text-xs font-bold">${escapeHtml(method)}</code></td>
    <td class="px-4 py-3 font-mono text-xs font-semibold text-cobalt"><a href="${escapeHtml(url)}">${escapeHtml(url)}</a></td>
    <td class="px-4 py-3 text-slate-600">${escapeHtml(purpose)}</td>
    <td class="px-4 py-3"><span class="inline-flex rounded-full border px-2.5 py-1 text-xs font-bold ${accessClass}">${accessLabel}</span></td>
  </tr>`;
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

if (require.main === module) {
  app.listen(port, () => {
  console.log(`\n🛡️  iri-test running on http://localhost:${port}`);
  console.log(` Dashboard: http://localhost:${port}/iri-shield`);
  console.log(`   Credentials: ${dashboardUser} / ${dashboardPassword === 'admin' ? 'admin' : '[configured]'}`);
  console.log(`   Storage: ${storageMode}${storageMode === 'sqlite' ? ` (${sqliteFile})` : ''}`);
  console.log(`   Security mode: medium`);
  console.log(`   Testing mode: ON (IP overrides via headers enabled)\n`);
  });
}

module.exports = app;
