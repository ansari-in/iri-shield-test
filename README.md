# iri-test

Demo Express API for testing the `iri-shield` package.

## Run

```bash
npm install
npm start
```

Open:

- API root: `http://localhost:3000/`
- Dashboard: `http://localhost:3000/iri-shield`
- Dashboard login: `admin` / `admin`

## Deploy to Vercel

This demo is ready to deploy on Vercel.

This demo depends on the sibling package with:

```json
"iri-shield": "file:../iri-shield"
```

Deploy from a repository that contains both `iri-test` and `iri-shield` so Vercel can resolve that local package. If you deploy only the `iri-test` folder by itself, publish the patched `iri-shield` package first and replace the dependency with that npm version.

Vercel Functions run on a read-only filesystem, and `/tmp` is temporary per function instance. Because of that, the demo uses:

- `sqlite` locally, stored at `./data/iri-shield.sqlite`
- `mongodb` automatically on Vercel when `IRI_MONGO_URL` is configured
- `sqlite` on Vercel only as a short-lived fallback, stored at `/tmp/iri-shield.sqlite`

Use MongoDB or another external datastore for persistent dashboard history on Vercel. SQLite in `/tmp` can disappear when Vercel recycles or moves the function instance, so old dashboard events, alerts, clients, and blocks should not be expected to survive there.

The important part is in `server.js`:

```js
const isVercel = Boolean(process.env.VERCEL);
const mongoUrl = process.env.IRI_MONGO_URL;
const storageMode = process.env.IRI_STORAGE_MODE || (isVercel && mongoUrl ? 'mongodb' : 'sqlite');
const sqliteFile = process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite');

const shield = createShield({
  storage: {
    mode: storageMode,
    sqliteFile,
    mongoUrl
  },
  dashboard: {
    username: process.env.SHIELD_ADMIN_USER || 'admin',
    password: process.env.SHIELD_ADMIN_PASSWORD || 'admin',
    sessionSecret: process.env.IRI_SHIELD_DASHBOARD_SECRET || process.env.SESSION_SECRET || process.env.JWT_SECRET
  }
});
```

### Vercel Environment Variables

For the easiest demo deployment, no storage variables are required.

Recommended production/demo variables:

```bash
JWT_SECRET=replace-with-a-long-random-secret
API_KEY=replace-with-your-demo-api-key
SHIELD_ADMIN_USER=admin
SHIELD_ADMIN_PASSWORD=replace-with-a-strong-password
IRI_SHIELD_DASHBOARD_SECRET=replace-with-a-long-random-session-secret
```

Optional storage variables:

```bash
# Local/default fallback. Uses /tmp on Vercel and ./data locally.
IRI_STORAGE_MODE=sqlite

# Memory mode. Data resets when the function instance is recycled.
IRI_STORAGE_MODE=memory

# Explicit temporary SQLite path for Vercel.
IRI_STORAGE_MODE=sqlite
IRI_SQLITE_FILE=/tmp/iri-shield.sqlite

# Persistent production storage, if you configure MongoDB for iri-shield.
IRI_STORAGE_MODE=mongodb
IRI_MONGO_URL=mongodb+srv://...
```

For Vercel dashboard persistence, set `IRI_STORAGE_MODE=mongodb` and `IRI_MONGO_URL`. If `IRI_MONGO_URL` is present and `IRI_STORAGE_MODE` is omitted, this demo now selects MongoDB automatically on Vercel.

The dashboard session cookie is stable across Vercel cold starts when `IRI_SHIELD_DASHBOARD_SECRET`/`SESSION_SECRET`/`JWT_SECRET` is configured. Without a stable session secret in older `iri-shield` versions, a random per-instance dashboard token could produce intermittent `401 Unauthorized` API responses while clicking tabs.

## Modes: Testing vs Real-World Usage

### 1. Testing Mode (Default in this Demo)
Allows benchmark replay and header-based IP/identity spoofing (`x-iri-test-ip`, `x-iri-test-user-agent`, etc.):
```javascript
// In server.js
testing: {
  enabled: true,
  allowClientOverrides: true
}
```

### 2. Switching to Real-World Mode (Live Protection)
To protect against actual incoming client traffic and enforce real network IP addresses:
1. In `server.js`, set `testing.enabled: false` (or remove the `testing` config block):
```javascript
// In server.js
testing: {
  enabled: false,
  allowClientOverrides: false
}
```
2. Restart the server:
```bash
npm start
```
When testing mode is disabled, any spoofed test headers are ignored, and `iri-shield` evaluates real client socket IPs and browser headers.

## Useful Test Calls

```bash
# Public endpoint test
curl http://localhost:3000/api/public

# SQL Injection threat detection test (should be flagged / blocked based on score)
curl "http://localhost:3000/api/search?q=' or 1=1"

# Protected API Key endpoint
curl -H "x-api-key: iri-demo-key" http://localhost:3000/api/private

# Sensitive endpoint probe detection
curl http://localhost:3000/admin/reports

# Run research replay dataset
curl -X POST http://localhost:3000/research/replay
```
