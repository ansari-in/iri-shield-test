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

Vercel Functions run on a read-only filesystem. Because of that, the demo uses:

- `sqlite` locally, stored at `./data/iri-shield.sqlite`
- `memory` automatically on Vercel, so the app boots without trying to create `./data`

The important part is in `server.js`:

```js
const isVercel = Boolean(process.env.VERCEL);
const storageMode = process.env.IRI_STORAGE_MODE || (isVercel ? 'memory' : 'sqlite');
const sqliteFile = process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite');

const shield = createShield({
  storage: {
    mode: storageMode,
    sqliteFile
  }
});
```

### Vercel Environment Variables

For the easiest demo deployment, no storage variables are required.

Recommended production/demo variables:

```bash
JWT_SECRET=replace-with-a-long-random-secret
API_KEY=replace-with-your-demo-api-key
```

Optional storage variables:

```bash
# Default on Vercel. Data resets when the function instance is recycled.
IRI_STORAGE_MODE=memory

# Temporary SQLite only. Works because /tmp is writable, but data is not permanent.
IRI_STORAGE_MODE=sqlite
IRI_SQLITE_FILE=/tmp/iri-shield.sqlite

# Persistent production storage, if you configure MongoDB for iri-shield.
IRI_STORAGE_MODE=mongodb
IRI_MONGO_URL=mongodb+srv://...
```

Use `memory` for quick Vercel checks. Use MongoDB or another external datastore for production persistence; `/tmp` SQLite is only scratch storage.

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
