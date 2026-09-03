# iri-test

Demo Express API for testing the local `iri-shield` package.

## Run

```bash
npm install
npm start
```

Open:

- API root: `http://localhost:3000/`
- Dashboard: `http://localhost:3000/iri-shield`
- Dashboard login: `admin` / `admin`

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
