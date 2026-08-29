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

## Useful Test Calls

```bash
curl http://localhost:3000/api/public
curl "http://localhost:3000/api/search?q=' or 1=1"
curl -H "x-api-key: iri-demo-key" http://localhost:3000/api/private
curl http://localhost:3000/admin/reports
```
