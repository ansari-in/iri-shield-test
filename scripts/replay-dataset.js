'use strict';

const { readFile } = require('fs/promises');
const { join } = require('path');

const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

async function main() {
  const dataset = JSON.parse(await readFile(join(__dirname, '..', 'client_requests.json'), 'utf8'));
  const results = [];

  for (const row of dataset) {
    const headers = {
      ...(row.headers || {}),
      'user-agent': row.userAgent || 'iri-dataset-client',
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
    const response = await fetch(`${baseUrl}${row.url}`, {
      method: row.method || 'GET',
      headers,
      body: row.body ? JSON.stringify(row.body) : undefined
    });

    results.push({
      id: row.id,
      scenario: row.scenario,
      expected: row.expected,
      status: response.status,
      durationMs: Date.now() - startedAt
    });
  }

  console.table(results);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
