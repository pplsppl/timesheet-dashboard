/**
 * Netlify Function: proxies Rippling API calls server-side
 * so the API key is never exposed to the browser.
 *
 * Environment variable required (set in Netlify UI → Site → Environment variables):
 *   RIPPLING_API_KEY
 *
 * Endpoints (via ?endpoint=):
 *   (none)        → time-tracking/time-entries  (accepts ?startDate=&endDate=)
 *   workers       → /workers
 *   departments   → /departments
 */

const RIPPLING_BASE = 'https://app.rippling.com/api/platform/api';

exports.handler = async function (event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  const apiKey = process.env.RIPPLING_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'RIPPLING_API_KEY environment variable is not set.' }),
    };
  }

  const q = event.queryStringParameters || {};
  const { endpoint, startDate, endDate } = q;

  try {
    let url;

    if (endpoint === 'workers') {
      url = `${RIPPLING_BASE}/workers`;
    } else if (endpoint === 'departments') {
      url = `${RIPPLING_BASE}/departments`;
    } else {
      const params = new URLSearchParams();
      if (startDate) params.set('startDate', startDate);
      if (endDate)   params.set('endDate',   endDate);
      url = `${RIPPLING_BASE}/time-tracking/time-entries?${params}`;
    }

    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });

    if (!r.ok) {
      const body = await r.text().catch(() => '');
      throw new Error(`Rippling ${r.status}: ${body.slice(0, 200)}`);
    }

    const data = await r.json();
    return { statusCode: 200, headers, body: JSON.stringify(data) };

  } catch (err) {
    console.error('[timesheets]', err.message);
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: err.message }),
    };
  }
};
