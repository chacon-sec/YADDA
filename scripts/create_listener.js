#!/usr/bin/env node
// create_listener.js — drive the Adaptix teamserver's operator REST API to
// create a BeaconHTTP listener, exactly as the GUI does:
//   POST /endpoint/login            {username, password, version} -> {access_token}
//   POST /endpoint/listener/create  {name, type, config}          (Bearer token)
//
// The `config` field is a JSON *string* of the listener transport config
// (extenders/beacon_listener_http TransportConfig json tags).
//
// Usage: node scripts/create_listener.js [--bind-port 8443] [--repro-bad-callback]

const https = require('https');

const TS_HOST = process.env.TS_HOST || '127.0.0.1';
const TS_PORT = parseInt(process.env.TS_PORT || '4321', 10);
const PASSWORD = process.env.TS_PASSWORD || 'pass';
const USERNAME = process.env.TS_USERNAME || 'alex';

const BIND_PORT = parseInt((process.argv.find(a => a === '--bind-port') ? process.argv[process.argv.indexOf('--bind-port') + 1] : null) || '8443', 10);
const REPRO_BAD = process.argv.includes('--repro-bad-callback');

// must match the Node agent's src/config.js defaults
const ENCRYPT_KEY = '00112233445566778899aabbccddeeff';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const URI = '/content.html';
const HB_HEADER = 'X-Beacon-Id';

const PAGE_404 = '<!DOCTYPE html>\n<html>\n<head>\n<title>ERROR 404 - Nothing Found</title>\n</head>\n<body>\n<h1 class="cover-heading">ERROR 404 - PAGE NOT FOUND</h1>\n</div>\n</div>\n</div>\n</body>\n</html>';
const PAGE_PAYLOAD = '{"status": "ok", "data": "<<<PAYLOAD_DATA>>>", "metrics": "sync"}';

function req(method, path, body, token) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = https.request({
      host: TS_HOST, port: TS_PORT, path, method,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      rejectUnauthorized: false,
      timeout: 10000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.on('timeout', () => r.destroy(new Error('timeout')));
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  // ---- 1) login ----
  const login = await req('POST', '/endpoint/login', { username: USERNAME, password: PASSWORD, version: 'v1.2' });
  if (login.status !== 200) throw new Error(`login HTTP ${login.status}: ${login.body}`);
  const { access_token, refresh_token } = JSON.parse(login.body);
  console.log('[+] login OK (access token %d chars)', (access_token || '').length);

  // ---- 2) build transport config (matches TransportConfig json tags) ----
  const transport = {
    host_bind: '0.0.0.0',
    port_bind: BIND_PORT,
    // REPRO: the GUI ships this list pre-filled with the placeholder "address:port",
    // which the plugin parses with net.SplitHostPort -> Atoi("port") fails ->
    // "Invalid port: address:port". That is the error the GUI shows.
    callback_addresses: REPRO_BAD ? ['address:port'] : [`127.0.0.1:${BIND_PORT}`],
    encrypt_key: ENCRYPT_KEY,
    ssl: false,
    http_method: 'POST',
    uri: [URI],
    hb_header: HB_HEADER,
    user_agent: [USER_AGENT],
    host_header: [],
    request_headers: '',
    response_headers: {},
    'x-forwarded-for': false,
    'page-error': PAGE_404,
    'page-payload': PAGE_PAYLOAD,
  };

  const payload = {
    name: 'BeaconHTTP-8443',
    type: 'BeaconHTTP',
    config: JSON.stringify(transport), // config is a JSON *string*
  };

  if (REPRO_BAD) console.log('[*] repro mode: callback_addresses = ["address:port"] (GUI placeholder)');

  // ---- 3) create listener ----
  const res = await req('POST', '/endpoint/listener/create', payload, access_token);
  console.log(`[*] listener/create -> HTTP ${res.status}`);
  let out = res.body;
  try { out = JSON.stringify(JSON.parse(res.body), null, 2); } catch (_) {}
  console.log(out);

  if (/Invalid port/i.test(out)) {
    console.log('\n[!] DIAGNOSIS CONFIRMED: the "Invalid port" error is the CALLBACK ADDRESSES placeholder ("address:port"), not your bind port.');
    console.log('    In the GUI: clear the placeholder in "Callback addresses" and put 127.0.0.1:' + BIND_PORT);
  }

  // ---- 4) verify ----
  const list = await req('GET', '/endpoint/listener/list', null, access_token);
  console.log(`\n[*] listener/list -> HTTP ${list.status}`);
  try {
    const j = JSON.parse(list.body);
    const arr = Array.isArray(j) ? j : (j.data || j.listeners || []);
    console.log(arr.length ? JSON.stringify(arr, null, 2) : list.body);
  } catch (_) { console.log(list.body); }
}

main().catch((e) => { console.error('[-]', e.message); process.exit(1); });
