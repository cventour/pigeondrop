// Activity log tests. The server runs as a child process against a temp
// folder, the way it runs for real; the ICAP scanner is a tiny fake on node:net.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import vm from 'node:vm';
import { settingsDiff } from '../settings-diff.js';

const SERVER = path.join(import.meta.dirname, '..', 'server.js');
const UA = 'pigeon-test/1.0';
const procs = [], dirs = [];

const freePort = () => new Promise((res) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

async function start(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-'));
  dirs.push(dir);
  const port = await freePort();
  const proc = spawn(process.execPath, [SERVER], {
    env: { ...process.env, REPO_ROOT: path.join(dir, 'files'), SETTINGS_FILE: path.join(dir, 'state', 'settings.json'),
           PORT: String(port), HOST: '127.0.0.1', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(proc);
  let err = '';
  proc.stderr.on('data', (d) => { err += d; });
  await new Promise((res, rej) => {
    proc.stdout.on('data', (d) => { if (String(d).includes('serving')) res(); });
    proc.on('exit', () => rej(new Error('server exited: ' + err)));
  });
  fs.mkdirSync(path.join(dir, 'state'), { recursive: true });
  const base = `http://127.0.0.1:${port}`;
  const logFile = path.join(dir, 'state', 'activity.log');
  const call = (p, o = {}) => fetch(base + p, { ...o, headers: { 'user-agent': UA, ...o.headers } });
  const jpost = (p, body) => call(p, { method: 'POST', body: JSON.stringify(body) });
  const lines = () => fs.existsSync(logFile)
    ? fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  // Downloads are logged when the response closes, which can trail the client.
  const waitFor = async (pred) => {
    for (let i = 0; i < 100; i++) { const l = lines(); if (pred(l)) return l; await new Promise((r) => setTimeout(r, 50)); }
    return lines();
  };
  const put = (p, body, q = '') => call('/api/upload' + p + q, { method: 'PUT', body });
  const activity = async (qs = '') => (await call('/api/activity' + qs)).json();
  return { dir, base, port, logFile, call, jpost, lines, waitFor, put, activity, err: () => err, proc };
}

// A fake ICAP server. `reply` is the raw response head it sends after the request.
function fakeIcap(reply) {
  const server = net.createServer((sock) => {
    sock.on('error', () => {});
    let buf = '';
    sock.on('data', (c) => {
      buf += c.toString('latin1');
      if (buf.includes('REQMOD')) { sock.write(reply); }
    });
  });
  return new Promise((res) => server.listen(0, '127.0.0.1', () => res({ server, port: server.address().port })));
}
const BLOCK = 'ICAP/1.0 200 OK\r\nX-Response-Info: Blocked\r\nX-Response-Desc: Malware found\r\n' +
  'X-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test;\r\nEncapsulated: res-hdr=0, res-body=10\r\n\r\n';
const FAULT = 'ICAP/1.0 500 Server Error\r\n\r\n';

async function scanner(s, port, extra = {}) {
  const r = await s.call('/api/settings', { method: 'PUT',
    body: JSON.stringify({ icap: { enabled: true, host: '127.0.0.1', port, ...extra } }) });
  assert.equal(r.status, 200);
}

after(() => { for (const p of procs) p.kill(); for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

test('upload, download, mkdir, rename, delete each log exactly one line', async () => {
  const s = await start();
  assert.equal((await s.put('/a.txt', 'hello')).status, 200);
  await (await s.call('/api/download/a.txt')).arrayBuffer();
  await (await s.call('/api/download/a.txt')).arrayBuffer();
  assert.equal((await s.jpost('/api/mkdir', { dir: '/', name: 'docs' })).status, 200);
  assert.equal((await s.jpost('/api/rename', { target: '/a.txt', name: 'b.txt' })).status, 200);
  assert.equal((await s.jpost('/api/delete', { target: '/b.txt' })).status, 200);

  const l = await s.waitFor((x) => x.length >= 6);
  assert.deepEqual(l.map((e) => e.action), ['upload', 'download', 'download', 'mkdir', 'rename', 'delete']);
  for (const e of l) {
    assert.match(e.ts, /^\d{4}-\d\d-\d\dT.*Z$/);
    assert.equal(e.ua, UA);
    assert.match(e.ip, /^127\.0\.0\.1$|^::1$/);
  }
  assert.deepEqual([l[0].path, l[0].size, l[0].result], ['/a.txt', 5, 'off']);
  assert.deepEqual([l[1].path, l[1].size, l[1].result], ['/a.txt', 5, 'completed']);
  assert.equal(l[3].path, '/docs');
  assert.deepEqual([l[4].path, l[4].to], ['/a.txt', '/b.txt']);
  assert.equal(l[5].path, '/b.txt');
  assert.ok(!fs.readFileSync(s.logFile, 'utf8').includes(s.dir), 'no host paths in the log');
});

test('download_zip logs the paths and total size', async () => {
  const s = await start();
  await s.put('/d/x.txt', 'aaaa');
  await s.put('/d/y.txt', 'bb');
  s.proc.stdout.resume();
  const form = new URLSearchParams([['path', '/d'], ['dir', '/']]);
  const r = await s.call('/api/zip', { method: 'POST', body: form });
  assert.equal(r.status, 200);
  await r.arrayBuffer();
  const z = (await s.waitFor((x) => x.some((e) => e.action === 'download_zip'))).filter((e) => e.action === 'download_zip');
  assert.equal(z.length, 1);
  assert.deepEqual(z[0].paths, ['/d']);
  assert.equal(z[0].size, 6);
  assert.equal(z[0].result, 'completed');
});

test('upload_blocked is logged with the scanner reason, and nothing lands', async () => {
  const s = await start();
  const { server, port } = await fakeIcap(BLOCK);
  try {
    await scanner(s, port);
    const r = await s.put('/bad.exe', 'X5O');
    assert.equal(r.status, 422);
    const l = s.lines().filter((e) => e.action.startsWith('upload'));
    assert.equal(l.length, 1);
    assert.equal(l[0].action, 'upload_blocked');
    assert.equal(l[0].reason, 'Malware found');
    assert.equal(l[0].threat, 'EICAR-Test');
    assert.equal(l[0].path, '/bad.exe');
    assert.equal(l[0].size, 3);
  } finally { server.close(); }
});

test('upload_scan_error is logged when the scanner faults, and not as an upload', async () => {
  const s = await start();
  const { server, port } = await fakeIcap(FAULT);
  try {
    await scanner(s, port);
    assert.equal((await s.put('/c.bin', 'abc')).status, 502);
    let l = s.lines().filter((e) => e.action.startsWith('upload'));
    assert.deepEqual(l.map((e) => [e.action, e.result]), [['upload_scan_error', 'rejected']]);
    assert.match(l[0].reason, /500/);

    await scanner(s, port, { failClosed: false });
    assert.equal((await s.put('/d.bin', 'abc')).status, 200);
    l = s.lines().filter((e) => e.action.startsWith('upload') && e.path === '/d.bin');
    assert.deepEqual(l.map((e) => [e.action, e.result]), [['upload_scan_error', 'accepted']]);
  } finally { server.close(); }
});

test('settings changes log each field as before -> after', async () => {
  const s = await start();
  await s.call('/api/settings', { method: 'PUT', body: JSON.stringify({ icap: { host: 'icap.test', port: 1345 } }) });
  const l = s.lines().filter((e) => e.action === 'settings');
  assert.equal(l.length, 1);
  assert.deepEqual(l[0].changes, [
    { field: 'icap.host', from: '', to: 'icap.test' },
    { field: 'icap.port', from: 1344, to: 1345 },
  ]);
  // Saving the same values again changes nothing, so logs nothing.
  await s.call('/api/settings', { method: 'PUT', body: JSON.stringify({ icap: { host: 'icap.test', port: 1345 } }) });
  assert.equal(s.lines().filter((e) => e.action === 'settings').length, 1);
});

test('secret fields are logged as changed, never with a value', () => {
  const d = settingsDiff(
    { icap: { host: 'a', password: 'old-pw', apiToken: 't1', secret: 's', accessKey: 'k' } },
    { icap: { host: 'b', password: 'new-pw', apiToken: 't2', secret: 's2', accessKey: 'k2' } });
  assert.equal(d.length, 5, 'every changed field appears');
  assert.deepEqual(d[0], { field: 'icap.host', from: 'a', to: 'b' });
  for (const e of d.slice(1)) assert.deepEqual(Object.keys(e).sort(), ['changed', 'field']);
  assert.ok(!/old-pw|new-pw|t1|t2|"k"|k2/.test(JSON.stringify(d.slice(1))));
  // A secret added or removed is a change too.
  assert.deepEqual(settingsDiff({ icap: {} }, { icap: { password: 'x' } }), [{ field: 'icap.password', changed: true }]);
});

test('log rotates at the threshold and keeps one previous file', async () => {
  const s = await start({ ACTIVITY_LOG_MAX_BYTES: '600' });
  for (let i = 0; i < 12; i++) await s.jpost('/api/mkdir', { dir: '/', name: 'dir' + i });
  const dirOf = path.dirname(s.logFile);
  const names = fs.readdirSync(dirOf).filter((n) => n.startsWith('activity.log')).sort();
  assert.deepEqual(names, ['activity.log', 'activity.log.1']);
  assert.ok(fs.statSync(s.logFile).size < 1200);
  // Another round replaces .1 rather than adding .2.
  for (let i = 12; i < 40; i++) await s.jpost('/api/mkdir', { dir: '/', name: 'dir' + i });
  assert.deepEqual(fs.readdirSync(dirOf).filter((n) => n.startsWith('activity.log')).sort(), ['activity.log', 'activity.log.1']);
  // The API reads across both files, newest first.
  const j = await s.activity('?limit=500');
  assert.equal(j.items[0].path, '/dir39');
  assert.ok(j.items.length > 5);
});

test('ACTIVITY_LOG=off writes nothing and /api/activity is 404', async () => {
  const s = await start({ ACTIVITY_LOG: 'off' });
  await s.put('/a.txt', 'x');
  await s.jpost('/api/mkdir', { dir: '/', name: 'z' });
  assert.equal(fs.existsSync(s.logFile), false);
  assert.equal((await s.call('/api/activity')).status, 404);
  assert.equal((await (await s.call('/api/config')).json()).activityLog, false);
});

test('config reports the log as on by default', async () => {
  const s = await start();
  assert.equal((await (await s.call('/api/config')).json()).activityLog, true);
});

test('a log that cannot be written never breaks requests, and warns once', async () => {
  const s = await start();
  fs.mkdirSync(s.logFile);                    // a directory where the file should be
  for (const n of ['a', 'b', 'c']) assert.equal((await s.jpost('/api/mkdir', { dir: '/', name: n })).status, 200);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(s.err().split('activity log: cannot write').length - 1, 1);
});

test('/api/activity pages newest first with a cursor, and filters by type', async () => {
  const s = await start();
  for (let i = 0; i < 7; i++) await s.jpost('/api/mkdir', { dir: '/', name: 'm' + i });
  await s.put('/u1.txt', 'x');
  await s.put('/u2.txt', 'x');
  await s.call('/api/download/u1.txt').then((r) => r.arrayBuffer());
  await s.jpost('/api/delete', { target: '/m0' });

  const all = await s.activity('?limit=500');
  assert.equal(all.items.length, 11);
  assert.equal(all.next, null);
  assert.equal(all.items[0].action, 'delete');

  // Walk the pages and get every event exactly once, in the same order.
  const seen = [];
  let before = '', pages = 0;
  do {
    const j = await s.activity(`?limit=4${before ? '&before=' + encodeURIComponent(before) : ''}`);
    assert.ok(j.items.length <= 4);
    seen.push(...j.items); before = j.next; pages++;
  } while (before);
  assert.equal(pages, 3);
  assert.deepEqual(seen, all.items);

  const count = async (t) => (await s.activity('?type=' + t)).items.map((e) => e.action);
  assert.deepEqual(await count('uploads'), ['upload', 'upload']);
  assert.deepEqual(await count('downloads'), ['download']);
  assert.equal((await count('changes')).length, 8);
  assert.deepEqual(await count('blocked'), []);
  assert.deepEqual(await count('settings'), []);
  assert.equal((await s.activity('?type=all&limit=2')).items.length, 2);
  assert.equal((await s.call('/api/activity?type=nope')).status, 400);
  assert.equal((await s.activity('?limit=99999')).items.length, 11, 'limit is clamped, not rejected');
  assert.deepEqual(await s.activity('?before=garbage'), { items: [], next: null });
});

test('a cursor survives a rotation between pages', async () => {
  const s = await start({ ACTIVITY_LOG_MAX_BYTES: '1500' });
  for (let i = 0; i < 8; i++) await s.jpost('/api/mkdir', { dir: '/', name: 'r' + i });
  const first = await s.activity('?limit=3');
  assert.ok(first.next);
  for (let i = 8; i < 20; i++) await s.jpost('/api/mkdir', { dir: '/', name: 'r' + i });   // rotates
  assert.ok(fs.existsSync(s.logFile + '.1'));
  const second = await s.activity(`?limit=3&before=${encodeURIComponent(first.next)}`);
  assert.deepEqual(second.items.map((e) => e.path), ['/r4', '/r3', '/r2']);
});

// --- CSV: the same file the page loads, run without a browser -------------
const csv = {};
vm.runInNewContext(fs.readFileSync(path.join(import.meta.dirname, '..', 'public', 'csv.js'), 'utf8')
  + ';this.csvCell = csvCell; this.csvRow = csvRow;', csv);

test('csv quotes commas, quotes and line breaks', () => {
  assert.equal(csv.csvCell('plain'), 'plain');
  assert.equal(csv.csvCell('a,b'), '"a,b"');
  assert.equal(csv.csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csv.csvCell('two\nlines'), '"two\nlines"');
  assert.equal(csv.csvCell(null), '');
  assert.equal(csv.csvCell(5), '5');
  assert.equal(csv.csvRow(['a', 'b,c', '']), 'a,"b,c",');
});

test('csv neutralises formula injection', () => {
  for (const c of ['=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx']) {
    assert.ok(csv.csvCell(c).replace(/^"/, '').startsWith("'"), JSON.stringify(c));
  }
  assert.equal(csv.csvCell('=HYPERLINK("x","y")'), '"\'=HYPERLINK(""x"",""y"")"');
  assert.equal(csv.csvCell('a=b'), 'a=b');
});

// --- downloads that do not finish ------------------------------------------
// Read a little of the response, then hang up.
const abortAfterFirstChunk = (s, method, url, body) => new Promise((res, rej) => {
  const r = http.request({ host: '127.0.0.1', port: s.port, path: url, method,
    headers: { 'user-agent': UA, ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}) } }, (resp) => {
    resp.once('data', () => { resp.destroy(); res(); });
  });
  r.on('error', rej); r.end(body);
});

test('an aborted download is logged once, as aborted, with the bytes sent', async () => {
  const s = await start();
  fs.mkdirSync(path.join(s.dir, 'files'), { recursive: true });
  fs.writeFileSync(path.join(s.dir, 'files', 'big.bin'), Buffer.alloc(128 * 1024 * 1024));
  await abortAfterFirstChunk(s, 'GET', '/api/download/big.bin');
  const l = (await s.waitFor((x) => x.some((e) => e.action === 'download'))).filter((e) => e.action === 'download');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(s.lines().filter((e) => e.action === 'download').length, 1);
  assert.equal(l[0].result, 'aborted');
  assert.equal(l[0].size, 128 * 1024 * 1024);
  assert.ok(l[0].sent > 0 && l[0].sent < l[0].size, `sent ${l[0].sent}`);
});

test('an aborted zip is logged once, as aborted, with the bytes sent', async () => {
  const s = await start();
  fs.mkdirSync(path.join(s.dir, 'files', 'd'), { recursive: true });
  fs.writeFileSync(path.join(s.dir, 'files', 'd', 'r.bin'), crypto.randomBytes(48 * 1024 * 1024));
  await abortAfterFirstChunk(s, 'POST', '/api/zip', 'path=%2Fd&dir=%2F');
  const l = (await s.waitFor((x) => x.some((e) => e.action === 'download_zip'))).filter((e) => e.action === 'download_zip');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(s.lines().filter((e) => e.action === 'download_zip').length, 1);
  assert.equal(l[0].result, 'aborted');
  assert.deepEqual(l[0].paths, ['/d']);
  assert.ok(l[0].sent > 0 && l[0].sent < 48 * 1024 * 1024, `sent ${l[0].sent}`);
});

// --- reading big logs ------------------------------------------------------
const fakeLine = (i, ua = 'x') => JSON.stringify({ ts: new Date(1e12 + i * 1000).toISOString(), ip: '10.0.0.1',
  ua, action: i % 5 === 0 ? 'delete' : 'mkdir', path: '/n' + i }) + '\n';

for (const [label, env, count, ua] of [
  ['a log bigger than one 64 KB chunk', {}, 1200, 'u'.repeat(50)],
  ['lines that cross small chunk boundaries', { ACTIVITY_READ_CHUNK: '97' }, 150, 'v'.repeat(40)],
]) {
  test('pages through ' + label + ' without losing or repeating a line', async () => {
    const s = await start(env);
    let text = '';
    for (let i = 0; i < count; i++) text += fakeLine(i, ua);
    fs.writeFileSync(s.logFile, text);
    if (!env.ACTIVITY_READ_CHUNK) assert.ok(text.length > 65536 * 2);
    const seen = [];
    let before = '';
    do {
      const j = await s.activity(`?limit=${env.ACTIVITY_READ_CHUNK ? 7 : 500}${before ? '&before=' + encodeURIComponent(before) : ''}`);
      seen.push(...j.items.map((e) => e.path)); before = j.next;
    } while (before);
    assert.deepEqual(seen, Array.from({ length: count }, (_, i) => '/n' + (count - 1 - i)));
    const del = await s.activity('?type=changes&limit=500');
    assert.equal(del.items.length, Math.min(count, 500));
  });
}

// --- refused requests ------------------------------------------------------
test('refused state-changing requests are logged as rejected, once, without double-logging', async () => {
  const s = await start();
  await s.put('/a.txt', 'x');
  assert.equal((await s.put('/a.txt', 'y')).status, 409);
  assert.equal((await s.jpost('/api/delete', { target: '/' })).status, 400);
  assert.equal((await s.jpost('/api/rename', { target: '/a.txt', name: 'a/b' })).status, 400);
  await s.jpost('/api/mkdir', { dir: '/', name: 'taken' });
  await s.put('/taken2', 'x');
  assert.equal((await s.jpost('/api/rename', { target: '/taken2', name: 'taken' })).status, 409);
  assert.equal((await s.call('/api/settings', { method: 'PUT', body: JSON.stringify({ icap: { port: 0 } }) })).status, 400);
  assert.equal((await s.call('/api/download/nope.txt')).status, 404);
  assert.equal((await s.call('/api/exists?path=/')).status, 400);

  const rej = s.lines().filter((e) => e.result === 'rejected');
  assert.deepEqual(rej.map((e) => [e.action, e.reason]), [
    ['upload', 'exists'], ['delete', 'bad path'], ['rename', 'bad name'],
    ['rename', 'name taken'], ['settings', 'Port must be a number from 1 to 65535'],
  ]);
  assert.equal(rej[0].path, '/a.txt');
  assert.equal(s.lines().filter((e) => e.action === 'download').length, 0, 'rejected GETs are not logged');

  // The scanner's own refusals are logged by their own actions, not as rejected too.
  const { server, port } = await fakeIcap(BLOCK);
  try {
    await scanner(s, port);
    await s.put('/bad.exe', 'X');
    const u = s.lines().filter((e) => e.path === '/bad.exe');
    assert.deepEqual(u.map((e) => e.action), ['upload_blocked']);
  } finally { server.close(); }
});

test('an upload over an existing file is marked replaced', async () => {
  const s = await start();
  await s.put('/a.txt', 'one');
  await s.put('/a.txt', 'two', '?mode=replace');
  await s.put('/a.txt', 'three', '?mode=keep');
  const u = s.lines().filter((e) => e.action === 'upload' && e.result !== 'rejected');
  assert.deepEqual(u.map((e) => [e.path, e.replaced]), [['/a.txt', undefined], ['/a.txt', true], ['/a (2).txt', undefined]]);
});

// --- who the log says it was -----------------------------------------------
test('TRUST_PROXY off ignores X-Forwarded-For entirely', async () => {
  const s = await start();
  await s.jpost('/api/mkdir', { dir: '/', name: 'a' }).then(() => {});
  await s.call('/api/mkdir', { method: 'POST', headers: { 'x-forwarded-for': '203.0.113.9' },
    body: JSON.stringify({ dir: '/', name: 'b' }) });
  for (const e of s.lines()) { assert.match(e.ip, /^(127\.0\.0\.1|::1)$/); assert.equal('peer' in e, false); }
});

test('TRUST_PROXY on logs the right-most X-Forwarded-For address and the peer', async () => {
  const s = await start({ TRUST_PROXY: 'on' });
  const mk = (name, xff) => s.call('/api/mkdir', { method: 'POST', headers: xff ? { 'x-forwarded-for': xff } : {},
    body: JSON.stringify({ dir: '/', name }) });
  await mk('a', '1.2.3.4, 10.0.0.9');          // the left entry is the client's claim
  await mk('b', '  2001:db8::1 ');
  await mk('c');
  await mk('d', '10.0.0.9, not-an-ip');
  await mk('e', '<script>');
  const l = s.lines();
  assert.equal(l[0].ip, '10.0.0.9');
  assert.match(l[0].peer, /^(127\.0\.0\.1|::1)$/);
  assert.equal('fwd_invalid' in l[0], false);
  assert.equal(l[1].ip, '2001:db8::1');
  for (const e of l.slice(2)) {
    assert.equal(e.ip, e.peer, 'missing or invalid: falls back to the socket address');
    assert.equal(e.fwd_invalid, true);
  }
});

test('mkdir on an existing name is a 409, logged as a rejected mkdir', async () => {
  const s = await start();
  assert.equal((await s.jpost('/api/mkdir', { dir: '/', name: 'dup' })).status, 200);
  const r = await s.jpost('/api/mkdir', { dir: '/', name: 'dup' });
  assert.equal(r.status, 409);
  assert.deepEqual(await r.json(), { error: 'that name is taken' });
  const l = s.lines();
  assert.deepEqual(l.map((e) => [e.action, e.result, e.reason]), [['mkdir', undefined, undefined], ['mkdir', 'rejected', 'name taken']]);
  assert.equal(l[1].path, '/dup');
});

// --- the activity dialog's paging, without a browser ------------------------
const pagerCtx = { AbortController };
vm.runInNewContext(fs.readFileSync(path.join(import.meta.dirname, '..', 'public', 'pager.js'), 'utf8')
  + ';this.makePager = makePager;', pagerCtx);

// A fake server whose replies the test releases by hand, in any order.
function fakePages() {
  const calls = [];
  const fetchPage = (type, before, signal) => new Promise((resolve, reject) => {
    const c = { type, before, signal, resolve, reject };
    signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    calls.push(c);
  });
  return { calls, fetchPage };
}
const tick = () => new Promise((r) => setImmediate(r));

test('pager: a slow reply for an old filter cannot land after the filter changed', async () => {
  const f = fakePages(), p = pagerCtx.makePager(f.fetchPage);
  const first = p.start('uploads');
  const second = p.start('blocked');
  assert.equal(f.calls[0].signal.aborted, true, 'the old request is aborted');
  f.calls[0].resolve({ items: [{ a: 'stale' }], next: 'STALE' });   // arrives anyway
  f.calls[1].resolve({ items: [{ a: 'fresh' }], next: 'FRESH' });
  assert.equal(await first, null);
  assert.deepEqual(JSON.parse(JSON.stringify(await second)), { items: [{ a: 'fresh' }] });
  assert.equal(p.next, 'FRESH');
  assert.equal(p.type, 'blocked');
});

test('pager: more() does nothing without a cursor or while a load is out', async () => {
  const f = fakePages(), p = pagerCtx.makePager(f.fetchPage);
  assert.equal(await p.more(), null);
  assert.equal(f.calls.length, 0, 'no request without a cursor');
  const s = p.start('all');
  f.calls[0].resolve({ items: [1], next: 'C1' });
  await s;
  const m1 = p.more(), m2 = p.more();
  assert.equal(f.calls.length, 2, 'a second click while loading is ignored');
  assert.equal(f.calls[1].before, 'C1');
  f.calls[1].resolve({ items: [2], next: null });
  assert.equal((await m1).items[0], 2);
  assert.equal(await m2, null);
  assert.equal(p.next, null);
  assert.equal(await p.more(), null);
  assert.equal(f.calls.length, 2, 'no refetch of page 1');
});

test('pager: closing or changing filter abandons an export; it exports the filter it started with', async () => {
  const f = fakePages(), p = pagerCtx.makePager(f.fetchPage);
  p.type = 'downloads';
  const exp = p.all();
  await tick();
  assert.equal(f.calls[0].type, 'downloads');
  f.calls[0].resolve({ items: [1], next: 'N' });
  await tick(); await tick();
  assert.equal(f.calls[1].type, 'downloads', 'later pages stay on the starting filter');
  p.start('uploads');                                  // the person clicks another chip
  assert.equal(f.calls[1].signal.aborted, true);
  assert.equal(await exp, null);

  const exp2 = p.all();
  await tick();
  f.calls[f.calls.length - 1].resolve({ items: [7], next: null });
  const r = await exp2;                                // an export that completes is for its own filter
  assert.deepEqual(JSON.parse(JSON.stringify(r)), { items: [7], type: 'uploads' });

  const exp3 = p.all();
  p.cancel();                                          // dialog closed
  assert.equal(await exp3, null);
});

test('pager: a real error from the current load still surfaces', async () => {
  const f = fakePages(), p = pagerCtx.makePager(f.fetchPage);
  const s = p.start('all');
  f.calls[0].reject(new Error('boom'));
  await assert.rejects(s, /boom/);
});
