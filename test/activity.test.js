// Activity log tests. The server runs as a child process against a temp
// folder, the way it runs for real; the ICAP scanner is a tiny fake on node:net.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
  const put = (p, body, q = '') => call('/api/upload' + p + q, { method: 'PUT', body });
  const activity = async (qs = '') => (await call('/api/activity' + qs)).json();
  return { dir, base, logFile, call, jpost, lines, put, activity, err: () => err, proc };
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
  assert.equal((await s.call('/api/download/a.txt')).status, 200);
  await (await s.call('/api/download/a.txt')).arrayBuffer();
  assert.equal((await s.jpost('/api/mkdir', { dir: '/', name: 'docs' })).status, 200);
  assert.equal((await s.jpost('/api/rename', { target: '/a.txt', name: 'b.txt' })).status, 200);
  assert.equal((await s.jpost('/api/delete', { target: '/b.txt' })).status, 200);

  const l = s.lines();
  assert.deepEqual(l.map((e) => e.action), ['upload', 'download', 'download', 'mkdir', 'rename', 'delete']);
  for (const e of l) {
    assert.match(e.ts, /^\d{4}-\d\d-\d\dT.*Z$/);
    assert.equal(e.ua, UA);
    assert.match(e.ip, /^127\.0\.0\.1$|^::1$/);
  }
  assert.deepEqual([l[0].path, l[0].size, l[0].result], ['/a.txt', 5, 'off']);
  assert.deepEqual([l[1].path, l[1].size], ['/a.txt', 5]);
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
  const z = s.lines().filter((e) => e.action === 'download_zip');
  assert.equal(z.length, 1);
  assert.deepEqual(z[0].paths, ['/d']);
  assert.equal(z[0].size, 6);
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
