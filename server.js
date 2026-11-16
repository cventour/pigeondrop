#!/usr/bin/env node
// Pigeondrop — a small self-hosted file manager.
//
// Node standard library only. Uploads arrive as a raw PUT body rather than
// multipart/form-data, which removes the only reason this would need a
// dependency: no parser to keep current, and the body streams straight to
// disk, so a 4 GB installer never lands in memory.
//
// Binds loopback by default; set HOST to expose it. There is no
// authentication, so it assumes a network you trust.

import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { once } from 'node:events';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { settingsDiff } from './settings-diff.js';

// Resolved, because safe() compares against this string: a relative
// REPO_ROOT would never match an absolute resolved path, and every
// request would fail the containment check.
const ROOT = path.resolve(process.env.REPO_ROOT || path.join(process.cwd(), 'files'));
const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC = path.join(import.meta.dirname, 'public');
// Settings changed from the page live here, not in ROOT: that is what people
// browse, zip and hand out, and a scanner address has no business in it.
// Under systemd, StateDirectory= names a place the service may write even with
// ProtectSystem=strict, and the code directory is not one of them.
// Run through npx or a global install, the code sits in npm's cache or a
// root-owned folder, so settings go beside the files folder in the working
// directory instead, where they survive an upgrade.
const CODE_DIR = import.meta.dirname.split(path.sep).includes('node_modules')
  ? process.cwd() : import.meta.dirname;
const SETTINGS_FILE = path.resolve(process.env.SETTINGS_FILE
  || path.join(process.env.STATE_DIRECTORY?.split(':')[0] || CODE_DIR, 'settings.json'));

// Branding is configuration, not code: one binary, any deployment.
const TITLE = process.env.REPO_TITLE || 'Pigeondrop';
const SUBTITLE = process.env.REPO_SUBTITLE || 'Drop files in. Take files out.';

// --- path safety -----------------------------------------------------------
// Everything the client sends is untrusted. Resolve it and confirm the result
// is still inside ROOT: `..`, absolute paths and symlink-shaped names all
// collapse here rather than somewhere further in.
function safe(rel) {
  const full = path.resolve(ROOT, '.' + path.posix.resolve('/', rel || '/'));
  if (full !== ROOT && !full.startsWith(ROOT + path.sep)) return null;
  return full;
}

// A single path component, for rename and mkdir. No separators, no dot-names.
function safeName(name) {
  if (typeof name !== 'string') return null;
  const n = name.trim();
  if (!n || n === '.' || n === '..') return null;
  if (n.includes('/') || n.includes('\\') || n.includes('\0')) return null;
  if (n.length > 200) return null;
  return n;
}

const json = (res, code, body) => {
  const s = JSON.stringify(body);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8',
                        'content-length': Buffer.byteLength(s) });
  res.end(s);
};

async function readBody(req, limit) {
  let size = 0; const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new Error('body too large');
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

async function readJson(req, limit = 64 * 1024) {
  return JSON.parse((await readBody(req, limit)).toString('utf8') || '{}');
}

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.pdf': 'application/pdf',
};

// --- settings --------------------------------------------------------------
// One small JSON file, read once and rewritten whole. Validated on the way in
// and again on the way out of disk, so a hand-edited file cannot put the
// scanner client into a state the page could not have produced.
const ICAP_DEFAULTS = {
  enabled: false, host: '', port: 1344, service: 'omsscan',
  timeout: 120,          // seconds without hearing from the ICAP server
  failClosed: true,      // refuse the upload when it cannot be scanned
  tls: false,            // ICAPS: the same protocol inside TLS
  tlsVerify: true,       // check the scanner's certificate
};

function cleanIcap(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const out = { ...ICAP_DEFAULTS };
  const bad = (m) => { const e = new Error(m); e.status = 400; throw e; };

  if ('host' in r) {
    const host = String(r.host ?? '').trim();
    // A hostname, IPv4 or IPv6 literal. No scheme, port or path: those have
    // their own fields, and a pasted icap:// URL should say so, not half-work.
    if (host && !/^[A-Za-z0-9._:-]{1,253}$/.test(host)) bad('Host must be a name or IP address, without icap:// or a port');
    out.host = host;
  }
  if ('port' in r) {
    const port = Number(r.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) bad('Port must be a number from 1 to 65535');
    out.port = port;
  }
  if ('service' in r) {
    const service = String(r.service ?? '').trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(service)) bad('Service must be one word of letters, digits, . _ or -');
    out.service = service;
  }
  if ('timeout' in r) {
    const t = Number(r.timeout);
    if (!Number.isInteger(t) || t < 5 || t > 3600) bad('Timeout must be 5 to 3600 seconds');
    out.timeout = t;
  }
  if ('failClosed' in r) out.failClosed = r.failClosed === true;
  if ('tls' in r) out.tls = r.tls === true;
  if ('tlsVerify' in r) out.tlsVerify = r.tlsVerify !== false;
  if ('enabled' in r) out.enabled = r.enabled === true;
  if (out.enabled && !out.host) bad('Enter the ICAP server before turning scanning on');
  return out;
}

let settings = { icap: { ...ICAP_DEFAULTS } };
try {
  settings.icap = cleanIcap(JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')).icap);
} catch (err) {
  if (err.code !== 'ENOENT') console.log(`ignoring ${SETTINGS_FILE}: ${err.message}`);
}

async function saveSettings(next) {
  // Temp and rename, as with uploads: a crash mid-write must not leave half a
  // JSON file that silently turns scanning off at the next start.
  const tmp = SETTINGS_FILE + '.tmp';
  try {
    await fsp.writeFile(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
    await fsp.rename(tmp, SETTINGS_FILE);
  } catch (err) {
    await fsp.rm(tmp, { force: true }).catch(() => {});
    if (['EROFS', 'EACCES', 'EPERM', 'ENOENT'].includes(err.code)) {
      throw new Error(`Could not save settings to ${SETTINGS_FILE} (${err.code}). ` +
        'Point SETTINGS_FILE at a folder this service can write to.');
    }
    throw err;
  }
  settings = next;
}

// --- activity log ----------------------------------------------------------
// An append-only record of what happened, when, and from where: one JSON line
// per event in activity.log beside settings.json. It is a record, not
// authentication: the address is whatever the socket says, which behind a
// proxy is the proxy.
//
// Rotation is a single step: past the size limit, activity.log becomes
// activity.log.1 (replacing any older one) and a new file starts. Writes are
// synchronous: a line is tiny, and it keeps order and rotation simple.
const ACTIVITY_ON = String(process.env.ACTIVITY_LOG || '').toLowerCase() !== 'off';
const ACTIVITY_FILE = path.join(path.dirname(SETTINGS_FILE), 'activity.log');
const ACTIVITY_MAX = Number(process.env.ACTIVITY_LOG_MAX_BYTES) || 10 * 1024 * 1024;

const TRUST_PROXY = String(process.env.TRUST_PROXY || '').toLowerCase() === 'on';
const CHUNK = Number(process.env.ACTIVITY_READ_CHUNK) || 64 * 1024;

// Where an event happened, relative to what is served: never a host path.
const relPath = (full) => '/' + path.relative(ROOT, full).split(path.sep).join('/');

let activityWarned = false;
function logActivity(req, action, fields = {}) {
  if (!ACTIVITY_ON) return;
  try {
    const peer = (req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
    const ua = String(req.headers['user-agent'] || '').slice(0, 300);
    // Only with TRUST_PROXY on, and then only for a proxy that sets the header:
    // otherwise any client could write whatever address it liked into the log.
    const fwd = TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim().slice(0, 64) : '';
    const who = TRUST_PROXY ? { ip: fwd || peer, peer } : { ip: peer };
    const line = JSON.stringify({ ts: new Date().toISOString(), ...who, ua, action, ...fields }) + '\n';
    try {
      if (fs.statSync(ACTIVITY_FILE).size >= ACTIVITY_MAX) fs.renameSync(ACTIVITY_FILE, ACTIVITY_FILE + '.1');
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
    fs.mkdirSync(path.dirname(ACTIVITY_FILE), { recursive: true });
    fs.appendFileSync(ACTIVITY_FILE, line, { mode: 0o600 });
  } catch (err) {
    // The log must never take a request down with it.
    if (!activityWarned) {
      activityWarned = true;
      console.error(`activity log: cannot write ${ACTIVITY_FILE} (${err.code || err.message}); further failures are not reported`);
    }
  }
}

const ACTIVITY_TYPES = {
  all: null,
  uploads: ['upload'],
  downloads: ['download', 'download_zip'],
  changes: ['delete', 'rename', 'mkdir'],
  blocked: ['upload_blocked', 'upload_scan_error'],
  settings: ['settings'],
};

// Newest first, paged. The cursor is "<file>:<offset>:<inode>": `file` is 0
// for activity.log and 1 for activity.log.1, `offset` is the byte where the
// last returned line starts, and the next page is everything before it. The
// inode lets a cursor survive a rotation between pages: the file it named
// is found again, as .1, instead of the offset being applied to a new file.
// Lines are only ever appended, so an offset never moves within a file.
//
// Files are read backwards from the end in CHUNK-sized pieces and reading
// stops once a page and one more matching line are in hand, so a page costs
// about a chunk however big the log is.
function* linesBackward(fd, end) {
  let tail = Buffer.alloc(0), pos = end;       // tail holds the bytes [pos, pos + tail.length)
  for (;;) {
    const i = tail.length >= 2 ? tail.lastIndexOf(10, tail.length - 2) : -1;
    if (i !== -1) {
      yield { start: pos + i + 1, text: tail.subarray(i + 1) };
      tail = tail.subarray(0, i + 1);
    } else if (pos > 0) {
      const from = Math.max(0, pos - CHUNK), buf = Buffer.alloc(pos - from);
      fs.readSync(fd, buf, 0, buf.length, from);
      tail = Buffer.concat([buf, tail]); pos = from;
    } else {
      if (tail.length) yield { start: 0, text: tail };
      return;
    }
  }
}

function readActivity(types, limit, before) {
  const fds = [ACTIVITY_FILE, ACTIVITY_FILE + '.1'].map((f) => {
    try { const fd = fs.openSync(f, 'r'); const st = fs.fstatSync(fd); return { fd, ino: String(st.ino), size: st.size }; }
    catch { return null; }
  });
  try {
    let startFile = 0, startOff = Infinity;
    if (before) {
      const [f, o, ino] = String(before).split(':');
      const hit = fds.findIndex((x) => x && x.ino === ino);
      if (!/^[01]$/.test(f) || !/^\d+$/.test(o) || hit === -1) return { items: [], next: null };
      startFile = hit; startOff = Number(o);
    }
    const items = [];
    for (let fi = startFile; fi < 2; fi++) {
      const x = fds[fi];
      if (!x) continue;
      for (const { start, text } of linesBackward(x.fd, fi === startFile ? Math.min(startOff, x.size) : x.size)) {
        let e;
        try { e = JSON.parse(text.toString('utf8')); } catch { e = null; }
        if (!e || (types && !types.includes(e.action))) continue;
        items.push({ e, cursor: `${fi}:${start}:${x.ino}` });
        // One past the page: proof that there is more, so "next" is never a
        // cursor to an empty page.
        if (items.length > limit) {
          return { items: items.slice(0, limit).map((i) => i.e), next: items[limit - 1].cursor };
        }
      }
    }
    return { items: items.map((i) => i.e), next: null };
  } finally {
    for (const x of fds) if (x) fs.closeSync(x.fd);
  }
}

// A refused request, logged as the action it tried. The path is what the
// client asked for, shortened; it is never resolved to a host path.
function refuse(req, res, action, code, error, fields = {}, reason = error) {
  logActivity(req, action, { ...fields, result: 'rejected', reason });
  return json(res, code, { error });
}
const asked = (v) => typeof v === 'string' ? v.slice(0, 300) : undefined;

// --- ICAP ------------------------------------------------------------------
// A minimal RFC 3507 client: one REQMOD per file, the file sent as the body of
// a PUT so the scanner sees a name and the bytes. It streams from disk in
// chunks, so a large file is never held in memory, and it stops reading the
// reply at the end of the ICAP headers, because a block page follows them and
// nothing here needs it.

// What the scanner says about its own health rather than about the file.
// These are not verdicts: whether they stop an upload is the failClosed choice.
const SCANNER_FAULT = /licen[sc]e|unavailable|not available|not ready|failed to scan|scan fail|timed? ?out|no engine|error/i;

// tlsVerify off accepts any certificate: the link is encrypted but the
// scanner is not authenticated. On, a private or self-signed certificate is
// trusted by pointing NODE_EXTRA_CA_CERTS at its CA file.
const icapConnect = (cfg) => cfg.tls
  ? tls.connect({ host: cfg.host, port: cfg.port, rejectUnauthorized: cfg.tlsVerify })
  : net.connect({ host: cfg.host, port: cfg.port });
const icapReady = (cfg) => cfg.tls ? 'secureConnect' : 'connect';

// Why a TLS connection failed, said so a person can fix it. Node and OpenSSL
// give codes; these are the ones a scanner setup actually runs into.
const TRUST_FIX = 'Set NODE_EXTRA_CA_CERTS to the CA file, or untick "Verify the certificate"';
function tlsReason(e, cfg) {
  const c = e.code || '', who = `${cfg.host}:${cfg.port}`;
  const day = (d) => d ? new Date(d).toISOString().slice(0, 10) : 'an unknown date';
  if (c === 'CERT_HAS_EXPIRED') return `the certificate of ${who} has expired. Renew it on the scanner`;
  if (c === 'CERT_NOT_YET_VALID') return `the certificate of ${who} is not valid yet. Check the clocks on both machines`;
  // Checked before the certificate codes below, which these also match.
  if (/CERTIFICATE_REQUIRED|HANDSHAKE_FAILURE/.test(c + e.message)) {
    return `${who} refused the TLS handshake: it wants a client certificate, or has no cipher in common`;
  }
  if (c === 'DEPTH_ZERO_SELF_SIGNED_CERT' || c === 'SELF_SIGNED_CERT_IN_CHAIN') {
    return `the certificate of ${who} is self-signed. ${TRUST_FIX}`;
  }
  if (/^UNABLE_TO_(GET_ISSUER_CERT|VERIFY_LEAF_SIGNATURE)/.test(c)) {
    return `the certificate of ${who} is issued by a CA this server does not trust. ${TRUST_FIX}`;
  }
  if (c === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    const names = (e.cert?.subjectaltname || e.cert?.subject?.CN || '').replace(/(DNS|IP Address):/g, '');
    return `the certificate of ${who} is for ${names || 'another name'}, not ${cfg.host}. ` +
      'Enter one of those names as Server';
  }
  if (c === 'CERT_REVOKED') return `the certificate of ${who} has been revoked`;
  if (/CERT|SIGNATURE/.test(c)) return `the certificate of ${who} was rejected (${c}). ${TRUST_FIX}`;
  if (/WRONG_VERSION_NUMBER|PACKET_LENGTH_TOO_LONG|HTTP_REQUEST/.test(c + e.message)) {
    return `${who} did not answer with TLS. It looks like a plain ICAP port: untick "Use TLS" or use the ICAPS port`;
  }
  if (/PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL/.test(c + e.message)) {
    return `${who} and this server have no TLS version in common. The scanner needs TLS 1.2 or later`;
  }
  if (c === 'ECONNRESET' || c === 'EPROTO') return `${who} dropped the connection during the TLS handshake`;
  return null;
}

function icapError(e, cfg) {
  if (e.code === 'ECONNREFUSED') return `${cfg.host}:${cfg.port} refused the connection`;
  if (e.code === 'ENOTFOUND') return `cannot resolve ${cfg.host}`;
  const t = cfg.tls && tlsReason(e, cfg);
  return t ? `TLS: ${t}` : e.message;
}

// A plain ICAP port given TLS says nothing back: it waits for a request.
// An ICAPS port given plain ICAP hangs up, because the request is not TLS.
const closed = (cfg) => 'the ICAP server closed the connection' +
  (cfg.tls ? '' : '. If it expects TLS, tick "Use TLS (ICAPS)"');
const silent = (cfg) => `no answer from ${cfg.host}:${cfg.port}` +
  (cfg.tls ? '. If this is a plain ICAP port, untick "Use TLS"' : '');

function readIcapHead(text) {
  const [status, ...lines] = text.split('\r\n');
  const code = Number(status.split(' ')[1]);
  const h = {};
  for (const l of lines) {
    const i = l.indexOf(':');
    if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  return { code, status, h };
}

function judge({ code, status, h }) {
  if (code === 204) return { verdict: 'clean' };
  if (code !== 200 && code !== 201) return { verdict: 'error', detail: status || 'unreadable ICAP reply' };

  // For a request modification, being answered with a *response* means the
  // scanner refused to pass the request on: the file is blocked.
  const refused = /^blocked$/i.test(h['x-response-info'] || '') || /res-hdr=/.test(h.encapsulated || '');
  if (!refused) return { verdict: 'clean' };

  const reason = h['x-response-desc'] || 'blocked by the scanner';
  const found = h['x-infection-found'] || h['x-violations-found'] || h['x-virus-id'] || '';
  const threat = (found.match(/Threat=([^;]+)/i) || [])[1]?.trim() || (found && !found.includes('=') ? found : '');
  if (SCANNER_FAULT.test(reason) && !threat) return { verdict: 'error', detail: reason };
  return { verdict: 'blocked', reason, threat };
}

// source: { size, stream() }. Resolves, never rejects: every failure is an
// 'error' verdict with something a person can act on.
async function icapScan(source, name, cfg) {
  const sock = icapConnect(cfg);
  sock.setTimeout(cfg.timeout * 1000);
  const ac = new AbortController();
  let finish;
  const answer = new Promise((resolve) => { finish = resolve; });
  const fault = (detail) => finish({ verdict: 'error', detail });

  let head = Buffer.alloc(0);
  sock.on('data', (c) => {
    head = Buffer.concat([head, c]);
    const end = head.indexOf('\r\n\r\n');
    if (end !== -1) finish(judge(readIcapHead(head.subarray(0, end).toString('latin1'))));
    else if (head.length > 64 * 1024) fault('unreadable ICAP reply');
  });
  sock.on('timeout', () => fault(`${silent(cfg)} (waited ${cfg.timeout}s)`));
  sock.on('error', (e) => fault(icapError(e, cfg)));
  sock.on('close', () => fault(closed(cfg)));

  (async () => {
    try {
      await once(sock, icapReady(cfg), { signal: ac.signal });
      const put = async (b) => { if (!sock.write(b)) await once(sock, 'drain', { signal: ac.signal }); };

      const http = `PUT /${encodeURIComponent(name)} HTTP/1.1\r\nHost: pigeondrop\r\n` +
        `Content-Disposition: attachment; filename="${name.replace(/[^\x20-\x7E]|["\\]/g, '_')}"\r\n` +
        `Content-Type: application/octet-stream\r\nContent-Length: ${source.size}\r\n\r\n`;
      await put(`REQMOD icap://${cfg.host}:${cfg.port}/${cfg.service} ICAP/1.0\r\n` +
        `Host: ${cfg.host}\r\nAllow: 204\r\n` +
        `Encapsulated: req-hdr=0, req-body=${Buffer.byteLength(http)}\r\n\r\n${http}`);

      for await (const c of source.stream()) {
        if (ac.signal.aborted) return;
        await put(`${c.length.toString(16)}\r\n`);
        await put(c);
        await put('\r\n');
      }
      await put('0\r\n\r\n');
    } catch {
      // A scanner that decides early (a block, say) may close while the body
      // is still going out. Its answer, if there is one, is already in hand.
    }
  })();

  const result = await answer;
  ac.abort();
  sock.destroy();
  return result;
}

const scanFile = async (full, name, cfg) =>
  icapScan({ size: (await fsp.stat(full)).size, stream: () => fs.createReadStream(full) }, name, cfg);

// What "Test connection" does: ask what the server is (OPTIONS), then push a
// few harmless bytes through a real scan. OPTIONS alone would report a server
// that answers but cannot scan, which is exactly the state worth catching.
async function icapTest(cfg) {
  const t0 = Date.now();
  const options = await new Promise((resolve) => {
    const sock = icapConnect(cfg);
    let buf = '';
    const end = (r) => { sock.destroy(); resolve(r); };
    sock.setTimeout(8000, () => end({ error: silent(cfg) }));
    sock.on('error', (e) => end({ error: icapError(e, cfg) }));
    sock.on(icapReady(cfg), () => sock.write(`OPTIONS icap://${cfg.host}:${cfg.port}/${cfg.service} ICAP/1.0\r\nHost: ${cfg.host}\r\n\r\n`));
    sock.on('data', (c) => {
      buf += c.toString('latin1');
      if (buf.includes('\r\n\r\n')) {
        const { code, status, h } = readIcapHead(buf.slice(0, buf.indexOf('\r\n\r\n')));
        end(code === 200 ? { server: h.service || h['server'] || 'ICAP server', methods: h.methods || '' }
                         : { error: status });
      }
    });
    sock.on('close', () => end({ error: closed(cfg) }));
  });
  if (options.error) return { ok: false, error: options.error };

  const sample = Buffer.from('pigeondrop connection test\n');
  const scan = await icapScan({ size: sample.length, stream: () => Readable.from([sample]) },
                              'pigeondrop-test.txt', { ...cfg, timeout: 20 });
  const ms = Date.now() - t0;
  if (scan.verdict === 'clean') return { ok: true, server: options.server, methods: options.methods, ms };
  return {
    ok: false, server: options.server, ms,
    error: scan.verdict === 'error' ? `${options.server} answers but cannot scan: ${scan.detail}`
      : `${options.server} blocked the test file: ${scan.reason}`,
  };
}

// --- handlers --------------------------------------------------------------
async function list(dir) {
  const full = safe(dir);
  if (!full) return null;
  const entries = await fsp.readdir(full, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    if (e.name.startsWith('.')) continue;
    let st;
    try { st = await fsp.stat(path.join(full, e.name)); } catch { continue; }
    out.push({
      name: e.name,
      dir: e.isDirectory(),
      size: e.isDirectory() ? null : st.size,
      mtime: st.mtimeMs,
    });
  }
  // Directories first, then name order — the arrangement a person scanning a
  // list expects, rather than whatever readdir happened to return.
  out.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
  return out;
}

// "file.tar.gz" -> ["file", ".tar.gz"], so a suffixed copy keeps the whole
// extension rather than becoming "file.tar (2).gz".
function splitName(name) {
  const m = name.match(/^(.+?)((?:\.tar)?\.[^.]+)$/);
  return m ? [m[1], m[2]] : [name, ''];
}

function freeName(dir, name) {
  const [base, ext] = splitName(name);
  for (let n = 2; n < 1000; n++) {
    const candidate = `${base} (${n})${ext}`;
    if (!fs.existsSync(path.join(dir, candidate))) return candidate;
  }
  return `${base} (${Date.now()})${ext}`;
}

async function upload(req, res, rel, mode) {
  let full = safe(rel);
  if (!full || full === ROOT) { req.resume(); return refuse(req, res, 'upload', 400, 'bad path', { path: asked(rel) }); }
  let name = path.basename(full);
  if (!safeName(name)) { req.resume(); return refuse(req, res, 'upload', 400, 'bad filename', { path: relPath(full) }); }

  await fsp.mkdir(path.dirname(full), { recursive: true });

  // Refuse rather than silently overwrite. The client asks and retries with
  // an explicit mode; a file manager that replaces without asking is the one
  // that loses somebody's work.
  if (fs.existsSync(full) && mode !== 'replace' && mode !== 'keep') {
    req.resume();                       // drain, or the socket hangs
    logActivity(req, 'upload', { path: relPath(full), result: 'rejected', reason: 'exists' });
    return json(res, 409, { error: 'exists', name });
  }
  const replaced = mode === 'replace' && fs.existsSync(full);
  if (fs.existsSync(full) && mode === 'keep') {
    name = freeName(path.dirname(full), name);
    full = path.join(path.dirname(full), name);
  }

  // Write to a temporary name and rename on success. An interrupted upload
  // then leaves nothing behind, instead of a truncated installer that looks
  // complete until someone runs it. Scanning slots in before the rename for
  // the same reason: a file under scrutiny is never visible under its name.
  const tmp = full + '.part';
  try {
    await pipeline(req, fs.createWriteStream(tmp));

    const cfg = settings.icap;
    let scan = 'off', note;
    if (cfg.enabled) {
      const r = await scanFile(tmp, name, cfg);
      if (r.verdict === 'blocked') {
        const size = (await fsp.stat(tmp).catch(() => null))?.size;
        await fsp.rm(tmp, { force: true });
        logActivity(req, 'upload_blocked', { path: relPath(full), size, reason: r.reason,
          ...(r.threat ? { threat: r.threat } : {}) });
        return json(res, 422, { error: 'blocked', reason: r.reason, threat: r.threat, name });
      }
      if (r.verdict === 'error') {
        const size = (await fsp.stat(tmp).catch(() => null))?.size;
        logActivity(req, 'upload_scan_error', { path: relPath(full), size, reason: r.detail,
          result: cfg.failClosed ? 'rejected' : 'accepted' });
        if (cfg.failClosed) {
          await fsp.rm(tmp, { force: true });
          return json(res, 502, { error: 'scan failed', detail: r.detail, name });
        }
        scan = 'skipped'; note = r.detail;
      } else scan = 'clean';
    }

    await fsp.rename(tmp, full);
    const st = await fsp.stat(full);
    // A file let through after a scanner fault already has its
    // upload_scan_error line; one line per event.
    if (scan !== 'skipped') logActivity(req, 'upload', { path: relPath(full), size: st.size, result: scan, ...(replaced ? { replaced: true } : {}) });
    json(res, 200, { ok: true, name, size: st.size, scan, note });
  } catch (err) {
    await fsp.rm(tmp, { force: true });
    json(res, 500, { error: String(err.message || err) });
  }
}

async function download(req, res, rel) {
  const full = safe(rel);
  if (!full) return json(res, 400, { error: 'bad path' });
  let st;
  try { st = await fsp.stat(full); } catch { return json(res, 404, { error: 'not found' }); }
  if (st.isDirectory()) return json(res, 400, { error: 'is a directory' });
  // Logged when the response ends, so the line says whether it got there.
  let sent = 0;
  res.on('close', () => logActivity(req, 'download', { path: relPath(full), size: st.size,
    ...(res.writableFinished ? { result: 'completed' } : { result: 'aborted', sent }) }));
  res.writeHead(200, {
    'content-type': 'application/octet-stream',
    'content-length': st.size,
    'content-disposition': `attachment; filename="${path.basename(full).replace(/"/g, '')}"`,
  });
  const rs = fs.createReadStream(full);
  rs.on('data', (c) => { sent += c.length; });
  // A client that goes away ends the pipeline with an error; headers are
  // already sent, so there is nothing to answer.
  await pipeline(rs, res).catch(() => {});
}

// --- zip -------------------------------------------------------------------
// Folders and multi-file selections download as one zip, written by hand
// rather than by a library. The archive streams: each entry is deflated as it
// is read and its CRC and sizes follow in a data descriptor, so nothing is
// buffered or staged on disk and the download starts at once. ZIP64 fields
// appear only where a size or offset needs them, which keeps small archives
// readable by the oldest unzip and lets large ones pass 4 GB.

const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
// zlib.crc32 is native but only from Node 20.15 / 22.2.
const crc32 = zlib.crc32 || ((buf, crc = 0) => {
  let c = ~crc;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return ~c >>> 0;
});

const U32 = 0xFFFFFFFF;

function dosTime(ms) {
  const d = new Date(Math.max(ms, 315532800000));      // zip time starts at 1980
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

// Everything under the chosen items, as { full, name, dir, st }. Skips what
// the listing hides (dot-names), unfinished uploads (.part), and symlinks, so
// a link can neither pull in files from outside ROOT nor loop forever.
async function collect(full, name, out) {
  let st;
  try { st = await fsp.lstat(full); } catch { return; }
  if (st.isSymbolicLink()) return;
  if (st.isDirectory()) {
    out.push({ full, name: name + '/', dir: true, st });
    let entries;
    try { entries = await fsp.readdir(full); } catch { return; }
    entries.sort((a, b) => a.localeCompare(b));
    for (const e of entries) {
      if (e.startsWith('.') || e.endsWith('.part')) continue;
      await collect(path.join(full, e), name + '/' + e, out);
    }
  } else if (st.isFile()) {
    out.push({ full, name, dir: false, st });
  }
}

async function zip(req, res, rels, filename) {
  const items = [];
  const asked = [];
  for (const rel of rels) {
    const full = safe(rel);
    if (!full || full === ROOT) return json(res, 400, { error: 'bad path' });
    asked.push(relPath(full));
    await collect(full, path.basename(full), items);
  }
  if (!items.length) return json(res, 404, { error: 'nothing to download' });
  const total = items.reduce((n, it) => n + (it.dir ? 0 : it.st.size), 0);

  const ascii = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '');
  res.writeHead(200, {
    'content-type': 'application/zip',
    'content-disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
  });

  // A closed tab must stop the work, not leave it deflating into nowhere.
  const ac = new AbortController();
  res.on('close', () => ac.abort());
  const { signal } = ac;

  let offset = 0;
  res.on('close', () => logActivity(req, 'download_zip', { paths: asked, size: total,
    ...(res.writableFinished ? { result: 'completed' } : { result: 'aborted', sent: offset }) }));
  const put = async (buf) => {
    offset += buf.length;
    if (!res.write(buf)) await once(res, 'drain', { signal });
  };

  const central = [];
  for (const it of items) {
    if (signal.aborted) return;
    const name = Buffer.from(it.name, 'utf8');
    const { time, date } = dosTime(it.st.mtimeMs);
    const start = offset;
    // Decided up front, since the local header is already sent by the time
    // the real sizes are known. The margin covers deflate's worst-case growth
    // on data that does not compress.
    const big = !it.dir && it.st.size >= U32 * 0.99;
    const flags = 0x0800 | (it.dir ? 0 : 0x0008);      // UTF-8 names; descriptor
    const method = it.dir ? 0 : 8;

    const extra = big ? Buffer.alloc(20) : Buffer.alloc(0);
    if (big) { extra.writeUInt16LE(0x0001, 0); extra.writeUInt16LE(16, 2); }
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(big ? 45 : 20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(time, 10);
    lh.writeUInt16LE(date, 12);
    lh.writeUInt32LE(big ? U32 : 0, 18);
    lh.writeUInt32LE(big ? U32 : 0, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(extra.length, 28);
    await put(Buffer.concat([lh, name, extra]));

    let crc = 0, usize = 0, csize = 0;
    if (!it.dir) {
      try {
        await pipeline(
          fs.createReadStream(it.full),
          async function* (src) {
            for await (const c of src) { crc = crc32(c, crc); usize += c.length; yield c; }
          },
          // Level 1: most of what goes through here (installers, archives,
          // media) is already compressed, and on a LAN the deflate would
          // otherwise be slower than the wire.
          zlib.createDeflateRaw({ level: 1 }),
          async function (src) {
            for await (const c of src) { csize += c.length; await put(c); }
          },
          { signal },
        );
      } catch (err) {
        // Headers are gone, so there is no status left to send. Cutting the
        // connection makes the browser report a failed download instead of
        // saving a truncated zip that looks complete.
        res.destroy(err);
        return;
      }
      const dd = Buffer.alloc(big ? 24 : 16);
      dd.writeUInt32LE(0x08074b50, 0);
      dd.writeUInt32LE(crc, 4);
      if (big) { dd.writeBigUInt64LE(BigInt(csize), 8); dd.writeBigUInt64LE(BigInt(usize), 16); }
      else { dd.writeUInt32LE(csize, 8); dd.writeUInt32LE(usize, 12); }
      await put(dd);
    }
    central.push({ name, time, date, flags, method, crc, usize, csize, start, big, dir: it.dir });
  }

  const cdStart = offset;
  for (const e of central) {
    const z = [];
    if (e.usize >= U32) z.push(e.usize);
    if (e.csize >= U32) z.push(e.csize);
    if (e.start >= U32) z.push(e.start);
    const extra = z.length ? Buffer.alloc(4 + z.length * 8) : Buffer.alloc(0);
    if (z.length) {
      extra.writeUInt16LE(0x0001, 0);
      extra.writeUInt16LE(z.length * 8, 2);
      z.forEach((v, i) => extra.writeBigUInt64LE(BigInt(v), 4 + i * 8));
    }
    const need = e.big || z.length ? 45 : 20;
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE((3 << 8) | 45, 4);                  // made by: unix
    ch.writeUInt16LE(need, 6);
    ch.writeUInt16LE(e.flags, 8);
    ch.writeUInt16LE(e.method, 10);
    ch.writeUInt16LE(e.time, 12);
    ch.writeUInt16LE(e.date, 14);
    ch.writeUInt32LE(e.crc, 16);
    ch.writeUInt32LE(Math.min(e.csize, U32), 20);
    ch.writeUInt32LE(Math.min(e.usize, U32), 24);
    ch.writeUInt16LE(e.name.length, 28);
    ch.writeUInt16LE(extra.length, 30);
    ch.writeUInt32LE(e.dir ? ((0o40755 << 16) | 0x10) >>> 0 : (0o100644 << 16) >>> 0, 38);
    ch.writeUInt32LE(Math.min(e.start, U32), 42);
    await put(Buffer.concat([ch, e.name, extra]));
  }
  const cdSize = offset - cdStart;

  const n = central.length;
  if (n >= 0xFFFF || cdStart >= U32 || cdSize >= U32) {
    const z64At = offset;
    const rec = Buffer.alloc(56);
    rec.writeUInt32LE(0x06064b50, 0);
    rec.writeBigUInt64LE(44n, 4);
    rec.writeUInt16LE((3 << 8) | 45, 12);
    rec.writeUInt16LE(45, 14);
    rec.writeBigUInt64LE(BigInt(n), 24);
    rec.writeBigUInt64LE(BigInt(n), 32);
    rec.writeBigUInt64LE(BigInt(cdSize), 40);
    rec.writeBigUInt64LE(BigInt(cdStart), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(z64At), 8);
    loc.writeUInt32LE(1, 16);
    await put(Buffer.concat([rec, loc]));
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Math.min(n, 0xFFFF), 8);
  end.writeUInt16LE(Math.min(n, 0xFFFF), 10);
  end.writeUInt32LE(Math.min(cdSize, U32), 12);
  end.writeUInt32LE(Math.min(cdStart, U32), 16);
  await put(end);
  res.end();
}

async function serveStatic(res, urlPath) {
  const rel = urlPath === '/' ? '/index.html' : urlPath;
  const full = path.resolve(PUBLIC, '.' + rel);
  if (!full.startsWith(PUBLIC)) return json(res, 400, { error: 'bad path' });
  try {
    const data = await fsp.readFile(full);
    res.writeHead(200, { 'content-type': TYPES[path.extname(full)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    json(res, 404, { error: 'not found' });
  }
}

// --- server ----------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = decodeURIComponent(url.pathname);

  try {
    if (req.method === 'GET' && p === '/api/config') {
      return json(res, 200, { title: TITLE, subtitle: SUBTITLE, root: path.basename(ROOT),
                              activityLog: ACTIVITY_ON });
    }

    if (req.method === 'GET' && p === '/api/activity') {
      if (!ACTIVITY_ON) return json(res, 404, { error: 'not found' });
      const q = url.searchParams;
      const type = q.get('type') || 'all';
      if (!(type in ACTIVITY_TYPES)) return json(res, 400, { error: 'unknown type' });
      const n = Number(q.get('limit'));
      const limit = Number.isInteger(n) && n > 0 ? Math.min(n, 500) : 100;
      const { items, next } = readActivity(ACTIVITY_TYPES[type], limit, q.get('before'));
      return json(res, 200, { items, next });
    }

    if (req.method === 'GET' && p === '/api/settings') {
      return json(res, 200, settings);
    }

    if (req.method === 'PUT' && p === '/api/settings') {
      const body = await readJson(req);
      const next = { ...settings, icap: cleanIcap({ ...settings.icap, ...body.icap }) };
      const before = settings;
      await saveSettings(next);
      const changes = settingsDiff(before, next);
      if (changes.length) logActivity(req, 'settings', { changes });
      return json(res, 200, settings);
    }

    // Tries the values on the page, not the saved ones, so a server can be
    // checked before it is committed to.
    if (req.method === 'POST' && p === '/api/settings/icap-test') {
      const body = await readJson(req);
      const cfg = cleanIcap({ ...body, enabled: false });
      if (!cfg.host) return json(res, 400, { error: 'Enter the ICAP server first' });
      return json(res, 200, await icapTest(cfg));
    }

    if (req.method === 'GET' && p === '/api/exists') {
      const full = safe(url.searchParams.get('path') || '');
      if (!full || full === ROOT) return json(res, 400, { error: 'bad path' });
      return json(res, 200, { exists: fs.existsSync(full) });
    }

    if (req.method === 'GET' && p === '/api/list') {
      const items = await list(url.searchParams.get('dir') || '/');
      return items ? json(res, 200, { items }) : json(res, 400, { error: 'bad path' });
    }

    if (req.method === 'PUT' && p.startsWith('/api/upload/')) {
      return await upload(req, res, p.slice('/api/upload'.length),
                          url.searchParams.get('mode'));
    }

    if (req.method === 'GET' && p.startsWith('/api/download/')) {
      return await download(req, res, p.slice('/api/download'.length));
    }

    // A form POST rather than fetch, so the browser runs the download itself:
    // its own progress, its own save dialog, and no archive held in page memory.
    if (req.method === 'POST' && p === '/api/zip') {
      const form = new URLSearchParams((await readBody(req, 4 * 1024 * 1024)).toString('utf8'));
      const paths = form.getAll('path');
      if (!paths.length) return json(res, 400, { error: 'nothing selected' });
      const dir = form.get('dir') || '/';
      // One folder is named after itself; a selection after the folder it came from.
      const base = paths.length === 1 ? path.posix.basename(paths[0])
        : (dir === '/' ? path.basename(ROOT) : path.posix.basename(dir));
      return await zip(req, res, paths, (base || 'download') + '.zip');
    }

    if (req.method === 'POST' && p === '/api/delete') {
      const { target } = await readJson(req);
      const full = safe(target);
      if (!full || full === ROOT) return refuse(req, res, 'delete', 400, 'bad path', { path: asked(target) });
      const existed = fs.existsSync(full);
      await fsp.rm(full, { recursive: true, force: true });
      if (existed) logActivity(req, 'delete', { path: relPath(full) });
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && p === '/api/rename') {
      const { target, name } = await readJson(req);
      const full = safe(target);
      const clean = safeName(name);
      if (!full || full === ROOT) return refuse(req, res, 'rename', 400, 'bad path', { path: asked(target) });
      if (!clean) return refuse(req, res, 'rename', 400, 'a name cannot contain / or \\', { path: relPath(full), to: asked(name) }, 'bad name');
      const dest = path.join(path.dirname(full), clean);
      if (fs.existsSync(dest)) return refuse(req, res, 'rename', 409, 'that name is taken', { path: relPath(full), to: relPath(dest) }, 'name taken');
      await fsp.rename(full, dest);
      logActivity(req, 'rename', { path: relPath(full), to: relPath(dest) });
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && p === '/api/mkdir') {
      const { dir, name } = await readJson(req);
      const base = safe(dir || '/');
      const clean = safeName(name);
      if (!base) return refuse(req, res, 'mkdir', 400, 'bad path', { path: asked(dir) });
      if (!clean) return refuse(req, res, 'mkdir', 400, 'a folder name cannot contain / or \\', { path: relPath(base), to: asked(name) }, 'bad name');
      await fsp.mkdir(path.join(base, clean), { recursive: false });
      logActivity(req, 'mkdir', { path: relPath(path.join(base, clean)) });
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET') return await serveStatic(res, p);
    json(res, 405, { error: 'method not allowed' });
  } catch (err) {
    const code = err.status || (err instanceof SyntaxError ? 400 : 500);
    // Validation and bad-JSON refusals on the state-changing routes.
    const attempted = { '/api/settings': req.method === 'PUT' && 'settings', '/api/delete': 'delete',
      '/api/rename': 'rename', '/api/mkdir': 'mkdir' }[p];
    if (code < 500 && attempted && !res.headersSent) {
      return refuse(req, res, attempted, code, String(err.message || err));
    }
    if (res.headersSent) return res.destroy();
    json(res, code, { error: String(err.message || err) });
  }
});

fs.mkdirSync(ROOT, { recursive: true });

// A .part file can only be an upload that did not finish, and nothing is in
// flight at startup, so anything here is debris from a previous run.
try {
  for (const f of fs.readdirSync(ROOT, { recursive: true })) {
    if (typeof f === 'string' && f.endsWith('.part')) {
      fs.rmSync(path.join(ROOT, f), { force: true });
      console.log(`removed stale partial upload: ${f}`);
    }
  }
} catch {}

server.listen(PORT, HOST, () => {
  console.log(`${TITLE} — serving ${ROOT} on http://${HOST}:${PORT}`);
});

// Finish what is in flight before exiting. Without this, a restart during a
// large upload drops the connection and leaves a .part behind — and an
// updater that restarts services is exactly the thing most likely to do it.
let closing = false;
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    if (closing) return process.exit(1);   // second signal: go now
    closing = true;
    console.log(`${sig} — finishing in-flight requests`);
    server.close(() => { console.log('drained, exiting'); process.exit(0); });
  });
}
