// Core upload logic: validation, naming, service-account token, resumable chunked upload with resume.
// No DOM access, so it can be tested in Node with fakes.
const Uploader = (() => {
  const CHUNK = 8 * 1024 * 1024; // 8 MiB, a multiple of 256 KiB as Drive requires
  const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB
  const MAX_FILES = 20;
  const EXT_OK = new Set(['jpg', 'jpeg', 'png', 'heic', 'heif', 'mp4', 'mov']);
  const SCOPE = 'https://www.googleapis.com/auth/drive.file';
  const UPLOAD_URL =
    'https://drive.google.com/drive/u/0/folders/1seWvirzrzVDW-PPa4ijcKNBHmAQ7mHy5';

  const extOf = (name) => (String(name).split('.').pop() || '').toLowerCase();

  // Judge by extension (iPhones may return an empty type). Returns null if OK.
  function validate(file) {
    if (!EXT_OK.has(extOf(file.name))) return 'type';
    if (!file.size) return 'empty';
    if (file.size > MAX_BYTES) return 'size';
    return null;
  }

  function makeName(eventName, ext) {
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    const id = [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${eventName}_${stamp}_${id}.${ext}`;
  }

  const b64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const fail = (code, message, extra) => Object.assign(new Error(message), { code }, extra);

  function createClient({
    credential, folderId, eventName,
    fetchFn = (...a) => fetch(...a),
    xhrFactory = () => new XMLHttpRequest(),
    sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
    now = () => Date.now(),
  }) {
    let token = null, tokenExp = 0;

    async function getToken() {
      if (token && now() < tokenExp - 60000) return token;
      try {
        const iat = Math.floor(now() / 1000);
        const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
        const unsigned = `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc({
          iss: credential.client_email, scope: SCOPE,
          aud: 'https://oauth2.googleapis.com/token', iat, exp: iat + 3600,
        })}`;
        const der = Uint8Array.from(
          atob(credential.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), (c) => c.charCodeAt(0));
        const key = await crypto.subtle.importKey(
          'pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned));
        const r = await fetchFn('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: `${unsigned}.${b64url(sig)}`,
          }),
        });
        if (!r.ok) throw new Error(`token ${r.status}`);
        const j = await r.json();
        token = j.access_token;
        tokenExp = now() + j.expires_in * 1000;
        return token;
      } catch (e) {
        token = null;
        throw fail('token', e.message);
      }
    }

    async function startSession(file) {
      const name = makeName(eventName, extOf(file.name));
      for (let attempt = 0; attempt < 2; attempt++) {
        const t = await getToken();
        let r;
        try {
          r = await fetchFn(UPLOAD_URL, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${t}`,
              'Content-Type': 'application/json; charset=UTF-8',
              'X-Upload-Content-Length': String(file.size),
            },
            body: JSON.stringify({ name, parents: [folderId] }),
          });
        } catch (e) { throw fail('network', e.message); }
        if (r.status === 401 && attempt === 0) { token = null; continue; } // expired token: refresh once
        const url = r.ok && r.headers.get('Location');
        if (!url) throw fail('session', `session ${r.status}`, { status: r.status });
        return url;
      }
    }

    // One PUT to the session URL; resolves with status, Range header and body text.
    function put(url, body, contentRange, onProgress) {
      return new Promise((resolve, reject) => {
        const x = xhrFactory();
        x.open('PUT', url);
        x.setRequestHeader('Content-Range', contentRange);
        if (onProgress) x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded);
        x.onload = () => resolve({ status: x.status, range: x.getResponseHeader('Range'), text: x.responseText });
        x.onerror = () => reject(fail('network', 'network error'));
        x.send(body);
      });
    }

    // Ask Google how much it already has. Returns { offset } or { id } if the file is complete.
    async function resumeState(item) {
      const r = await put(item.sessionUrl, null, `bytes */${item.file.size}`);
      if (r.status === 200 || r.status === 201) return { id: JSON.parse(r.text).id };
      if (r.status === 308) return { offset: r.range ? parseInt(r.range.split('-')[1], 10) + 1 : 0 };
      throw fail('session', `resume ${r.status}`, { status: r.status });
    }

    // item: { file, sessionUrl?, offset? }. Returns the Drive file id. Safe to call again after a failure.
    async function upload(item, onProgress = () => {}) {
      const total = item.file.size;
      if (!item.sessionUrl) {
        item.sessionUrl = await startSession(item.file);
        item.offset = 0;
      } else {
        const s = await resumeState(item).catch(() => { item.sessionUrl = null; throw fail('session', 'resume failed'); });
        if (s.id) return s.id;
        item.offset = s.offset;
      }
      let attempts = 0;
      for (;;) {
        const start = item.offset;
        const end = Math.min(start + CHUNK, total);
        try {
          const r = await put(item.sessionUrl, item.file.slice(start, end), `bytes ${start}-${end - 1}/${total}`,
            (loaded) => onProgress(Math.min(start + loaded, total) / total));
          if (r.status === 200 || r.status === 201) { onProgress(1); return JSON.parse(r.text).id; }
          if (r.status === 308) {
            item.offset = r.range ? parseInt(r.range.split('-')[1], 10) + 1 : 0;
            attempts = 0;
            if (item.offset >= total) { // everything stored but no final reply seen: ask for the result
              const s = await resumeState(item);
              if (s.id) { onProgress(1); return s.id; }
            }
            continue;
          }
          if (r.status >= 500 || r.status === 429) throw fail('network', `chunk ${r.status}`);
          item.sessionUrl = null; // 4xx (e.g. session expired): start fresh next time
          throw fail('session', `chunk ${r.status}`, { status: r.status });
        } catch (e) {
          if (e.code !== 'network' || ++attempts > 3) throw e;
          await sleep(1000 * 2 ** attempts);
          try {
            const s = await resumeState(item);
            if (s.id) { onProgress(1); return s.id; }
            item.offset = s.offset;
          } catch (_) { /* try the same chunk again */ }
        }
      }
    }

    return { upload, getToken };
  }

  return { CHUNK, MAX_BYTES, MAX_FILES, EXT_OK, extOf, validate, makeName, createClient };
})();

if (typeof module !== 'undefined') module.exports = Uploader;
