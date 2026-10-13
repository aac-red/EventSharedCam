// Encrypts / decrypts the upload credential with the event code.
// PBKDF2-SHA256 (slow on purpose) -> AES-256-GCM. Same file is used by the page and the build script.
const CredCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const toB64 = (u8) => btoa(String.fromCharCode(...u8));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const DEFAULT_ITER = 600000;

  async function deriveKey(code, salt, iter, usage) {
    const base = await crypto.subtle.importKey('raw', enc.encode(String(code).trim()), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, usage);
  }

  async function encrypt(obj, code, iter = DEFAULT_ITER) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(code, salt, iter, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { v: 1, kdf: 'PBKDF2-SHA256', iter, salt: toB64(salt), iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
  }

  // Throws Error('bad_code') for a wrong code or damaged data.
  async function decrypt(blob, code) {
    try {
      if (!blob || blob.v !== 1 || blob.kdf !== 'PBKDF2-SHA256' || !(blob.iter > 0 && blob.iter <= 5000000)) throw 0;
      const key = await deriveKey(code, fromB64(blob.salt), blob.iter, ['decrypt']);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.ct));
      return JSON.parse(dec.decode(pt));
    } catch (_) {
      throw new Error('bad_code');
    }
  }

  return { encrypt, decrypt, DEFAULT_ITER };
})();

if (typeof module !== 'undefined') module.exports = CredCrypto;
