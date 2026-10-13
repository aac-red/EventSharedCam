#!/usr/bin/env node
// Run on YOUR computer, not on the web. Encrypts the service account key with the event code.
//
//   node encrypt-credential.js service-account.json --folder <FOLDER_ID> [--event-name oktoberfest] [--code <CODE>] [--out credential.enc.json]
//
// If --code is omitted, a long random event code is generated and printed once.
// Only credential.enc.json is meant for GitHub. Never commit service-account.json.

const fs = require('fs');
globalThis.crypto ??= require('node:crypto').webcrypto; // Node 18
const CredCrypto = require('./credcrypto.js');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : undefined;
}
const keyFile = process.argv[2];
const folderId = arg('--folder');
const eventName = arg('--event-name') || 'oktoberfest';
const out = arg('--out') || 'credential.enc.json';
let code = arg('--code');

if (!keyFile || keyFile.startsWith('--') || !folderId) {
  console.error('Usage: node encrypt-credential.js service-account.json --folder <FOLDER_ID> [--event-name NAME] [--code CODE] [--out FILE]');
  process.exit(1);
}

let key;
try { key = JSON.parse(fs.readFileSync(keyFile, 'utf8')); } catch (e) { console.error('Cannot read the key file:', e.message); process.exit(1); }
if (!key.client_email || !key.private_key) { console.error('That file is not a service account key (needs client_email and private_key).'); process.exit(1); }

if (!code) {
  // 20 characters from a 32-symbol alphabet without look-alikes = 100 bits.
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  code = [...crypto.getRandomValues(new Uint8Array(20))].map((b) => A[b % 32]).join('');
} else if (code.length < 16) {
  console.error('Event code too short. Use at least 16 random characters (or omit --code to generate one).');
  process.exit(1);
}

(async () => {
  // Only what the page needs; the rest of the key file is left out.
  const payload = { client_email: key.client_email, private_key: key.private_key, folderId, eventName };
  const blob = await CredCrypto.encrypt(payload, code);
  fs.writeFileSync(out, JSON.stringify(blob));
  console.log(`Wrote ${out} (${fs.statSync(out).size} bytes).`);
  console.log(`\nEVENT CODE (shown once, keep it safe): ${code}`);
  console.log(`Guest link: https://<username>.github.io/<repo>/?event=${code}`);
})();
