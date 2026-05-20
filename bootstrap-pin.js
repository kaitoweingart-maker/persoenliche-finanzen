#!/usr/bin/env node
/*
 * bootstrap-pin.js — Persönliche Finanzen
 *
 * Erzeugt pin-bootstrap.js aus einem im Terminal eingegebenen PIN.
 * PIN landet NICHT in der Ausgabedatei und NICHT in diesem Script.
 * Aufruf (PIN wird unsichtbar abgefragt):
 *   read -s -p 'PIN: ' P; echo; printf '%s' "$P" | node bootstrap-pin.js
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAGIC_PLAIN = 'FINANZEN_UNLOCKED_2026';
const PBKDF2_ITER = 150000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32;
const OUT_FILE = path.join(__dirname, 'pin-bootstrap.js');

const pin = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
if (!/^\d{6,}$/.test(pin)) {
  console.error('Fehler: PIN muss mindestens 6 Ziffern haben (nur Ziffern).');
  process.exit(1);
}

const salt = crypto.randomBytes(SALT_BYTES);
const key = crypto.pbkdf2Sync(pin, salt, PBKDF2_ITER, KEY_BYTES, 'sha256');
const iv = crypto.randomBytes(IV_BYTES);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(MAGIC_PLAIN, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();
const ctWithTag = Buffer.concat([ct, tag]);
const magic = Buffer.from(JSON.stringify({
  iv: Array.from(iv),
  ct: Array.from(ctWithTag),
})).toString('base64');

const payload = {
  version: 1,
  createdAt: new Date().toISOString(),
  iterations: PBKDF2_ITER,
  salt: Array.from(salt),
  magic,
};

const out =
  '/* Auto-generiert von bootstrap-pin.js. PIN ist hier NICHT enthalten. */\n' +
  'window.__PIN_BOOTSTRAP__ = ' + JSON.stringify(payload, null, 2) + ';\n';
fs.writeFileSync(OUT_FILE, out);
console.log('OK — pin-bootstrap.js geschrieben (' + OUT_FILE + ').');
