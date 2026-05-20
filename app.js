/* ============================================================
 * Persönliche Finanzen — MVP v1.0
 * Vanilla JS, AES-GCM-verschlüsselter localStorage, PIN-Login.
 * ============================================================ */

/* ===== Stammdaten ===== */
const CURRENCIES = ['CHF', 'EUR', 'USD', 'GBP', 'HKD', 'JPY'];
const KV_KATEGORIEN = ['Kreditkarte', 'Konsumkredit', 'Rechnung', 'Privatdarlehen', 'Steuern', 'Sonstiges'];
const LV_KATEGORIEN = ['Hypothek', 'Konsumkredit', 'Leasing', 'Studiendarlehen', 'Sonstiges'];
const LV_ZINSTYPEN = ['Fest', 'Variabel', 'SARON'];
const EIN_KATEGORIEN = ['Lohn', 'Bonus', 'Mieteinnahme', 'Dividende', 'Rente', 'Nebeneinkommen', 'Sonstiges'];
const AUS_KATEGORIEN = ['Wohnen', 'Versicherung', 'Abo', 'Lebenshaltung', 'Mobilität', 'Freizeit', 'Steuern', 'Gesundheit', 'Sonstiges'];
const FREQUENZ = ['Monatlich', 'Quartal', 'Halbjährlich', 'Jährlich', 'Einmalig'];
const FREQUENZ_FAKTOR = { Monatlich: 1, Quartal: 1 / 3, Halbjährlich: 1 / 6, Jährlich: 1 / 12, Einmalig: 0 };
const ZAHLUNGSMETHODEN = ['Dauerauftrag', 'LSV', 'Kreditkarte', 'Manuell'];
const INV_KATEGORIEN = ['Aktie', 'Fonds', 'ETF', 'Anleihe', 'Krypto', 'Säule 3a', 'Vorsorge', 'Cash', 'Sonstiges'];
const PLAN_TYPEN = ['RSU', 'PSU', 'Option', 'ESPP', 'Restricted Shares', 'Sonstiges'];
const VESTING_RHYTHMUS = ['Monatlich', 'Quartal', 'Jährlich'];

const KV_STATUS = ['Offen', 'Teilweise getilgt', 'Beglichen'];
const LV_STATUS = ['Aktiv', 'Abgelöst', 'In Refinanzierung'];
const EIN_STATUS = ['Aktiv', 'Pausiert', 'Beendet'];
const AUS_STATUS = ['Aktiv', 'Pausiert', 'Gekündigt'];
const INV_STATUS = ['Im Portfolio', 'Verkauft'];
const PLAN_STATUS = ['Aktiv', 'Vollständig gevestet', 'Verkauft', 'Verfallen'];
const FIXVAR = ['Fix', 'Variabel'];

const STATUS_COLORS = {
  'Offen': 'yellow', 'Teilweise getilgt': 'blue', 'Beglichen': 'green',
  'Aktiv': 'green', 'Pausiert': 'gray', 'Beendet': 'gray', 'Gekündigt': 'gray',
  'Abgelöst': 'green', 'In Refinanzierung': 'yellow',
  'Im Portfolio': 'green', 'Verkauft': 'gray',
  'Vollständig gevestet': 'blue', 'Verfallen': 'red',
};

/* ===== FX Rates (frankfurter.app, ECB-basiert) ===== */
const FX = {
  STORAGE_KEY: 'fin_fx_rates',
  TTL_MS: 6 * 60 * 60 * 1000, // 6h
  rates: { CHF: 1, EUR: 1.04, USD: 0.91, GBP: 0.85, HKD: 8.45, JPY: 175.50 }, // Fallback
  date: '—',
  source: 'fallback',

  loadFromStorage() {
    try {
      const obj = JSON.parse(localStorage.getItem(this.STORAGE_KEY) || 'null');
      if (obj && obj.rates && obj.rates.CHF) {
        this.rates = obj.rates;
        this.date = obj.date;
        this.source = 'cache';
        return obj.ts || 0;
      }
    } catch (_) {}
    return 0;
  },

  async fetchLive() {
    try {
      const r = await fetch('https://api.frankfurter.app/latest?from=CHF');
      if (!r.ok) throw new Error('FX API ' + r.status);
      const data = await r.json();
      this.rates = { CHF: 1, ...data.rates };
      this.date = data.date;
      this.source = 'live';
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify({ rates: this.rates, date: data.date, ts: Date.now() }));
      return true;
    } catch (e) {
      console.warn('FX fetch failed:', e.message);
      return false;
    }
  },

  init() {
    const ts = this.loadFromStorage();
    const stale = !ts || (Date.now() - ts > this.TTL_MS);
    if (stale) {
      this.fetchLive().then(ok => {
        if (ok && App && !App.locked && App.currentView === 'dashboard') render();
      });
    }
  },

  toCHF(value, currency) {
    if (value === null || value === undefined) return 0;
    if (!currency || currency === 'CHF') return value;
    const rate = this.rates[currency];
    if (!rate || rate === 0) return value;
    return value / rate;
  },
};

/* ===== Crypto layer (Web Crypto API) ===== */
const Crypto = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),

  async deriveKey(pin, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', this.enc.encode(pin), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, this.enc.encode(plaintext));
    return this.b64({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
  },

  async decrypt(key, payload) {
    const { iv, ct } = this.unb64(payload);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(ct)
    );
    return this.dec.decode(pt);
  },

  b64(obj) { return btoa(JSON.stringify(obj)); },
  unb64(s) { return JSON.parse(atob(s)); },

  randomSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  },
};

/* ===== Auth ===== */
const Auth = {
  STORAGE_KEYS: {
    salt: 'fin_salt',
    magic: 'fin_magic',
    attempts: 'fin_attempts',
    lockUntil: 'fin_lockuntil',
    pinChangedAt: 'fin_pinchanged',
    recovery: 'fin_recovery_email',
  },
  MAGIC_PLAIN: 'FINANZEN_UNLOCKED_2026',
  MAX_ATTEMPTS: 5,
  LOCK_MS: 15 * 60 * 1000,
  IDLE_MS: 15 * 60 * 1000,
  key: null,

  isSetup() { return !!localStorage.getItem(this.STORAGE_KEYS.salt); },

  getSalt() {
    const s = localStorage.getItem(this.STORAGE_KEYS.salt);
    if (!s) return null;
    return new Uint8Array(JSON.parse(s));
  },

  setSalt(salt) {
    localStorage.setItem(this.STORAGE_KEYS.salt, JSON.stringify(Array.from(salt)));
  },

  lockUntil() {
    const v = localStorage.getItem(this.STORAGE_KEYS.lockUntil);
    return v ? parseInt(v, 10) : 0;
  },
  isLocked() { return this.lockUntil() > Date.now(); },
  remainingLockMs() { return Math.max(0, this.lockUntil() - Date.now()); },

  attempts() {
    return parseInt(localStorage.getItem(this.STORAGE_KEYS.attempts) || '0', 10);
  },
  recordFail() {
    const a = this.attempts() + 1;
    localStorage.setItem(this.STORAGE_KEYS.attempts, String(a));
    if (a >= this.MAX_ATTEMPTS) {
      this.detonate();
    }
    return a;
  },

  detonate() {
    Store.clearAll();
    try { sessionStorage.setItem('fin_detonated', '1'); } catch (_) {}
    setTimeout(() => location.reload(), 50);
  },
  resetFails() {
    localStorage.removeItem(this.STORAGE_KEYS.attempts);
    localStorage.removeItem(this.STORAGE_KEYS.lockUntil);
  },

  async setupPin(pin) {
    const salt = Crypto.randomSalt();
    const key = await Crypto.deriveKey(pin, salt);
    const magic = await Crypto.encrypt(key, this.MAGIC_PLAIN);
    this.setSalt(salt);
    localStorage.setItem(this.STORAGE_KEYS.magic, magic);
    localStorage.setItem(this.STORAGE_KEYS.pinChangedAt, new Date().toISOString());
    this.key = key;
    return key;
  },

  async verifyPin(pin) {
    if (this.isLocked()) return false;
    const salt = this.getSalt();
    if (!salt) return false;
    const magic = localStorage.getItem(this.STORAGE_KEYS.magic);
    if (!magic) return false;
    try {
      const key = await Crypto.deriveKey(pin, salt);
      const plain = await Crypto.decrypt(key, magic);
      if (plain === this.MAGIC_PLAIN) {
        this.key = key;
        this.resetFails();
        return true;
      }
    } catch (_) { /* wrong PIN */ }
    this.recordFail();
    return false;
  },

  async changePin(oldPin, newPin) {
    if (!await this.verifyPin(oldPin)) throw new Error('Aktuelle PIN falsch');
    // Re-encrypt all data with new key
    const dump = await Store.exportPlain();
    await this.setupPin(newPin);
    await Store.importPlain(dump);
  },

  lock() {
    this.key = null;
    App.locked = true;
    showLogin();
  },
};

/* ===== Store (encrypted) ===== */
const Store = {
  CACHE: {}, // in-memory after unlock
  STORES: ['kv', 'lv', 'einkuenfte', 'ausgaben', 'investments', 'aktienplaene', 'counters', 'settings'],

  storageKey(name) { return 'fin_' + name; },

  async loadAll() {
    for (const name of this.STORES) {
      this.CACHE[name] = await this.load(name);
    }
    if (!this.CACHE.counters) this.CACHE.counters = {};
    if (!this.CACHE.settings) this.CACHE.settings = { autoLock: 15, currency: 'CHF', concentrationLimit: 30 };
  },

  async load(name) {
    const raw = localStorage.getItem(this.storageKey(name));
    if (!raw) return name === 'counters' || name === 'settings' ? null : [];
    try {
      const pt = await Crypto.decrypt(Auth.key, raw);
      return JSON.parse(pt);
    } catch (e) {
      console.error('Decrypt failed', name, e);
      return name === 'counters' || name === 'settings' ? null : [];
    }
  },

  async save(name, data) {
    this.CACHE[name] = data;
    const pt = JSON.stringify(data);
    const ct = await Crypto.encrypt(Auth.key, pt);
    localStorage.setItem(this.storageKey(name), ct);
  },

  get(name) { return this.CACHE[name]; },

  nextId(prefix) {
    const c = this.CACHE.counters || {};
    const year = new Date().getFullYear();
    const key = `${prefix}-${year}`;
    c[key] = (c[key] || 0) + 1;
    this.save('counters', c);
    return `${prefix}-${year}-${String(c[key]).padStart(4, '0')}`;
  },

  async exportPlain() {
    const out = {};
    for (const name of this.STORES) out[name] = this.CACHE[name];
    return out;
  },

  async importPlain(data) {
    for (const name of this.STORES) {
      if (data[name] !== undefined) {
        await this.save(name, data[name]);
      }
    }
  },

  exportEncryptedBackup() {
    const payload = {
      version: 1,
      exportedAt: new Date().toISOString(),
      salt: localStorage.getItem(Auth.STORAGE_KEYS.salt),
      magic: localStorage.getItem(Auth.STORAGE_KEYS.magic),
      pinChangedAt: localStorage.getItem(Auth.STORAGE_KEYS.pinChangedAt),
    };
    for (const name of this.STORES) {
      payload[name] = localStorage.getItem(this.storageKey(name));
    }
    return payload;
  },

  importEncryptedBackup(payload) {
    if (payload.salt) localStorage.setItem(Auth.STORAGE_KEYS.salt, payload.salt);
    if (payload.magic) localStorage.setItem(Auth.STORAGE_KEYS.magic, payload.magic);
    if (payload.pinChangedAt) localStorage.setItem(Auth.STORAGE_KEYS.pinChangedAt, payload.pinChangedAt);
    for (const name of this.STORES) {
      if (payload[name]) localStorage.setItem(this.storageKey(name), payload[name]);
    }
  },

  clearAll() {
    for (const name of this.STORES) localStorage.removeItem(this.storageKey(name));
    Object.values(Auth.STORAGE_KEYS).forEach(k => localStorage.removeItem(k));
    this.CACHE = {};
  },
};

/* ===== App State ===== */
const App = {
  currentView: 'dashboard',
  selectedId: null,
  filters: {},
  searchTerm: '',
  idleTimer: null,
  locked: true,
};

/* ===== Utilities ===== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (v === null || v === undefined) return;
    if (k === 'className') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => e.dataset[dk] = dv);
    else if (typeof v === 'boolean') { if (v) e.setAttribute(k, ''); }
    else e.setAttribute(k, v);
  });
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

function chf(v, opts = {}) {
  if (v === null || v === undefined || isNaN(v)) return '–';
  const { sign = false, decimals = 0 } = opts;
  const n = Number(v);
  const s = new Intl.NumberFormat('de-CH', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(Math.abs(n));
  const pre = n < 0 ? '−' : (sign && n > 0 ? '+' : '');
  return `${pre}CHF ${s}`;
}
function num(v, decimals = 0) {
  if (v === null || v === undefined || isNaN(v)) return '–';
  return new Intl.NumberFormat('de-CH', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(Number(v));
}
function pct(v, decimals = 1) {
  if (v === null || v === undefined || isNaN(v)) return '–';
  return `${num(v, decimals)} %`;
}
function fmtDate(s) {
  if (!s) return '–';
  const d = new Date(s);
  if (isNaN(d.getTime())) return '–';
  return d.toLocaleDateString('de-CH');
}
function daysUntil(s) {
  if (!s) return null;
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return Math.ceil((d - Date.now()) / 86400000);
}
function todayISO() { return new Date().toISOString().slice(0, 10); }
function uid() { return crypto.randomUUID(); }

function showToast(msg, kind = 'ok') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + kind;
  setTimeout(() => t.classList.remove('show'), 2400);
}

function openModal(content) {
  const m = $('#modal');
  $('#modalContent').innerHTML = '';
  if (typeof content === 'string') $('#modalContent').innerHTML = content;
  else $('#modalContent').appendChild(content);
  m.showModal();
}
function closeModal() { $('#modal').close(); }

/* ===== Bootstrap ===== */
function ensureBootstrapped() {
  if (Auth.isSetup()) return true;
  const b = window.__PIN_BOOTSTRAP__;
  if (!b || !b.salt || !b.magic) return false;
  localStorage.setItem(Auth.STORAGE_KEYS.salt, JSON.stringify(b.salt));
  localStorage.setItem(Auth.STORAGE_KEYS.magic, b.magic);
  return true;
}

/* ===== Login Flow ===== */
function showLogin() {
  $('#appShell').classList.add('hidden');
  $('#loginScreen').classList.remove('hidden');
  const sub = $('#loginSub');
  const detonated = (() => { try { return sessionStorage.getItem('fin_detonated') === '1'; } catch (_) { return false; } })();
  if (detonated) {
    sub.textContent = 'Datenbank wurde nach zu vielen Fehlversuchen gelöscht.';
    try { sessionStorage.removeItem('fin_detonated'); } catch (_) {}
  } else if (!Auth.isSetup()) {
    sub.textContent = 'Nicht initialisiert — bootstrap-pin.js im Terminal ausführen.';
    $('#loginSubmit').disabled = true;
    return;
  } else {
    sub.textContent = 'Bitte sechsstelligen Zahlencode eingeben';
  }
  $('#loginSubmit').textContent = 'Anmelden';
  refreshLockState();
  clearPinInputs();
  setTimeout(() => $('.pin-row input[data-i="0"]')?.focus(), 50);
}

function clearPinInputs() {
  $$('.pin-row input').forEach(i => i.value = '');
  $('#loginMsg').textContent = '';
  $('#loginMsg').className = 'login-msg';
}

function readPinInputs() {
  return $$('.pin-row input').map(i => i.value).join('');
}

function refreshLockState() {
  $('#loginSubmit').disabled = false;
  $$('.pin-row input').forEach(i => i.disabled = false);
}

function keypadInsertDigit(d) {
  const inputs = $$('.pin-row input');
  for (let i = 0; i < inputs.length; i++) {
    if (!inputs[i].value) {
      inputs[i].value = d;
      const next = inputs[i + 1];
      if (next) next.focus(); else inputs[i].blur();
      if (i === inputs.length - 1) $('#pinForm').requestSubmit();
      return;
    }
  }
}
function keypadBackspace() {
  const inputs = $$('.pin-row input');
  for (let i = inputs.length - 1; i >= 0; i--) {
    if (inputs[i].value) {
      inputs[i].value = '';
      inputs[i].focus();
      return;
    }
  }
}
function setupKeypadHandlers() {
  const pad = $('#pinKeypad');
  if (!pad) return;
  pad.addEventListener('click', e => {
    const btn = e.target.closest('button.key');
    if (!btn) return;
    if (btn.dataset.digit) keypadInsertDigit(btn.dataset.digit);
    else if (btn.dataset.action === 'backspace') keypadBackspace();
    else if (btn.dataset.action === 'submit') $('#pinForm').requestSubmit();
  });
}

function setupPinHandlers() {
  setupKeypadHandlers();
  const inputs = $$('.pin-row input');
  inputs.forEach((inp, idx) => {
    inp.addEventListener('input', e => {
      const v = inp.value.replace(/\D/g, '');
      inp.value = v.slice(0, 1);
      if (inp.value && idx < inputs.length - 1) inputs[idx + 1].focus();
      if (idx === inputs.length - 1 && readPinInputs().length === 6) {
        $('#pinForm').requestSubmit();
      }
    });
    inp.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !inp.value && idx > 0) {
        inputs[idx - 1].focus();
      }
      if (e.key === 'ArrowLeft' && idx > 0) inputs[idx - 1].focus();
      if (e.key === 'ArrowRight' && idx < inputs.length - 1) inputs[idx + 1].focus();
    });
    inp.addEventListener('paste', e => {
      e.preventDefault();
      const txt = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
      [...txt].forEach((c, i) => { if (inputs[i]) inputs[i].value = c; });
      const last = Math.min(txt.length, inputs.length) - 1;
      if (last >= 0) inputs[Math.min(last + 1, inputs.length - 1)].focus();
      if (txt.length === 6) $('#pinForm').requestSubmit();
    });
  });

  $('#pinForm').addEventListener('submit', async e => {
    e.preventDefault();
    const pin = readPinInputs();
    if (pin.length !== 6) {
      $('#loginMsg').textContent = 'Bitte 6 Ziffern eingeben.';
      return;
    }
    if (!Auth.isSetup()) { $('#loginMsg').textContent = 'Nicht initialisiert.'; return; }
    const ok = await Auth.verifyPin(pin);
    if (ok) {
      await unlockAndShow();
    } else {
      const tries = Auth.MAX_ATTEMPTS - Auth.attempts();
      if (tries <= 0) return;
      $('#loginMsg').textContent = `Falscher Code – noch ${tries} Versuch${tries === 1 ? '' : 'e'}. Nach 0 wird die Datenbank gelöscht.`;
      $('#pinRow').classList.add('shake');
      setTimeout(() => $('#pinRow').classList.remove('shake'), 500);
      clearPinInputs();
      $('.pin-row input[data-i="0"]').focus();
    }
  });

  $('#forgotBtn').addEventListener('click', () => {
    const wizard = el('div', {},
      el('h3', {}, 'PIN vergessen – Backup wiederherstellen'),
      el('p', { className: 'small' }, 'Wenn Sie eine Backup-Datei heruntergeladen haben, können Sie diese mit der damals verwendeten PIN hochladen. Ohne Backup sind die Daten unwiderruflich verloren.'),
      el('input', { type: 'file', accept: '.json', id: 'restoreFile', className: 'mt-2' }),
      el('div', { className: 'form-actions' },
        el('button', { className: 'btn', onClick: closeModal }, 'Abbrechen'),
        el('button', { className: 'btn primary', onClick: async () => {
          const f = $('#restoreFile').files[0];
          if (!f) { showToast('Keine Datei gewählt', 'err'); return; }
          try {
            const txt = await f.text();
            const data = JSON.parse(txt);
            if (data.version !== 1 || !data.salt) {
              showToast('Backup-Format ungültig', 'err'); return;
            }
            Store.importEncryptedBackup(data);
            closeModal();
            showLogin();
            showToast('Backup geladen – jetzt mit ursprünglicher PIN anmelden');
          } catch (e) {
            showToast('Fehler beim Laden: ' + e.message, 'err');
          }
        }}, 'Hochladen')
      ),
      el('hr', { className: 'mt-2' }),
      el('p', { className: 'small mt-2' }, 'Vollständig zurücksetzen (alle Daten löschen):'),
      el('button', { className: 'btn danger', onClick: () => {
        if (confirm('Wirklich ALLE Daten und PIN löschen? Diese Aktion ist nicht rückgängig zu machen.')) {
          Store.clearAll();
          closeModal();
          showLogin();
          showToast('Alles gelöscht – Ersteinrichtung erneut möglich');
        }
      }}, 'Komplett zurücksetzen')
    );
    openModal(wizard);
  });
}

/* ===== Idle timer ===== */
function resetIdleTimer() {
  if (App.idleTimer) clearTimeout(App.idleTimer);
  const mins = Store.get('settings')?.autoLock ?? 15;
  if (mins <= 0) return;
  App.idleTimer = setTimeout(() => {
    Auth.lock();
    showToast('Automatisch gesperrt');
  }, mins * 60000);
}
function installIdleHandlers() {
  ['mousemove', 'keydown', 'click', 'touchstart'].forEach(ev =>
    document.addEventListener(ev, resetIdleTimer, { passive: true })
  );
}

/* ===== Unlock & main app boot ===== */
async function unlockAndShow() {
  await Store.loadAll();
  App.locked = false;
  $('#loginScreen').classList.add('hidden');
  $('#appShell').classList.remove('hidden');
  resetIdleTimer();
  FX.init();
  // Offer demo data on first unlock if completely empty
  const allEmpty = ['kv', 'lv', 'einkuenfte', 'ausgaben', 'investments', 'aktienplaene']
    .every(k => (Store.get(k) || []).length === 0);
  const offered = Store.get('settings')?.demoOffered;
  if (allEmpty && !offered) {
    setTimeout(() => offerDemoData(), 400);
  }
  render();
}

function offerDemoData() {
  const card = el('div', {},
    el('h3', {}, '👋 Willkommen!'),
    el('p', {}, 'Möchten Sie mit Demo-Daten starten, um die App auszuprobieren? Sie können diese jederzeit über das ⋯-Menü zurücksetzen.'),
    el('div', { className: 'form-actions' },
      el('button', { className: 'btn ghost', onClick: async () => {
        const s = Store.get('settings'); s.demoOffered = true; await Store.save('settings', s);
        closeModal();
      }}, 'Nein, leer starten'),
      el('button', { className: 'btn primary', onClick: async () => {
        await loadDemoData();
        const s = Store.get('settings'); s.demoOffered = true; await Store.save('settings', s);
        closeModal();
        render();
        showToast('Demo-Daten geladen');
      }}, 'Demo-Daten laden')
    )
  );
  openModal(card);
}

/* ===== Demo data ===== */
async function loadDemoData() {
  const today = new Date();
  const iso = d => d.toISOString().slice(0, 10);
  const inDays = n => { const d = new Date(today); d.setDate(d.getDate() + n); return iso(d); };
  const inMonths = n => { const d = new Date(today); d.setMonth(d.getMonth() + n); return iso(d); };

  await Store.save('kv', [
    { id: Store.nextId('KV'), bezeichnung: 'Kreditkarte', kategorie: 'Kreditkarte', glaeubiger: '', ursprung: 9900, saldo: 9900, currency: 'CHF', zins: 0, faellig: inDays(30), mindestrate: null, status: 'Offen', notizen: '', payments: [] },
    { id: Store.nextId('KV'), bezeichnung: 'Privatkredit', kategorie: 'Privatdarlehen', glaeubiger: '', ursprung: 18984, saldo: 18984, currency: 'CHF', zins: 10.6, faellig: inDays(365), mindestrate: null, status: 'Offen', notizen: '10.6 % Zins', payments: [] },
    { id: Store.nextId('KV'), bezeichnung: 'Steuern', kategorie: 'Steuern', glaeubiger: 'Steueramt', ursprung: 5318.05, saldo: 5318.05, currency: 'CHF', zins: 0, faellig: inDays(60), mindestrate: null, status: 'Offen', notizen: '', payments: [] },
  ]);
  await Store.save('lv', []);
  await Store.save('einkuenfte', []);
  await Store.save('ausgaben', []);
  await Store.save('investments', [
    { id: Store.nextId('I'), bezeichnung: 'Vanguard FTSE All-World UCITS ETF', kategorie: 'ETF', ticker: 'VWRL.AS', broker: '', anzahl: 20, kaufpreis: 136.94, investTotal: 2738.80, kurs: 154.78, aktuellerWert: 3094.18, currency: 'EUR', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: 'Kaufdatum geschätzt; Quelle: Yahoo Finance App', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Alibaba Group Holding', kategorie: 'Aktie', ticker: '9988.HK', broker: '', anzahl: 100, kaufpreis: 123.68, investTotal: 12368, kurs: 131.90, aktuellerWert: 13188.39, currency: 'HKD', kaufdatum: '2024-06-01', dividende: null, status: 'Im Portfolio', notizen: 'Kaufdatum geschätzt; Quelle: Yahoo Finance App', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Mizuho Financial Group', kategorie: 'Aktie', ticker: '8411.T', broker: '', anzahl: 100, kaufpreis: 2486.31, investTotal: 248631, kurs: 6982.00, aktuellerWert: 697444.14, currency: 'JPY', kaufdatum: '2021-01-01', dividende: null, status: 'Im Portfolio', notizen: 'Kaufdatum geschätzt aus +180 % Gewinn; Quelle: Yahoo Finance App', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Rakuten Group', kategorie: 'Aktie', ticker: '4755.T', broker: '', anzahl: 1200, kaufpreis: 800.05, investTotal: 960060, kurs: 784.00, aktuellerWert: 940563.81, currency: 'JPY', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: 'Kaufdatum geschätzt; Quelle: Yahoo Finance App', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Darlehen Amanthos Hotel AG', kategorie: 'Anleihe', ticker: '', broker: '', anzahl: null, kaufpreis: null, investTotal: 50000, kurs: null, aktuellerWert: 50000, currency: 'CHF', kaufdatum: '2024-01-01', dividende: 3.5, status: 'Im Portfolio', notizen: 'Aktionärsdarlehen, 3.5 % Zins p.a.', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Darlehen Amanthos Living AG', kategorie: 'Anleihe', ticker: '', broker: '', anzahl: null, kaufpreis: null, investTotal: 50000, kurs: null, aktuellerWert: 50000, currency: 'CHF', kaufdatum: '2024-01-01', dividende: 3.5, status: 'Im Portfolio', notizen: 'Aktionärsdarlehen, 3.5 % Zins p.a.', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Beteiligung Amanthos Hotel AG (2.5 %)', kategorie: 'Aktie', ticker: '', broker: '', anzahl: null, kaufpreis: null, investTotal: 50000, kurs: null, aktuellerWert: 50000, currency: 'CHF', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: '2.5 % Anteil an Amanthos Hotel AG', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Beteiligung Amanthos Living AG (2.5 %)', kategorie: 'Aktie', ticker: '', broker: '', anzahl: null, kaufpreis: null, investTotal: 50000, kurs: null, aktuellerWert: 50000, currency: 'CHF', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: '2.5 % Anteil an Amanthos Living AG', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Forderung Lohn / Provisionseinkünfte', kategorie: 'Sonstiges', ticker: '', broker: '', anzahl: null, kaufpreis: null, investTotal: 90000, kurs: null, aktuellerWert: 90000, currency: 'CHF', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: 'Offene Forderung für ausstehende Lohn- und Provisionsauszahlungen', transactions: [] },
    { id: Store.nextId('I'), bezeichnung: 'Hive Blockchain Technologies', kategorie: 'Aktie', ticker: 'HIVE', broker: '', anzahl: 1890, kaufpreis: 2.20, investTotal: 4158, kurs: 3.36, aktuellerWert: 6350.40, currency: 'USD', kaufdatum: '2024-01-01', dividende: null, status: 'Im Portfolio', notizen: 'Crypto-Mining-Aktie · +52.46 % Stand bei Eingabe', transactions: [] },
  ]);
  await Store.save('aktienplaene', []);
}

/* ===== Rendering / Routing ===== */
function render() {
  const view = App.currentView;
  $$('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  const root = $('#app');
  root.innerHTML = '';
  const fn = VIEWS[view];
  if (fn) fn(root);
}

function navigate(view, opts = {}) {
  App.currentView = view;
  App.selectedId = opts.selectedId || null;
  render();
}

/* =====================================================================
 * VIEWS
 * ===================================================================== */
const VIEWS = {};

/* ----- DASHBOARD ----- */
VIEWS.dashboard = function (root) {
  const kpis = computeKPIs();
  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Netto-Vermögen', chf(kpis.nettoVermoegen), `Vermögen − Schulden`, kpis.nettoVermoegen >= 0 ? 'positive' : 'negative'),
    kpi('Monatl. Cashflow', chf(kpis.cashflow, { sign: true }), `Einkünfte − Ausgaben`, kpis.cashflow >= 0 ? 'positive' : 'negative'),
    kpi('Sparquote', pct(kpis.sparquote), `vom Netto-Einkommen`, kpis.sparquote >= 10 ? 'positive' : (kpis.sparquote < 0 ? 'negative' : 'warn')),
    kpi('Schuldendienst-Quote', pct(kpis.schuldendienstQuote), `Zins+Tilgung / Einkünfte`, kpis.schuldendienstQuote > 33 ? 'negative' : (kpis.schuldendienstQuote > 15 ? 'warn' : 'positive')),
  ));

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Aktive Verbindlichkeiten', chf(kpis.schuldenTotal), `${kpis.kvCount + kpis.lvCount} Positionen`),
    kpi('KV-Schulden abgebaut', chf(kpis.kvAbgebaut), 'kurzfristig getilgt seit Erfassung', kpis.kvAbgebaut > 0 ? 'positive' : ''),
    kpi('Investments', chf(kpis.investWert), `Buchgewinn: ${chf(kpis.investGewinn, { sign: true })}`, kpis.investGewinn >= 0 ? 'positive' : 'negative'),
    kpi('Gevestete Aktien', chf(kpis.vestedWert), `${num(kpis.vestedAnzahl, 0)} Stück (gevestet)`),
    kpi('Mtl. Einkünfte', chf(kpis.einkuenfteMonat), 'inkl. anteiliger Boni'),
  ));

  // FX-Status (zeigt verwendete Umrechnungskurse)
  const usedCurrencies = new Set();
  (Store.get('investments') || []).forEach(i => { if (i.currency && i.currency !== 'CHF') usedCurrencies.add(i.currency); });
  if (usedCurrencies.size > 0) {
    const srcLabel = FX.source === 'live' ? 'Live (ECB)' : FX.source === 'cache' ? 'Cache' : 'Fallback';
    const srcCls = FX.source === 'live' ? 'tag green' : FX.source === 'cache' ? 'tag blue' : 'tag yellow';
    const ratesRow = el('div', { className: 'fx-rates' });
    [...usedCurrencies].sort().forEach(c => {
      const rate = FX.rates[c];
      if (rate) ratesRow.appendChild(el('span', { className: 'fx-pair' },
        el('span', { className: 'mono' }, `1 ${c}`),
        el('span', { className: 'muted' }, ' = '),
        el('span', { className: 'mono' }, num(1 / rate, 4)),
        el('span', { className: 'muted' }, ' CHF')
      ));
    });
    root.appendChild(el('div', { className: 'card fx-card' },
      el('div', { className: 'fx-head' },
        el('span', { className: 'fx-title' }, 'Live-CHF-Umrechnung'),
        el('span', { className: srcCls }, srcLabel),
        el('span', { className: 'small muted' }, `Stand ${FX.date}`),
        el('button', { className: 'btn small', onClick: async () => { await FX.fetchLive(); render(); } }, '↻ Aktualisieren')
      ),
      ratesRow,
      el('div', { className: 'small muted mt-1' }, 'Quelle: frankfurter.app (Europäische Zentralbank). Alle Investments-KPIs werden für die Anzeige in CHF umgerechnet.')
    ));
  }

  // Pivoting-Vorschläge für ausgeglichenes Portfolio
  const sugs = computeSuggestions(kpis);
  root.appendChild(el('div', { className: 'card sugg-card' },
    el('h2', {}, 'Vorschläge zur Balance', el('span', { className: 'small' }, `${sugs.length} Hinweis${sugs.length === 1 ? '' : 'e'}`)),
    el('div', { className: 'sugg-list' },
      ...sugs.map(s => el('div', { className: 'sugg sugg-' + s.type },
        el('div', { className: 'sugg-title' }, s.title),
        el('div', { className: 'sugg-msg' }, s.msg)
      ))
    )
  ));

  const grid = el('div', { className: 'two-col' });

  // Anstehende Fälligkeiten (30 Tage)
  const upcomingPayments = computeUpcomingPayments(30);
  grid.appendChild(el('div', { className: 'card' },
    el('h2', {}, 'Anstehende Fälligkeiten (30 Tage)', el('span', { className: 'small' }, `${upcomingPayments.length} Pos.`)),
    upcomingPayments.length === 0
      ? el('p', { className: 'muted small' }, 'Keine fälligen Positionen in den nächsten 30 Tagen.')
      : (() => {
        const tbl = el('table', {});
        const tb = el('tbody', {});
        upcomingPayments.slice(0, 8).forEach(p => {
          const days = daysUntil(p.faellig);
          const cls = days <= 0 ? 'overdue' : days <= 7 ? 'due-now' : days <= 14 ? 'due-soon' : '';
          tb.appendChild(el('tr', { onClick: () => navigate(p.view, { selectedId: p.id }) },
            el('td', {}, el('span', { className: cls }, days < 0 ? 'überfällig' : (days === 0 ? 'heute' : `in ${days} T.`))),
            el('td', {}, p.bezeichnung),
            el('td', { className: 'num' }, chf(p.betrag))
          ));
        });
        tbl.appendChild(el('thead', {}, el('tr', {}, el('th', {}, 'Fällig'), el('th', {}, 'Position'), el('th', {}, 'Betrag'))));
        tbl.appendChild(tb);
        return tbl;
      })()
  ));

  // Bevorstehende Vesting Tranchen
  const vesting = computeUpcomingVesting(90);
  grid.appendChild(el('div', { className: 'card' },
    el('h2', {}, 'Bevorstehende Vesting-Tranchen (90 T.)', el('span', { className: 'small' }, `${vesting.length} Tranchen`)),
    vesting.length === 0
      ? el('p', { className: 'muted small' }, 'Keine anstehenden Vesting-Tranchen.')
      : (() => {
        const tbl = el('table', {});
        const tb = el('tbody', {});
        vesting.slice(0, 8).forEach(v => {
          const days = daysUntil(v.date);
          const cls = days <= 7 ? 'due-now' : days <= 14 ? 'due-soon' : '';
          tb.appendChild(el('tr', { onClick: () => navigate('aktienplaene', { selectedId: v.planId }) },
            el('td', {}, el('span', { className: cls }, `${fmtDate(v.date)}`)),
            el('td', {}, v.planName),
            el('td', { className: 'num' }, num(v.qty, 0)),
            el('td', { className: 'num' }, chf(v.wert))
          ));
        });
        tbl.appendChild(el('thead', {}, el('tr', {}, el('th', {}, 'Datum'), el('th', {}, 'Plan'), el('th', {}, 'Stück'), el('th', {}, 'Wert'))));
        tbl.appendChild(tb);
        return tbl;
      })()
  ));

  // Cashflow Aufschlüsselung
  const ein = Store.get('einkuenfte').filter(e => e.status === 'Aktiv');
  const aus = Store.get('ausgaben').filter(a => a.status === 'Aktiv');
  const einByCat = groupSumMonthly(ein, 'netto');
  const ausByCat = groupSumMonthly(aus, 'betrag');
  const einTotal = Object.values(einByCat).reduce((a, b) => a + b, 0);
  const ausTotal = Object.values(ausByCat).reduce((a, b) => a + b, 0);

  grid.appendChild(el('div', { className: 'card' },
    el('h2', {}, 'Mtl. Einkünfte nach Kategorie'),
    einTotal > 0 ? renderBarChart(einByCat, einTotal) : el('p', { className: 'muted small' }, 'Keine Einkünfte erfasst.')
  ));
  grid.appendChild(el('div', { className: 'card' },
    el('h2', {}, 'Mtl. Ausgaben nach Kategorie'),
    ausTotal > 0 ? renderBarChart(ausByCat, ausTotal) : el('p', { className: 'muted small' }, 'Keine Ausgaben erfasst.')
  ));

  // Portfolio Allokation
  const invs = Store.get('investments').filter(i => i.status === 'Im Portfolio');
  const byCat = {};
  invs.forEach(i => {
    const w = currentInvWert(i);
    byCat[i.kategorie] = (byCat[i.kategorie] || 0) + w;
  });
  const totInv = Object.values(byCat).reduce((a, b) => a + b, 0);
  if (totInv > 0) {
    grid.appendChild(el('div', { className: 'card' },
      el('h2', {}, 'Portfolio-Allokation'),
      renderRing(byCat, totInv)
    ));
  }

  // Aktienplan-Konzentration
  const planTot = computePlanTotalVested();
  const limit = Store.get('settings').concentrationLimit || 30;
  const totalAssets = kpis.investWert + kpis.vestedWert + (kpis.cashflow > 0 ? kpis.cashflow : 0);
  if (planTot > 0 && totalAssets > 0) {
    const share = planTot / (kpis.investWert + kpis.vestedWert) * 100;
    grid.appendChild(el('div', { className: 'card' },
      el('h2', {}, 'Konzentrationsrisiko Mitarbeiteraktien'),
      el('div', { className: 'flex flex-between' },
        el('div', {}, el('div', { className: 'kpi-value' }, pct(share)), el('div', { className: 'small' }, `Limit: ${limit} %`)),
        el('div', { className: share > limit ? 'tag red' : 'tag green' }, share > limit ? '⚠ Überschreitung' : '✓ unter Limit')
      ),
      el('p', { className: 'small mt-1' }, `Gevestete Mitarbeiteraktien: ${chf(planTot)} · Übrige Investments: ${chf(kpis.investWert)}`)
    ));
  }

  root.appendChild(grid);
};

function kpi(label, value, sub, cls = '') {
  return el('div', { className: 'kpi ' + cls },
    el('div', { className: 'kpi-label' }, label),
    el('div', { className: 'kpi-value' }, value),
    sub ? el('div', { className: 'kpi-sub' }, sub) : null
  );
}

function renderBarChart(byCat, total) {
  const wrap = el('div', { className: 'bar-chart' });
  const sorted = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  sorted.forEach(([k, v]) => {
    const pctVal = total > 0 ? (v / total * 100) : 0;
    wrap.appendChild(el('div', { className: 'bar-row' },
      el('div', {}, k),
      el('div', { className: 'bar-track' }, el('div', { className: 'bar-fill', style: `width:${pctVal}%` })),
      el('div', { className: 'bar-val' }, `${chf(v)} · ${pct(pctVal, 0)}`)
    ));
  });
  return wrap;
}

const RING_COLORS = ['#34d399', '#60a5fa', '#f59e0b', '#f87171', '#a78bfa', '#22d3ee', '#fb923c', '#a3e635'];
function renderRing(byCat, total) {
  const entries = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  let start = 0;
  const stops = [];
  entries.forEach(([k, v], i) => {
    const deg = v / total * 360;
    const color = RING_COLORS[i % RING_COLORS.length];
    stops.push(`${color} ${start}deg ${start + deg}deg`);
    start += deg;
  });
  const ring = el('div', { className: 'ring', style: `background: conic-gradient(${stops.join(',')});` });
  const legend = el('ul', { className: 'legend' });
  entries.forEach(([k, v], i) => {
    const color = RING_COLORS[i % RING_COLORS.length];
    legend.appendChild(el('li', {},
      el('span', { className: 'sw', style: `background:${color}` }),
      el('span', {}, `${k} – ${chf(v)} (${pct(v / total * 100, 1)})`)
    ));
  });
  return el('div', { className: 'ring-wrap' }, ring, legend);
}

/* =====================================================================
 * Module 2: Kurzfristige Verbindlichkeiten
 * ===================================================================== */
VIEWS.kv = function (root) {
  const data = Store.get('kv');
  const totalSaldo = data.filter(x => x.status !== 'Beglichen').reduce((s, x) => s + (x.saldo || 0), 0);
  const totalAbgebaut = data.reduce((s, x) => {
    if (x.ursprung && x.saldo !== undefined && x.ursprung > x.saldo) return s + (x.ursprung - x.saldo);
    return s;
  }, 0);

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Total offen', chf(totalSaldo), `${data.filter(x => x.status !== 'Beglichen').length} aktive Positionen`),
    kpi('Bereits abgebaut', chf(totalAbgebaut), 'Ursprung − aktueller Saldo', totalAbgebaut > 0 ? 'positive' : ''),
    kpi('Fällig < 7 T.', chf(data.filter(x => x.status !== 'Beglichen' && daysUntil(x.faellig) !== null && daysUntil(x.faellig) <= 7).reduce((s, x) => s + x.saldo, 0)), 'rote Zone', 'warn'),
    kpi('Jährliche Zinslast', chf(data.filter(x => x.status !== 'Beglichen').reduce((s, x) => s + (x.saldo * (x.zins || 0) / 100), 0))),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openKvForm(),
    searchKey: 'kvSearch',
    filters: [
      { key: 'kvKategorie', label: 'Alle Kategorien', options: KV_KATEGORIEN },
      { key: 'kvStatus', label: 'Alle Status', options: KV_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'glaeubiger', 'notizen'], {
    kvKategorie: 'kategorie', kvStatus: 'status'
  }, App.filters.kvSearch);

  const tbl = el('table', {});
  tbl.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Bezeichnung'),
    el('th', {}, 'Kategorie'),
    el('th', {}, 'Gläubiger'),
    el('th', { className: 'num' }, 'Saldo'),
    el('th', { className: 'num' }, 'Zins'),
    el('th', {}, 'Fällig'),
    el('th', {}, 'Status'),
  )));
  const tb = el('tbody', {});
  filtered.sort((a, b) => (a.faellig || '9999').localeCompare(b.faellig || '9999')).forEach(x => {
    const days = daysUntil(x.faellig);
    const rowCls = x.status === 'Beglichen' ? 'muted' : (days !== null && days <= 7 ? 'danger-row' : (days !== null && days <= 14 ? 'warn-row' : ''));
    tb.appendChild(el('tr', { className: rowCls, onClick: () => openKvForm(x.id) },
      el('td', {}, x.bezeichnung || '–'),
      el('td', {}, el('span', { className: 'tag' }, x.kategorie || '–')),
      el('td', {}, x.glaeubiger || '–'),
      el('td', { className: 'num' }, chf(x.saldo)),
      el('td', { className: 'num' }, x.zins ? pct(x.zins) : '–'),
      el('td', {}, daysCell(x.faellig)),
      el('td', {}, statusTag(x.status))
    ));
  });
  tbl.appendChild(tb);
  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine kurzfristigen Verbindlichkeiten', 'Neue Verbindlichkeit anlegen', () => openKvForm()));
  } else {
    root.appendChild(el('div', { className: 'card scroll-x' }, tbl));
  }
};

function openKvForm(id) {
  const list = Store.get('kv');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Offen', zins: 0, payments: [] };
  const abgebaut = (rec.ursprung && rec.saldo !== undefined && rec.ursprung > rec.saldo) ? (rec.ursprung - rec.saldo) : 0;
  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neue kurzfristige Verbindlichkeit'),
    formGrid([
      ['bezeichnung', 'Bezeichnung *', 'text', true, rec.bezeichnung],
      ['kategorie', 'Kategorie *', 'select', true, rec.kategorie || 'Sonstiges', KV_KATEGORIEN],
      ['glaeubiger', 'Gläubiger', 'text', false, rec.glaeubiger],
      ['ursprung', 'Ursprünglicher Betrag', 'number', false, rec.ursprung],
      ['saldo', 'Aktueller Saldo *', 'number', true, rec.saldo],
      ['currency', 'Währung *', 'select', true, rec.currency || 'CHF', CURRENCIES],
      ['zins', 'Zinssatz p.a. (%)', 'number', false, rec.zins, null, 0.1],
      ['faellig', 'Fällig am *', 'date', true, rec.faellig],
      ['mindestrate', 'Mindest-Monatsrate', 'number', false, rec.mindestrate],
      ['status', 'Status *', 'select', true, rec.status || 'Offen', KV_STATUS],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    id ? el('div', { className: 'kv-progress' },
      el('span', { className: 'small muted' }, 'Bereits abgebaut'),
      el('span', { className: 'mono kv-progress-val' }, chf(abgebaut)),
      rec.ursprung ? el('span', { className: 'small muted' }, `(${pct(abgebaut / rec.ursprung * 100, 0)} von ${chf(rec.ursprung)})`) : null
    ) : null,
    paymentsSection(rec, 'payments', 'Rückzahlungen'),
    crudActions(rec, async (data) => {
      data.payments = rec.payments || [];
      // recompute saldo from ursprung minus payments? -> user controls saldo manually but we expose payments
      await saveRecord('kv', data, 'KV');
    }, 'kv')
  );
  openModal(form);
}

/* =====================================================================
 * Module 3: Langfristige Verbindlichkeiten
 * ===================================================================== */
VIEWS.lv = function (root) {
  const data = Store.get('lv');
  const totalSaldo = data.filter(x => x.status === 'Aktiv').reduce((s, x) => s + (x.saldo || 0), 0);
  const monZins = data.filter(x => x.status === 'Aktiv').reduce((s, x) => s + (x.saldo * (x.zins || 0) / 100 / 12), 0);
  const monTilgung = data.filter(x => x.status === 'Aktiv').reduce((s, x) => s + (x.tilgungsrate || 0), 0);

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Total Restschuld', chf(totalSaldo), `${data.filter(x => x.status === 'Aktiv').length} aktive Verträge`),
    kpi('Mtl. Zinslast', chf(monZins), 'aus Saldo × Zinssatz'),
    kpi('Mtl. Tilgung', chf(monTilgung)),
    kpi('Verträge < 90 T. Ablauf', String(data.filter(x => x.status === 'Aktiv' && daysUntil(x.vertragsende) !== null && daysUntil(x.vertragsende) <= 90).length), 'Refi-Hinweis', 'warn'),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openLvForm(),
    searchKey: 'lvSearch',
    filters: [
      { key: 'lvKategorie', label: 'Alle Kategorien', options: LV_KATEGORIEN },
      { key: 'lvStatus', label: 'Alle Status', options: LV_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'glaeubiger', 'notizen'], {
    lvKategorie: 'kategorie', lvStatus: 'status'
  }, App.filters.lvSearch);

  const tbl = el('table', {});
  tbl.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Bezeichnung'), el('th', {}, 'Kategorie'), el('th', {}, 'Gläubiger'),
    el('th', { className: 'num' }, 'Saldo'), el('th', { className: 'num' }, 'Zins'),
    el('th', {}, 'Vertragsende'), el('th', {}, 'Status')
  )));
  const tb = el('tbody', {});
  filtered.sort((a, b) => (a.vertragsende || '9999').localeCompare(b.vertragsende || '9999')).forEach(x => {
    const days = daysUntil(x.vertragsende);
    const rowCls = days !== null && days <= 90 && x.status === 'Aktiv' ? 'warn-row' : '';
    tb.appendChild(el('tr', { className: rowCls, onClick: () => openLvForm(x.id) },
      el('td', {}, x.bezeichnung),
      el('td', {}, el('span', { className: 'tag' }, x.kategorie)),
      el('td', {}, x.glaeubiger || '–'),
      el('td', { className: 'num' }, chf(x.saldo)),
      el('td', { className: 'num' }, x.zins ? pct(x.zins, 2) : '–'),
      el('td', {}, daysCell(x.vertragsende, 90)),
      el('td', {}, statusTag(x.status))
    ));
  });
  tbl.appendChild(tb);
  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine langfristigen Verbindlichkeiten', 'Neue Verbindlichkeit anlegen', () => openLvForm()));
  } else {
    root.appendChild(el('div', { className: 'card scroll-x' }, tbl));
  }
};

function openLvForm(id) {
  const list = Store.get('lv');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Aktiv', zinstyp: 'Fest', sondertilgungen: [] };
  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neue langfristige Verbindlichkeit'),
    formGrid([
      ['bezeichnung', 'Bezeichnung *', 'text', true, rec.bezeichnung],
      ['kategorie', 'Kategorie *', 'select', true, rec.kategorie || 'Hypothek', LV_KATEGORIEN],
      ['glaeubiger', 'Gläubiger / Bank', 'text', false, rec.glaeubiger],
      ['ursprung', 'Ursprünglicher Betrag', 'number', false, rec.ursprung],
      ['saldo', 'Aktueller Saldo *', 'number', true, rec.saldo],
      ['currency', 'Währung *', 'select', true, rec.currency || 'CHF', CURRENCIES],
      ['zins', 'Zinssatz p.a. (%) *', 'number', true, rec.zins, null, 0.01],
      ['zinstyp', 'Zinstyp *', 'select', true, rec.zinstyp || 'Fest', LV_ZINSTYPEN],
      ['vertragsbeginn', 'Vertragsbeginn *', 'date', true, rec.vertragsbeginn],
      ['vertragsende', 'Vertragsende / Fixierung bis *', 'date', true, rec.vertragsende],
      ['tilgungsrate', 'Tilgungsrate (Monat)', 'number', false, rec.tilgungsrate],
      ['sicherheiten', 'Sicherheiten', 'text', false, rec.sicherheiten],
      ['status', 'Status *', 'select', true, rec.status || 'Aktiv', LV_STATUS],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    rec.id ? interestPreviewCard(rec) : null,
    paymentsSection(rec, 'sondertilgungen', 'Sondertilgungen'),
    crudActions(rec, async (data) => {
      data.sondertilgungen = rec.sondertilgungen || [];
      await saveRecord('lv', data, 'LV');
    }, 'lv')
  );
  openModal(form);
}

function interestPreviewCard(rec) {
  const monZins = (rec.saldo || 0) * (rec.zins || 0) / 100 / 12;
  const jZins = monZins * 12;
  const restJahre = rec.tilgungsrate ? Math.round(rec.saldo / (rec.tilgungsrate * 12)) : null;
  return el('div', { className: 'card mt-1' },
    el('div', { className: 'small' }, 'Berechnung'),
    el('div', { className: 'flex flex-gap flex-wrap mt-1' },
      el('div', {}, el('div', { className: 'small' }, 'Mtl. Zins'), el('div', { className: 'mono' }, chf(monZins, { decimals: 2 }))),
      el('div', {}, el('div', { className: 'small' }, 'Jährl. Zins'), el('div', { className: 'mono' }, chf(jZins, { decimals: 0 }))),
      restJahre ? el('div', {}, el('div', { className: 'small' }, 'Tilgungsdauer'), el('div', { className: 'mono' }, `~ ${restJahre} J.`)) : null,
    )
  );
}

/* =====================================================================
 * Module 4: Einkünfte
 * ===================================================================== */
VIEWS.einkuenfte = function (root) {
  const data = Store.get('einkuenfte');
  const aktiv = data.filter(x => x.status === 'Aktiv');
  const monatlich = aktiv.reduce((s, x) => s + (x.netto || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0), 0);
  const jaehrlich = monatlich * 12;

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Monatlich (Ø)', chf(monatlich), `${aktiv.length} aktive Quellen`, 'positive'),
    kpi('Jährlich (Ø)', chf(jaehrlich)),
    kpi('Aktive Quellen', String(aktiv.length)),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openEinForm(),
    searchKey: 'einSearch',
    filters: [
      { key: 'einKategorie', label: 'Alle Kategorien', options: EIN_KATEGORIEN },
      { key: 'einStatus', label: 'Alle Status', options: EIN_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'quelle', 'notizen'], {
    einKategorie: 'kategorie', einStatus: 'status'
  }, App.filters.einSearch);

  const tbl = el('table', {});
  tbl.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Bezeichnung'), el('th', {}, 'Kategorie'), el('th', {}, 'Quelle'),
    el('th', { className: 'num' }, 'Netto'), el('th', {}, 'Frequenz'),
    el('th', { className: 'num' }, 'Ø Monat'), el('th', {}, 'Status')
  )));
  const tb = el('tbody', {});
  filtered.sort((a, b) => (b.netto * (FREQUENZ_FAKTOR[b.frequenz] || 0)) - (a.netto * (FREQUENZ_FAKTOR[a.frequenz] || 0))).forEach(x => {
    tb.appendChild(el('tr', { onClick: () => openEinForm(x.id) },
      el('td', {}, x.bezeichnung),
      el('td', {}, el('span', { className: 'tag green' }, x.kategorie)),
      el('td', {}, x.quelle || '–'),
      el('td', { className: 'num' }, chf(x.netto)),
      el('td', {}, x.frequenz),
      el('td', { className: 'num' }, chf((x.netto || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0))),
      el('td', {}, statusTag(x.status))
    ));
  });
  tbl.appendChild(tb);
  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine Einkünfte erfasst', 'Neue Einkunft anlegen', () => openEinForm()));
  } else {
    root.appendChild(el('div', { className: 'card scroll-x' }, tbl));
  }
};

function openEinForm(id) {
  const list = Store.get('einkuenfte');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Aktiv', frequenz: 'Monatlich' };
  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neue Einkunft'),
    formGrid([
      ['bezeichnung', 'Bezeichnung *', 'text', true, rec.bezeichnung],
      ['kategorie', 'Kategorie *', 'select', true, rec.kategorie || 'Lohn', EIN_KATEGORIEN],
      ['quelle', 'Quelle / Auftraggeber', 'text', false, rec.quelle],
      ['netto', 'Netto-Betrag *', 'number', true, rec.netto],
      ['brutto', 'Brutto-Betrag', 'number', false, rec.brutto],
      ['frequenz', 'Häufigkeit *', 'select', true, rec.frequenz || 'Monatlich', FREQUENZ],
      ['empfangstag', 'Empfangstag (1–31)', 'number', false, rec.empfangstag],
      ['currency', 'Währung *', 'select', true, rec.currency || 'CHF', CURRENCIES],
      ['start', 'Startdatum *', 'date', true, rec.start],
      ['ende', 'Enddatum (optional)', 'date', false, rec.ende],
      ['konto', 'Ziel-Konto', 'text', false, rec.konto],
      ['status', 'Status *', 'select', true, rec.status || 'Aktiv', EIN_STATUS],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    crudActions(rec, async (data) => await saveRecord('einkuenfte', data, 'E'), 'einkuenfte')
  );
  openModal(form);
}

/* =====================================================================
 * Module 5: Ausgaben
 * ===================================================================== */
VIEWS.ausgaben = function (root) {
  const data = Store.get('ausgaben');
  const aktiv = data.filter(x => x.status === 'Aktiv');
  const monatlich = aktiv.reduce((s, x) => s + (x.betrag || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0), 0);
  const fix = aktiv.filter(x => x.fixvar === 'Fix').reduce((s, x) => s + (x.betrag || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0), 0);
  const variabel = monatlich - fix;

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Mtl. Total', chf(monatlich), `${aktiv.length} Positionen`, 'negative'),
    kpi('Fixkosten', chf(fix), pct(monatlich > 0 ? fix / monatlich * 100 : 0)),
    kpi('Variabel', chf(variabel), pct(monatlich > 0 ? variabel / monatlich * 100 : 0)),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openAusForm(),
    searchKey: 'ausSearch',
    filters: [
      { key: 'ausKategorie', label: 'Alle Kategorien', options: AUS_KATEGORIEN },
      { key: 'ausFixvar', label: 'Fix + Variabel', options: FIXVAR },
      { key: 'ausStatus', label: 'Alle Status', options: AUS_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'empfaenger', 'notizen'], {
    ausKategorie: 'kategorie', ausFixvar: 'fixvar', ausStatus: 'status'
  }, App.filters.ausSearch);

  const tbl = el('table', {});
  tbl.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Bezeichnung'), el('th', {}, 'Kategorie'), el('th', {}, 'Empfänger'),
    el('th', { className: 'num' }, 'Betrag'), el('th', {}, 'Frequenz'),
    el('th', { className: 'num' }, 'Ø Monat'), el('th', {}, 'Fix/Var'), el('th', {}, 'Status')
  )));
  const tb = el('tbody', {});
  filtered.sort((a, b) => (b.betrag * (FREQUENZ_FAKTOR[b.frequenz] || 0)) - (a.betrag * (FREQUENZ_FAKTOR[a.frequenz] || 0))).forEach(x => {
    tb.appendChild(el('tr', { onClick: () => openAusForm(x.id) },
      el('td', {}, x.bezeichnung),
      el('td', {}, el('span', { className: 'tag red' }, x.kategorie)),
      el('td', {}, x.empfaenger || '–'),
      el('td', { className: 'num' }, chf(x.betrag)),
      el('td', {}, x.frequenz),
      el('td', { className: 'num' }, chf((x.betrag || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0))),
      el('td', {}, el('span', { className: 'tag ' + (x.fixvar === 'Fix' ? 'blue' : 'gray') }, x.fixvar || '–')),
      el('td', {}, statusTag(x.status))
    ));
  });
  tbl.appendChild(tb);
  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine Ausgaben erfasst', 'Neue Ausgabe anlegen', () => openAusForm()));
  } else {
    root.appendChild(el('div', { className: 'card scroll-x' }, tbl));
  }
};

function openAusForm(id) {
  const list = Store.get('ausgaben');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Aktiv', frequenz: 'Monatlich', fixvar: 'Variabel' };
  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neue Ausgabe'),
    formGrid([
      ['bezeichnung', 'Bezeichnung *', 'text', true, rec.bezeichnung],
      ['kategorie', 'Kategorie *', 'select', true, rec.kategorie || 'Wohnen', AUS_KATEGORIEN],
      ['empfaenger', 'Empfänger', 'text', false, rec.empfaenger],
      ['betrag', 'Betrag *', 'number', true, rec.betrag],
      ['frequenz', 'Häufigkeit *', 'select', true, rec.frequenz || 'Monatlich', FREQUENZ],
      ['faelligtag', 'Fällig am (Tag 1–31)', 'number', false, rec.faelligtag],
      ['methode', 'Zahlungsmethode', 'select', false, rec.methode, ZAHLUNGSMETHODEN],
      ['currency', 'Währung *', 'select', true, rec.currency || 'CHF', CURRENCIES],
      ['start', 'Startdatum *', 'date', true, rec.start],
      ['ende', 'Enddatum (optional)', 'date', false, rec.ende],
      ['fixvar', 'Fix / Variabel *', 'select', true, rec.fixvar || 'Variabel', FIXVAR],
      ['status', 'Status *', 'select', true, rec.status || 'Aktiv', AUS_STATUS],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    crudActions(rec, async (data) => await saveRecord('ausgaben', data, 'A'), 'ausgaben')
  );
  openModal(form);
}

/* =====================================================================
 * Module 6: Investments
 * ===================================================================== */
VIEWS.investments = function (root) {
  const data = Store.get('investments');
  const aktiv = data.filter(x => x.status === 'Im Portfolio');
  const totalWert = aktiv.reduce((s, x) => s + currentInvWert(x), 0);
  const totalInvested = aktiv.reduce((s, x) => s + investedCHF(x), 0);
  const gewinn = totalWert - totalInvested;
  const perfPct = totalInvested > 0 ? gewinn / totalInvested * 100 : 0;

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Portfolio-Wert', chf(totalWert), `${aktiv.length} Positionen`),
    kpi('Investiert', chf(totalInvested)),
    kpi('Gewinn / Verlust', chf(gewinn, { sign: true }), pct(perfPct, 1), gewinn >= 0 ? 'positive' : 'negative'),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openInvForm(),
    searchKey: 'invSearch',
    filters: [
      { key: 'invKategorie', label: 'Alle Kategorien', options: INV_KATEGORIEN },
      { key: 'invStatus', label: 'Alle Status', options: INV_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'ticker', 'broker', 'notizen'], {
    invKategorie: 'kategorie', invStatus: 'status'
  }, App.filters.invSearch);

  const tbl = el('table', {});
  tbl.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Bezeichnung'), el('th', {}, 'Kategorie'), el('th', {}, 'Broker'),
    el('th', { className: 'num' }, 'Anzahl'), el('th', { className: 'num' }, 'Einstand'),
    el('th', { className: 'num' }, 'Kurs'), el('th', { className: 'num' }, 'Wert'),
    el('th', { className: 'num' }, 'G/V'), el('th', {}, 'Status')
  )));
  const tb = el('tbody', {});
  filtered.sort((a, b) => currentInvWert(b) - currentInvWert(a)).forEach(x => {
    const wert = currentInvWert(x);
    const gv = wert - (x.investTotal || 0);
    const gvPct = x.investTotal ? gv / x.investTotal * 100 : 0;
    tb.appendChild(el('tr', { onClick: () => openInvForm(x.id) },
      el('td', {},
        el('div', {}, x.bezeichnung),
        x.ticker ? el('div', { className: 'small' }, x.ticker) : null
      ),
      el('td', {}, el('span', { className: 'tag blue' }, x.kategorie)),
      el('td', {}, x.broker || '–'),
      el('td', { className: 'num' }, x.anzahl ? num(x.anzahl, 4) : '–'),
      el('td', { className: 'num' }, x.kaufpreis ? `${x.currency || 'CHF'} ${num(x.kaufpreis, 2)}` : '–'),
      el('td', { className: 'num' }, x.kurs ? `${x.currency || 'CHF'} ${num(x.kurs, 2)}` : '–'),
      el('td', { className: 'num' },
        el('div', {}, chf(wert)),
        x.currency && x.currency !== 'CHF' ? el('div', { className: 'small muted' }, `${x.currency} ${num(currentInvWertNative(x), 2)}`) : null
      ),
      el('td', { className: 'num ' + (gv >= 0 ? '' : '') }, el('span', { className: gv >= 0 ? 'tag green' : 'tag red' }, `${chf(gv, { sign: true })} (${pct(gvPct, 1)})`)),
      el('td', {}, statusTag(x.status))
    ));
  });
  tbl.appendChild(tb);
  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine Investments erfasst', 'Neues Investment anlegen', () => openInvForm()));
  } else {
    root.appendChild(el('div', { className: 'card scroll-x' }, tbl));
  }
};

function currentInvWertNative(x) {
  if (!x) return 0;
  if (x.kurs && x.anzahl) return x.kurs * x.anzahl;
  if (x.aktuellerWert) return x.aktuellerWert;
  return x.investTotal || 0;
}
function currentInvWert(x) {
  return FX.toCHF(currentInvWertNative(x), x?.currency || 'CHF');
}
function investedCHF(x) {
  return FX.toCHF(x?.investTotal || 0, x?.currency || 'CHF');
}

function openInvForm(id) {
  const list = Store.get('investments');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Im Portfolio', transactions: [] };
  const hasAdv = !!(rec.ticker || rec.broker || rec.anzahl || rec.kaufpreis || rec.kurs || rec.dividende || (rec.currency && rec.currency !== 'CHF') || (rec.status && rec.status !== 'Im Portfolio'));
  const advDetails = el('details', { className: 'adv-fields' });
  if (hasAdv) advDetails.setAttribute('open', '');
  advDetails.appendChild(el('summary', {}, 'Erweiterte Felder (Broker, Stückzahl, Kurs, Dividende, Status, Währung)'));
  advDetails.appendChild(formGrid([
    ['ticker', 'Ticker / ISIN', 'text', false, rec.ticker],
    ['broker', 'Broker / Depot', 'text', false, rec.broker],
    ['anzahl', 'Anzahl / Stück', 'number', false, rec.anzahl, null, 0.0001],
    ['kaufpreis', 'Kaufpreis pro Einheit', 'number', false, rec.kaufpreis, null, 0.01],
    ['kurs', 'Aktueller Kurs pro Einheit', 'number', false, rec.kurs, null, 0.01],
    ['dividende', 'Dividenden-Rendite p.a. (%)', 'number', false, rec.dividende, null, 0.01],
    ['currency', 'Währung', 'select', false, rec.currency || 'CHF', CURRENCIES],
    ['status', 'Status', 'select', false, rec.status || 'Im Portfolio', INV_STATUS],
  ]));

  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neues Investment'),
    formGrid([
      ['bezeichnung', 'Was hast du gekauft? *', 'text', true, rec.bezeichnung],
      ['kategorie', 'Kategorie *', 'select', true, rec.kategorie || 'ETF', INV_KATEGORIEN],
      ['investTotal', 'Investiert (CHF) *', 'number', true, rec.investTotal],
      ['aktuellerWert', 'Aktueller Wert (CHF)', 'number', false, rec.aktuellerWert],
      ['kaufdatum', 'Kaufdatum *', 'date', true, rec.kaufdatum],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    advDetails,
    rec.id ? investmentPerfCard(rec) : null,
    paymentsSection(rec, 'transactions', 'Transaktionen', ['type', 'date', 'qty', 'price', 'note']),
    crudActions(rec, async (data) => {
      data.transactions = rec.transactions || [];
      await saveRecord('investments', data, 'I');
    }, 'investments')
  );
  openModal(form);
}

function investmentPerfCard(rec) {
  const wert = currentInvWert(rec);
  const inv = rec.investTotal || 0;
  const gv = wert - inv;
  const pctVal = inv ? gv / inv * 100 : 0;
  return el('div', { className: 'card mt-1' },
    el('div', { className: 'small' }, 'Performance'),
    el('div', { className: 'flex flex-gap flex-wrap mt-1' },
      el('div', {}, el('div', { className: 'small' }, 'Marktwert'), el('div', { className: 'mono' }, chf(wert))),
      el('div', {}, el('div', { className: 'small' }, 'Gewinn/Verlust'), el('div', { className: 'mono ' + (gv >= 0 ? '' : '') }, chf(gv, { sign: true }))),
      el('div', {}, el('div', { className: 'small' }, 'Performance %'), el('div', { className: 'mono' }, pct(pctVal, 2))),
    )
  );
}

/* =====================================================================
 * Module 7: Aktienpläne
 * ===================================================================== */
VIEWS.aktienplaene = function (root) {
  const data = Store.get('aktienplaene');
  const aktiv = data.filter(x => x.status === 'Aktiv' || x.status === 'Vollständig gevestet');
  const totalVested = computePlanTotalVested();
  const totalGrant = aktiv.reduce((s, x) => s + (x.gesamtanzahl || 0) * (x.kurs || 0), 0);
  const upcoming = computeUpcomingVesting(90).length;

  root.appendChild(el('div', { className: 'kpi-grid' },
    kpi('Gevestet (CHF)', chf(totalVested), `aus ${aktiv.length} Plänen`, 'positive'),
    kpi('Grant-Wert Total', chf(totalGrant), 'alle zugeteilten Stücke'),
    kpi('Vesting nächste 90 T.', String(upcoming), 'anstehende Tranchen', upcoming > 0 ? 'warn' : ''),
  ));

  root.appendChild(toolbarBar({
    onNew: () => openPlanForm(),
    searchKey: 'apSearch',
    filters: [
      { key: 'apTyp', label: 'Alle Typen', options: PLAN_TYPEN },
      { key: 'apStatus', label: 'Alle Status', options: PLAN_STATUS },
    ],
  }));

  const filtered = filterRecords(data, ['bezeichnung', 'arbeitgeber', 'ticker', 'notizen'], {
    apTyp: 'plantyp', apStatus: 'status'
  }, App.filters.apSearch);

  if (filtered.length === 0) {
    root.appendChild(emptyState('Keine Aktienpläne erfasst', 'Neuen Plan anlegen', () => openPlanForm()));
    return;
  }

  filtered.forEach(plan => {
    const v = computeVesting(plan);
    const card = el('div', { className: 'card', onClick: () => openPlanForm(plan.id) },
      el('div', { className: 'flex flex-between flex-wrap' },
        el('div', {},
          el('h2', {}, plan.bezeichnung, ' ', el('span', { className: 'tag ' + (plan.plantyp === 'Option' ? 'purple' : 'blue') }, plan.plantyp), ' ', statusTag(plan.status)),
          el('div', { className: 'small' }, `${plan.arbeitgeber} · ${plan.ticker || ''} · Grant: ${fmtDate(plan.grantDate)}`)
        ),
        el('div', { className: 'right' },
          el('div', { className: 'kpi-label' }, 'Aktueller Wert (gevestet)'),
          el('div', { className: 'kpi-value' }, chf(v.vestedQty * (plan.kurs || 0)))
        )
      ),
      el('div', { className: 'vesting-timeline' },
        el('div', { className: 'small' },
          `${num(v.vestedQty)} von ${num(plan.gesamtanzahl)} gevestet (${pct(v.vestedQty / plan.gesamtanzahl * 100, 0)}) · ${num(v.pendingQty)} ausstehend`),
        el('div', { className: 'vesting-bar' },
          el('div', { className: 'vesting-fill', style: `width:${(v.vestedQty / plan.gesamtanzahl * 100)}%` })
        ),
        el('div', { className: 'tranche-list' },
          ...v.tranches.slice(0, 12).map(t => el('div', { className: 'tranche ' + (t.vested ? 'done' : (t.isNext ? 'next' : '')) },
            el('div', { className: 't-qty' }, num(t.qty, 0)),
            el('div', { className: 't-date' }, fmtDate(t.date))
          ))
        )
      )
    );
    card.style.cursor = 'pointer';
    root.appendChild(card);
  });
};

function openPlanForm(id) {
  const list = Store.get('aktienplaene');
  const rec = id ? list.find(x => x.id === id) : { id: null, currency: 'CHF', status: 'Aktiv', plantyp: 'RSU', rhythmus: 'Quartal', events: [] };
  const v = id ? computeVesting(rec) : null;
  const form = el('form', { className: 'crud-form' },
    el('h3', {}, id ? `Bearbeiten: ${rec.id}` : 'Neuer Aktienplan'),
    formGrid([
      ['bezeichnung', 'Bezeichnung *', 'text', true, rec.bezeichnung],
      ['plantyp', 'Plantyp *', 'select', true, rec.plantyp || 'RSU', PLAN_TYPEN],
      ['arbeitgeber', 'Arbeitgeber *', 'text', true, rec.arbeitgeber],
      ['ticker', 'Ticker / ISIN', 'text', false, rec.ticker],
      ['grantDate', 'Grant-Datum *', 'date', true, rec.grantDate],
      ['gesamtanzahl', 'Gesamtanzahl *', 'number', true, rec.gesamtanzahl],
      ['strikePrice', 'Grant-Preis / Strike', 'number', false, rec.strikePrice, null, 0.01],
      ['kurs', 'Aktueller Kurs', 'number', false, rec.kurs, null, 0.01],
      ['vestingStart', 'Vesting-Beginn *', 'date', true, rec.vestingStart],
      ['vestingJahre', 'Vesting-Dauer (Jahre) *', 'number', true, rec.vestingJahre],
      ['cliff', 'Cliff (Jahre)', 'number', false, rec.cliff, null, 0.25],
      ['rhythmus', 'Vesting-Rhythmus *', 'select', true, rec.rhythmus || 'Quartal', VESTING_RHYTHMUS],
      ['sperrfrist', 'Sperrfrist (Lock-up bis)', 'date', false, rec.sperrfrist],
      ['ablaufdatum', 'Ablaufdatum (Option)', 'date', false, rec.ablaufdatum],
      ['currency', 'Währung *', 'select', true, rec.currency || 'CHF', CURRENCIES],
      ['status', 'Status *', 'select', true, rec.status || 'Aktiv', PLAN_STATUS],
      ['perfBedingung', 'Performance-Bedingung (PSU)', 'textarea', false, rec.perfBedingung, null, null, true],
      ['notizen', 'Notizen', 'textarea', false, rec.notizen, null, null, true],
    ]),
    v ? el('div', { className: 'card mt-1' },
      el('div', { className: 'small' }, 'Vesting-Status'),
      el('div', { className: 'flex flex-gap flex-wrap mt-1' },
        el('div', {}, el('div', { className: 'small' }, 'Bereits gevestet'), el('div', { className: 'mono' }, num(v.vestedQty))),
        el('div', {}, el('div', { className: 'small' }, 'Noch ausstehend'), el('div', { className: 'mono' }, num(v.pendingQty))),
        el('div', {}, el('div', { className: 'small' }, 'Nächste Tranche'), el('div', { className: 'mono' }, v.nextTranche ? `${fmtDate(v.nextTranche.date)} (${num(v.nextTranche.qty)})` : '–')),
        el('div', {}, el('div', { className: 'small' }, 'Wert gevestet'), el('div', { className: 'mono' }, chf(v.vestedQty * (rec.kurs || 0)))),
      )
    ) : null,
    paymentsSection(rec, 'events', 'Ereignisse (Ausübung / Verkauf)', ['type', 'date', 'qty', 'price', 'note']),
    crudActions(rec, async (data) => {
      data.events = rec.events || [];
      await saveRecord('aktienplaene', data, 'AP');
    }, 'aktienplaene')
  );
  openModal(form);
}

/* =====================================================================
 * Generic form helpers
 * ===================================================================== */
function formGrid(rows) {
  const wrap = el('div', { className: 'form-grid' });
  rows.forEach(r => {
    const [name, label, type, required, value, opts, step, full] = r;
    const lbl = el('label', { className: full ? 'full' : '' },
      el('span', { className: 'lbl' }, label.replace(' *', ''), required ? el('span', { className: 'req' }, ' *') : null)
    );
    let input;
    if (type === 'select') {
      input = el('select', { name, required });
      (opts || []).forEach(o => {
        const opt = el('option', { value: o }, o);
        if (o === value) opt.selected = true;
        input.appendChild(opt);
      });
      if (!required && !(opts || []).includes(value)) {
        const blank = el('option', { value: '' }, '— bitte wählen —');
        if (!value) blank.selected = true;
        input.insertBefore(blank, input.firstChild);
      }
    } else if (type === 'textarea') {
      input = el('textarea', { name, required }, value || '');
    } else {
      const attrs = { type, name, required };
      if (value !== undefined && value !== null && value !== '') attrs.value = value;
      if (step) attrs.step = step;
      if (type === 'number') attrs.step = step || 'any';
      input = el('input', attrs);
    }
    lbl.appendChild(input);
    wrap.appendChild(lbl);
  });
  return wrap;
}

function crudActions(rec, onSave, view) {
  return el('div', { className: 'form-actions' },
    rec.id ? el('button', { type: 'button', className: 'btn danger left', onClick: async () => {
      if (confirm('Datensatz wirklich löschen?')) {
        const list = Store.get(view);
        const i = list.findIndex(x => x.id === rec.id);
        if (i >= 0) { list.splice(i, 1); await Store.save(view, list); }
        closeModal(); render(); showToast('Gelöscht');
      }
    } }, 'Löschen') : null,
    el('button', { type: 'button', className: 'btn ghost', onClick: closeModal }, 'Abbrechen'),
    el('button', { type: 'submit', className: 'btn primary', onClick: e => {
      e.preventDefault();
      const form = e.target.closest('form');
      const data = Object.fromEntries(new FormData(form).entries());
      // Coerce numbers
      ['ursprung', 'saldo', 'zins', 'mindestrate', 'tilgungsrate', 'netto', 'brutto', 'empfangstag', 'betrag', 'faelligtag', 'anzahl', 'kaufpreis', 'investTotal', 'kurs', 'aktuellerWert', 'dividende', 'gesamtanzahl', 'strikePrice', 'vestingJahre', 'cliff'].forEach(k => {
        if (data[k] !== undefined && data[k] !== '') data[k] = parseFloat(data[k]);
        else if (data[k] === '') delete data[k];
      });
      // Required check
      const missing = $$('[required]', form).filter(i => !i.value).map(i => i.previousElementSibling?.textContent || i.name);
      if (missing.length) { showToast('Pflichtfelder: ' + missing.join(', '), 'err'); return; }
      onSave({ ...rec, ...data });
    } }, rec.id ? 'Speichern' : 'Anlegen'),
  );
}

async function saveRecord(view, data, prefix) {
  const list = Store.get(view);
  if (!data.id) {
    data.id = Store.nextId(prefix);
    data.createdAt = new Date().toISOString();
    list.push(data);
  } else {
    const i = list.findIndex(x => x.id === data.id);
    if (i >= 0) list[i] = { ...list[i], ...data, updatedAt: new Date().toISOString() };
  }
  await Store.save(view, list);
  closeModal();
  render();
  showToast('Gespeichert');
}

function paymentsSection(rec, key, title, fields = ['date', 'amount', 'note']) {
  const list = rec[key] || [];
  const wrap = el('div', { className: 'mt-2' },
    el('div', { className: 'flex flex-between' },
      el('div', { className: 'section-title' }, `${title} (${list.length})`),
      el('button', { type: 'button', className: 'btn small', onClick: () => {
        const entry = {};
        fields.forEach(f => {
          if (f === 'date') entry[f] = todayISO();
          else if (f === 'type') entry[f] = 'Kauf';
          else entry[f] = '';
        });
        const inputs = el('div', { className: 'form-grid' });
        fields.forEach(f => {
          let inp;
          if (f === 'type') inp = el('select', { name: f }, ...['Kauf', 'Verkauf', 'Dividende', 'Sondertilgung', 'Vesting', 'Ausübung'].map(o => el('option', { value: o, ...(o === entry[f] ? { selected: true } : {}) }, o)));
          else if (f === 'date') inp = el('input', { type: 'date', name: f, value: entry[f] });
          else if (f === 'note') inp = el('input', { type: 'text', name: f, placeholder: 'Notiz' });
          else inp = el('input', { type: 'number', name: f, step: 'any', placeholder: f });
          inputs.appendChild(el('label', { className: 'full' }, el('span', { className: 'lbl' }, f), inp));
        });
        const dialog = el('form', {},
          el('h3', {}, 'Eintrag hinzufügen'),
          inputs,
          el('div', { className: 'form-actions' },
            el('button', { type: 'button', className: 'btn ghost', onClick: () => closeSubModal() }, 'Abbrechen'),
            el('button', { type: 'submit', className: 'btn primary' }, 'Hinzufügen')
          )
        );
        dialog.addEventListener('submit', e => {
          e.preventDefault();
          const entry2 = Object.fromEntries(new FormData(dialog).entries());
          ['amount', 'qty', 'price'].forEach(k => { if (entry2[k]) entry2[k] = parseFloat(entry2[k]); });
          entry2.id = uid();
          rec[key] = rec[key] || [];
          rec[key].push(entry2);
          closeSubModal();
          renderPayments();
        });
        openSubModal(dialog);
      } }, '+ Hinzufügen')
    ),
    el('div', { id: `pay-${key}` })
  );

  function renderPayments() {
    const container = wrap.querySelector(`#pay-${key}`);
    container.innerHTML = '';
    const list2 = rec[key] || [];
    if (list2.length === 0) {
      container.appendChild(el('p', { className: 'muted small' }, '– keine Einträge –'));
      return;
    }
    list2.sort((a, b) => (b.date || '').localeCompare(a.date || '')).forEach(p => {
      const row = el('div', { className: 'note-entry' },
        el('div', { className: 'note-meta' }, `${fmtDate(p.date)} ${p.type ? '· ' + p.type : ''}`),
        el('div', {},
          p.amount !== undefined ? chf(p.amount) : '',
          p.qty !== undefined ? ` ${num(p.qty)} Stk.` : '',
          p.price !== undefined ? ` × ${chf(p.price)}` : '',
          p.note ? ` — ${p.note}` : ''
        ),
        el('button', { type: 'button', className: 'btn small danger', onClick: () => {
          rec[key] = rec[key].filter(x => x.id !== p.id);
          renderPayments();
        } }, 'Löschen')
      );
      container.appendChild(row);
    });
  }
  renderPayments();
  return wrap;
}

/* Sub-modal (simple stacked) ===== */
let SUB_BACKDROP = null;
function openSubModal(content) {
  SUB_BACKDROP = el('div', { className: 'sub-backdrop' });
  Object.assign(SUB_BACKDROP.style, { position: 'fixed', inset: '0', background: 'rgba(0,0,0,0.6)', zIndex: 9000, display: 'flex', alignItems: 'center', justifyContent: 'center' });
  const card = el('div', {});
  Object.assign(card.style, { background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px', maxWidth: '480px', width: '92%', maxHeight: '90vh', overflowY: 'auto' });
  card.appendChild(content);
  SUB_BACKDROP.appendChild(card);
  document.body.appendChild(SUB_BACKDROP);
  SUB_BACKDROP.addEventListener('click', e => { if (e.target === SUB_BACKDROP) closeSubModal(); });
}
function closeSubModal() {
  if (SUB_BACKDROP) { SUB_BACKDROP.remove(); SUB_BACKDROP = null; }
}

/* =====================================================================
 * Filter / Search helpers
 * ===================================================================== */
function toolbarBar({ onNew, searchKey, filters = [] }) {
  const bar = el('div', { className: 'toolbar' },
    el('button', { className: 'btn primary', onClick: onNew }, '+ Neu'),
    el('input', { type: 'search', placeholder: 'Suchen…', value: App.filters[searchKey] || '', oninput: e => { App.filters[searchKey] = e.target.value; render(); } })
  );
  filters.forEach(f => {
    const sel = el('select', { onchange: e => { App.filters[f.key] = e.target.value; render(); } },
      el('option', { value: '' }, f.label),
      ...f.options.map(o => {
        const opt = el('option', { value: o }, o);
        if (App.filters[f.key] === o) opt.selected = true;
        return opt;
      })
    );
    bar.appendChild(sel);
  });
  bar.appendChild(el('button', { className: 'btn ghost', onClick: () => exportCsv() }, '↓ CSV'));
  return bar;
}

function filterRecords(list, textKeys, filterMap, search) {
  return list.filter(x => {
    for (const [fk, prop] of Object.entries(filterMap)) {
      const v = App.filters[fk];
      if (v && x[prop] !== v) return false;
    }
    if (search) {
      const q = search.toLowerCase();
      const hit = textKeys.some(k => (x[k] || '').toString().toLowerCase().includes(q));
      if (!hit) return false;
    }
    return true;
  });
}

function emptyState(title, btnLabel, onClick) {
  return el('div', { className: 'card empty-state' },
    el('h3', {}, title),
    el('p', { className: 'muted' }, 'Noch keine Einträge.'),
    el('button', { className: 'btn primary mt-1', onClick }, btnLabel)
  );
}

function statusTag(s) {
  const c = STATUS_COLORS[s] || 'gray';
  return el('span', { className: 'tag ' + c }, s || '–');
}

function daysCell(date, threshold = 14) {
  if (!date) return el('span', { className: 'muted' }, '–');
  const d = daysUntil(date);
  let cls = '';
  if (d <= 0) cls = 'overdue';
  else if (d <= 7) cls = 'due-now';
  else if (d <= threshold) cls = 'due-soon';
  return el('div', {},
    el('div', {}, fmtDate(date)),
    d !== null ? el('div', { className: 'small ' + cls }, d < 0 ? `${-d} T. überfällig` : (d === 0 ? 'heute' : `in ${d} T.`)) : null
  );
}

function groupSumMonthly(list, valueKey) {
  const out = {};
  list.forEach(x => {
    const f = FREQUENZ_FAKTOR[x.frequenz] || 0;
    const m = (x[valueKey] || 0) * f;
    out[x.kategorie] = (out[x.kategorie] || 0) + m;
  });
  return out;
}

/* =====================================================================
 * Computations
 * ===================================================================== */
function computeKPIs() {
  const kv = Store.get('kv') || [];
  const lv = Store.get('lv') || [];
  const ein = Store.get('einkuenfte') || [];
  const aus = Store.get('ausgaben') || [];
  const inv = Store.get('investments') || [];

  const kvActive = kv.filter(x => x.status !== 'Beglichen');
  const lvActive = lv.filter(x => x.status === 'Aktiv');
  const schuldenTotal = kvActive.reduce((s, x) => s + (x.saldo || 0), 0) + lvActive.reduce((s, x) => s + (x.saldo || 0), 0);

  const einMonth = ein.filter(x => x.status === 'Aktiv').reduce((s, x) => s + (x.netto || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0), 0);
  const ausMonth = aus.filter(x => x.status === 'Aktiv').reduce((s, x) => s + (x.betrag || 0) * (FREQUENZ_FAKTOR[x.frequenz] || 0), 0);

  const invActive = inv.filter(x => x.status === 'Im Portfolio');
  const investWert = invActive.reduce((s, x) => s + currentInvWert(x), 0);
  const investGekauft = invActive.reduce((s, x) => s + investedCHF(x), 0);
  const investGewinn = investWert - investGekauft;

  const vestedWert = computePlanTotalVested();
  const vestedAnzahl = (Store.get('aktienplaene') || []).reduce((s, p) => s + computeVesting(p).vestedQty, 0);

  const cashflow = einMonth - ausMonth;
  const sparquote = einMonth > 0 ? cashflow / einMonth * 100 : 0;
  // Schuldendienst = mtl. Zins lv + Tilgung lv + Mindestraten kv
  const sdLv = lvActive.reduce((s, x) => s + (x.saldo * (x.zins || 0) / 100 / 12) + (x.tilgungsrate || 0), 0);
  const sdKv = kvActive.reduce((s, x) => s + (x.mindestrate || 0), 0);
  const schuldendienstQuote = einMonth > 0 ? (sdLv + sdKv) / einMonth * 100 : 0;

  const nettoVermoegen = investWert + vestedWert - schuldenTotal;

  const kvAbgebaut = kv.reduce((s, x) => {
    if (x.ursprung && x.saldo !== undefined && x.ursprung > x.saldo) return s + (x.ursprung - x.saldo);
    return s;
  }, 0);

  return {
    nettoVermoegen, cashflow, sparquote, schuldendienstQuote, schuldenTotal,
    investWert, investGewinn, vestedWert, vestedAnzahl,
    einkuenfteMonat: einMonth, ausgabenMonat: ausMonth,
    kvAbgebaut,
    kvCount: kvActive.length, lvCount: lvActive.length,
  };
}

function computeSuggestions(kpis) {
  const sugs = [];
  const inv = Store.get('investments') || [];
  const invActive = inv.filter(i => i.status === 'Im Portfolio');

  // Allokation nach Kategorie
  const byCat = {};
  invActive.forEach(i => {
    const w = currentInvWert(i);
    byCat[i.kategorie] = (byCat[i.kategorie] || 0) + w;
  });
  const totInv = Object.values(byCat).reduce((a, b) => a + b, 0);

  // 1. Hochzinsschulden vor Investitionen tilgen
  const kvHigh = (Store.get('kv') || []).filter(x => x.status !== 'Beglichen' && (x.zins || 0) >= 5);
  if (kvHigh.length > 0) {
    const tot = kvHigh.reduce((s, x) => s + (x.saldo || 0), 0);
    sugs.push({ type: 'danger', title: 'Hochzinsschulden zuerst tilgen',
      msg: `${chf(tot)} kurzfristige Schulden mit ≥5 % Zins. Tilgung schlägt fast jedes Investment — vor neuen Käufen abbauen.` });
  }

  // 2. Notgroschen (3-6 Monate Ausgaben in Cash)
  const cashPos = invActive.filter(i => i.kategorie === 'Cash').reduce((s, x) => s + currentInvWert(x), 0);
  if (kpis.ausgabenMonat > 0) {
    const months = cashPos / kpis.ausgabenMonat;
    if (months < 3) {
      sugs.push({ type: 'warn', title: 'Notgroschen aufbauen',
        msg: `Cash-Reserve ${chf(cashPos)} = ${num(months, 1)} Monate Ausgaben. Ziel: 3–6 Monate (${chf(kpis.ausgabenMonat * 3)}–${chf(kpis.ausgabenMonat * 6)}).` });
    } else if (months > 12) {
      sugs.push({ type: 'info', title: 'Zu viel Cash',
        msg: `${num(months, 0)} Monate Ausgaben in Cash. Überschuss von ~${chf(cashPos - kpis.ausgabenMonat * 6)} in ETF/Anleihen investieren.` });
    }
  }

  // 3. Säule 3a
  const s3aTotal = invActive.filter(i => i.kategorie === 'Säule 3a').reduce((s, x) => s + currentInvWert(x), 0);
  if (s3aTotal === 0 && kpis.einkuenfteMonat > 4000) {
    sugs.push({ type: 'warn', title: 'Säule 3a nutzen',
      msg: 'Keine Säule-3a-Position erfasst. Max-Einzahlung 2026: CHF 7\'258 (mit Pensionskasse). Steuerersparnis je nach Einkommen 1\'500–2\'500 CHF/Jahr.' });
  }

  // 4. Klumpenrisiko Mitarbeiteraktien
  if (kpis.vestedWert > 0 && (kpis.investWert + kpis.vestedWert) > 0) {
    const share = kpis.vestedWert / (kpis.investWert + kpis.vestedWert) * 100;
    if (share > 30) {
      sugs.push({ type: 'warn', title: 'Klumpenrisiko Mitarbeiteraktien',
        msg: `${pct(share, 0)} deines Equity-Vermögens in Mitarbeiteraktien. Schrittweise verkaufen + in ETF diversifizieren.` });
    }
  }

  // 5. Allokations-Balance
  if (totInv > 0) {
    const aktien = (byCat['Aktie'] || 0) + (byCat['ETF'] || 0) + (byCat['Fonds'] || 0);
    const anleihen = byCat['Anleihe'] || 0;
    const krypto = byCat['Krypto'] || 0;
    const aktienShare = aktien / totInv * 100;
    const anleihenShare = anleihen / totInv * 100;
    const kryptoShare = krypto / totInv * 100;

    if (kryptoShare > 10) {
      sugs.push({ type: 'warn', title: 'Krypto-Anteil hoch',
        msg: `Krypto ${pct(kryptoShare, 0)} des Portfolios. >10 % gilt als spekulativ — Position auf 5–10 % reduzieren.` });
    }
    if (aktienShare > 85 && totInv > 30000) {
      sugs.push({ type: 'info', title: 'Anleihen beimischen',
        msg: `Aktien/ETF ${pct(aktienShare, 0)}, Anleihen ${pct(anleihenShare, 0)}. Bei grösserem Portfolio 10–25 % Anleihen für Stabilität.` });
    }
    if (anleihenShare === 0 && totInv > 50000) {
      sugs.push({ type: 'info', title: 'Anleihen-Diversifikation fehlt',
        msg: 'Keine Anleihen erfasst. Schweizer Staatsanleihen oder Global-Aggregate-ETFs dämpfen Aktien-Volatilität.' });
    }
    // Top-1-Position-Konzentration
    const sorted = invActive.map(i => ({ name: i.bezeichnung, wert: currentInvWert(i) }))
      .filter(x => x.wert > 0)
      .sort((a, b) => b.wert - a.wert);
    if (sorted.length > 0) {
      const topShare = sorted[0].wert / totInv * 100;
      if (topShare > 35 && sorted.length >= 3) {
        sugs.push({ type: 'warn', title: 'Einzelposition zu gross',
          msg: `"${sorted[0].name}" macht ${pct(topShare, 0)} deines Portfolios aus. Streuung verbessern.` });
      }
    }
  }

  // 6. Schuldendienst-Quote
  if (kpis.schuldendienstQuote > 33) {
    sugs.push({ type: 'danger', title: 'Schuldendienst über 33 %',
      msg: `Zins+Tilgung beanspruchen ${pct(kpis.schuldendienstQuote, 0)} der Einkünfte. Refinanzierung oder Konsolidierung prüfen.` });
  }

  // 7. Sparquote
  if (kpis.sparquote < 0) {
    sugs.push({ type: 'danger', title: 'Negativer Cashflow',
      msg: `Ausgaben übersteigen Einkünfte um ${chf(-kpis.cashflow)}/Monat. Variable Ausgaben durchgehen.` });
  } else if (kpis.sparquote >= 0 && kpis.sparquote < 10 && kpis.einkuenfteMonat > 0) {
    sugs.push({ type: 'warn', title: 'Sparquote unter 10 %',
      msg: `Aktuell ${pct(kpis.sparquote, 0)}. Ziel: ≥10 %, ideal 20 %+. Fixkosten reduzieren oder Einkünfte erhöhen.` });
  }

  // 8. Fallback: alles im Lot
  if (sugs.length === 0) {
    sugs.push({ type: 'ok', title: 'Portfolio im Gleichgewicht',
      msg: 'Keine kritischen Ungleichgewichte erkannt. Weiter so — periodisch reviewen.' });
  }

  return sugs;
}

function computeUpcomingPayments(days = 30) {
  const out = [];
  (Store.get('kv') || []).forEach(x => {
    if (x.status === 'Beglichen' || !x.faellig) return;
    const d = daysUntil(x.faellig);
    if (d <= days) out.push({ id: x.id, bezeichnung: x.bezeichnung, betrag: x.saldo, faellig: x.faellig, view: 'kv' });
  });
  (Store.get('lv') || []).forEach(x => {
    if (x.status !== 'Aktiv' || !x.vertragsende) return;
    const d = daysUntil(x.vertragsende);
    if (d <= days) out.push({ id: x.id, bezeichnung: 'Refi: ' + x.bezeichnung, betrag: x.saldo, faellig: x.vertragsende, view: 'lv' });
  });
  return out.sort((a, b) => (a.faellig || '').localeCompare(b.faellig || ''));
}

function computeVesting(plan) {
  const total = plan.gesamtanzahl || 0;
  const years = plan.vestingJahre || 0;
  const cliff = plan.cliff || 0;
  const start = plan.vestingStart ? new Date(plan.vestingStart) : null;
  if (!start || total === 0 || years === 0) {
    return { tranches: [{ date: plan.vestingStart || plan.grantDate, qty: total, vested: true, isNext: false }], vestedQty: total, pendingQty: 0, nextTranche: null };
  }
  const periodsPerYear = plan.rhythmus === 'Monatlich' ? 12 : plan.rhythmus === 'Quartal' ? 4 : 1;
  const totalPeriods = years * periodsPerYear;
  const cliffPeriods = Math.round(cliff * periodsPerYear);
  const stepMonths = 12 / periodsPerYear;
  const now = Date.now();

  const tranches = [];
  let cumulative = 0;
  for (let i = 1; i <= totalPeriods; i++) {
    const d = new Date(start);
    d.setMonth(d.getMonth() + Math.round(i * stepMonths));
    let qty;
    if (i <= cliffPeriods) {
      if (i === cliffPeriods && cliffPeriods > 0) {
        qty = Math.round((cliffPeriods / totalPeriods) * total);
      } else {
        continue;
      }
    } else {
      const remaining = total - cumulative;
      const remainingPeriods = totalPeriods - i + 1;
      qty = Math.round(remaining / remainingPeriods);
    }
    cumulative += qty;
    tranches.push({ date: d.toISOString().slice(0, 10), qty, vested: d.getTime() <= now, isNext: false });
  }
  // Fix rounding to ensure cumulative === total
  const sum = tranches.reduce((s, t) => s + t.qty, 0);
  if (sum !== total && tranches.length > 0) tranches[tranches.length - 1].qty += (total - sum);

  const vestedQty = tranches.filter(t => t.vested).reduce((s, t) => s + t.qty, 0);
  const pendingQty = total - vestedQty;
  const nextTranche = tranches.find(t => !t.vested);
  if (nextTranche) nextTranche.isNext = true;

  return { tranches, vestedQty, pendingQty, nextTranche };
}

function computePlanTotalVested() {
  return (Store.get('aktienplaene') || []).reduce((s, p) => {
    const v = computeVesting(p);
    return s + v.vestedQty * (p.kurs || 0);
  }, 0);
}

function computeUpcomingVesting(days = 90) {
  const out = [];
  (Store.get('aktienplaene') || []).forEach(p => {
    if (p.status === 'Verkauft' || p.status === 'Verfallen') return;
    const v = computeVesting(p);
    v.tranches.forEach(t => {
      if (t.vested) return;
      const d = daysUntil(t.date);
      if (d !== null && d >= 0 && d <= days) {
        out.push({ date: t.date, qty: t.qty, planId: p.id, planName: p.bezeichnung, wert: t.qty * (p.kurs || 0) });
      }
    });
  });
  return out.sort((a, b) => a.date.localeCompare(b.date));
}

/* =====================================================================
 * Global search
 * ===================================================================== */
function globalSearch(q) {
  if (!q || q.length < 2) return [];
  q = q.toLowerCase();
  const out = [];
  const push = (view, list, label) => {
    list.forEach(x => {
      const blob = JSON.stringify(x).toLowerCase();
      if (blob.includes(q)) out.push({ view, id: x.id, label: `${label}: ${x.bezeichnung || x.id}` });
    });
  };
  push('kv', Store.get('kv') || [], 'KV');
  push('lv', Store.get('lv') || [], 'LV');
  push('einkuenfte', Store.get('einkuenfte') || [], 'Einkunft');
  push('ausgaben', Store.get('ausgaben') || [], 'Ausgabe');
  push('investments', Store.get('investments') || [], 'Investment');
  push('aktienplaene', Store.get('aktienplaene') || [], 'Aktienplan');
  return out;
}

function renderSearchResults(results) {
  const list = el('div', { className: 'card' },
    el('h3', {}, `Suchergebnisse (${results.length})`),
    results.length === 0
      ? el('p', { className: 'muted' }, 'Keine Treffer.')
      : el('ul', { className: 'menu-list' },
        ...results.map(r => el('li', {}, el('button', { onClick: () => { closeModal(); navigate(r.view, { selectedId: r.id }); } }, r.label)))
      ),
    el('div', { className: 'form-actions' }, el('button', { className: 'btn', onClick: closeModal }, 'Schliessen'))
  );
  openModal(list);
}

/* =====================================================================
 * CSV / Backup
 * ===================================================================== */
function exportCsv() {
  const view = App.currentView;
  if (!['kv', 'lv', 'einkuenfte', 'ausgaben', 'investments', 'aktienplaene'].includes(view)) {
    showToast('CSV nur für Modul-Ansichten', 'err'); return;
  }
  const list = Store.get(view);
  if (!list || list.length === 0) { showToast('Keine Daten zum Exportieren', 'err'); return; }
  const keys = [...new Set(list.flatMap(x => Object.keys(x)))].filter(k => !['payments', 'sondertilgungen', 'transactions', 'events'].includes(k));
  const rows = [keys.join(';')];
  list.forEach(x => rows.push(keys.map(k => csvCell(x[k])).join(';')));
  const blob = new Blob(['﻿' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, `${view}_${todayISO()}.csv`);
}
function csvCell(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') v = JSON.stringify(v);
  v = String(v);
  if (v.includes(';') || v.includes('"') || v.includes('\n')) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}
function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = el('a', { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function downloadBackup() {
  const payload = Store.exportEncryptedBackup();
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `finanzen_backup_${todayISO()}.json`);
  showToast('Verschlüsseltes Backup heruntergeladen');
}

/* =====================================================================
 * Menu (⋯)
 * =================================================================== */
function openDataMenu() {
  const menu = el('div', {},
    el('h3', {}, 'Daten & Einstellungen'),
    el('ul', { className: 'menu-list' },
      el('li', {}, el('button', { onClick: () => { closeModal(); downloadBackup(); } }, '⬇️  Verschlüsseltes Backup (.json)')),
      el('li', {}, el('button', { onClick: () => { closeModal(); restoreBackupPrompt(); } }, '⬆️  Backup wiederherstellen')),
      el('li', { className: 'divider' }),
      el('li', {}, el('button', { onClick: () => { closeModal(); openChangePinForm(); } }, '🔑  PIN ändern')),
      el('li', {}, el('button', { onClick: () => { closeModal(); openSettingsForm(); } }, '⚙️  Einstellungen')),
      el('li', { className: 'divider' }),
      el('li', {}, el('button', { onClick: () => { closeModal(); offerDemoData(); } }, '🎬  Demo-Daten laden')),
      el('li', {}, el('button', { onClick: async () => {
        if (!confirm('Wirklich ALLE Finanzdaten löschen (PIN bleibt erhalten)?')) return;
        for (const n of ['kv', 'lv', 'einkuenfte', 'ausgaben', 'investments', 'aktienplaene']) await Store.save(n, []);
        await Store.save('counters', {});
        closeModal(); render(); showToast('Alle Datensätze entfernt');
      } }, '🗑️  Alle Datensätze löschen')),
      el('li', { className: 'divider' }),
      el('li', {}, el('button', { onClick: () => { closeModal(); Auth.lock(); } }, '🔒  Sperren / Abmelden')),
    ),
    el('div', { className: 'form-actions' }, el('button', { className: 'btn', onClick: closeModal }, 'Schliessen'))
  );
  openModal(menu);
}

function restoreBackupPrompt() {
  const form = el('div', {},
    el('h3', {}, 'Backup wiederherstellen'),
    el('p', { className: 'small' }, 'JSON-Backup einlesen. Hinweis: PIN wird ebenfalls aus dem Backup übernommen.'),
    el('input', { type: 'file', accept: '.json', id: 'restoreFile2' }),
    el('div', { className: 'form-actions' },
      el('button', { className: 'btn ghost', onClick: closeModal }, 'Abbrechen'),
      el('button', { className: 'btn primary', onClick: async () => {
        const f = $('#restoreFile2').files[0];
        if (!f) { showToast('Keine Datei', 'err'); return; }
        try {
          const txt = await f.text();
          const data = JSON.parse(txt);
          if (data.version !== 1) { showToast('Falsche Version', 'err'); return; }
          Store.importEncryptedBackup(data);
          Auth.lock();
          showToast('Backup geladen – neu anmelden');
        } catch (e) {
          showToast('Fehler: ' + e.message, 'err');
        }
      } }, 'Importieren')
    )
  );
  openModal(form);
}

function openChangePinForm() {
  const form = el('form', {},
    el('h3', {}, 'PIN ändern'),
    el('div', { className: 'form-grid' },
      el('label', { className: 'full' }, el('span', { className: 'lbl' }, 'Aktuelle PIN'),
        el('input', { type: 'password', inputmode: 'numeric', maxlength: 6, pattern: '[0-9]{6}', name: 'old', required: true })),
      el('label', { className: 'full' }, el('span', { className: 'lbl' }, 'Neue PIN (6 Ziffern)'),
        el('input', { type: 'password', inputmode: 'numeric', maxlength: 6, pattern: '[0-9]{6}', name: 'new', required: true })),
      el('label', { className: 'full' }, el('span', { className: 'lbl' }, 'Neue PIN wiederholen'),
        el('input', { type: 'password', inputmode: 'numeric', maxlength: 6, pattern: '[0-9]{6}', name: 'new2', required: true })),
    ),
    el('div', { className: 'form-actions' },
      el('button', { type: 'button', className: 'btn ghost', onClick: closeModal }, 'Abbrechen'),
      el('button', { type: 'submit', className: 'btn primary' }, 'PIN ändern')
    )
  );
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(form).entries());
    if (fd.new !== fd.new2) { showToast('Neue PINs stimmen nicht überein', 'err'); return; }
    if (!/^[0-9]{6}$/.test(fd.new)) { showToast('Neue PIN muss 6 Ziffern sein', 'err'); return; }
    try {
      await Auth.changePin(fd.old, fd.new);
      closeModal();
      showToast('PIN geändert');
    } catch (e) {
      showToast(e.message, 'err');
    }
  });
  openModal(form);
}

function openSettingsForm() {
  const s = Store.get('settings');
  const form = el('form', {},
    el('h3', {}, 'Einstellungen'),
    el('div', { className: 'form-grid' },
      el('label', { className: 'full' }, el('span', { className: 'lbl' }, 'Auto-Sperre nach (Minuten Inaktivität)'),
        el('input', { type: 'number', name: 'autoLock', value: s.autoLock || 15, min: 1, max: 60 })),
      el('label', { className: 'full' }, el('span', { className: 'lbl' }, 'Konzentrationslimit Mitarbeiteraktien (%)'),
        el('input', { type: 'number', name: 'concentrationLimit', value: s.concentrationLimit || 30, min: 1, max: 100 })),
    ),
    el('div', { className: 'form-actions' },
      el('button', { type: 'button', className: 'btn ghost', onClick: closeModal }, 'Abbrechen'),
      el('button', { type: 'submit', className: 'btn primary' }, 'Speichern')
    )
  );
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(form).entries());
    s.autoLock = parseInt(fd.autoLock, 10);
    s.concentrationLimit = parseInt(fd.concentrationLimit, 10);
    await Store.save('settings', s);
    closeModal();
    resetIdleTimer();
    render();
    showToast('Gespeichert');
  });
  openModal(form);
}

/* =====================================================================
 * INIT
 * =================================================================== */
function installShellHandlers() {
  $$('.nav-btn').forEach(b => b.addEventListener('click', () => navigate(b.dataset.view)));
  $('#dataMenuBtn').addEventListener('click', openDataMenu);
  $('#lockBtn').addEventListener('click', () => Auth.lock());
  $('#globalSearch').addEventListener('input', e => {
    App.searchTerm = e.target.value;
  });
  $('#globalSearch').addEventListener('keydown', e => {
    if (e.key === 'Enter' && App.searchTerm.length >= 2) {
      renderSearchResults(globalSearch(App.searchTerm));
    }
  });
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); $('#globalSearch').focus(); }
    if (e.key === 'Escape' && $('#modal').open) closeModal();
  });
  // Enter-key safety net: prevent default reload, trigger primary action button instead.
  $('#modal').addEventListener('submit', e => {
    if (e.defaultPrevented) return;
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('.btn.primary:not(:disabled)');
    if (btn) btn.click();
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupPinHandlers();
  installShellHandlers();
  installIdleHandlers();
  ensureBootstrapped();
  showLogin();
});
