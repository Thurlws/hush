// The hush protocol for the browser. Same keys, encryption and trust rules
// as src/client.c (see src/proto.h), so browser and terminal users share a
// chat. No DOM here: app.js draws the page and tests run this in Node.

const T = {
  HELLO: 1, AUTH: 2, POST: 3, HISTORY: 4, UPLOAD: 5, FETCH: 6, DECIDE: 7, NEWCHAT: 8, MANAGE: 9,
  CHALLENGE: 10, WELCOME: 11, PEER: 12, LEAVE: 13, MSG: 14, ERROR: 15, HISTORY_END: 16, UPLOADED: 17, BLOB: 18,
  WAITING: 19, PENDING: 20, CREATED: 21, ADMIN: 22, ITEM: 23, LIST_END: 24, DONE: 25, SHARED: 26, CLEARED: 27,
  RENAMED: 28,
};
export const MG = { LIST: 0, KICK: 1, REMOVE: 2, BAN: 3, UNBAN: 4, SHARE: 5, CLEAR: 6, REVOKE: 7, RENAME: 8, DECIDE: 9 };
const HIST_OLDER = 0, HIST_NEWER = 1, HIST_MINE = 2, WELCOME_ADMIN = 1;
const PEER_ONLINE = 1, PEER_NEW = 2, PEER_REMOVED = 4, UP_FIRST = 1, UP_LAST = 2, BLOB_LAST = 1, BLOB_MISSING = 2;
export const LIST = { SESSIONS: 0, CHATS: 1, MEMBERS: 2, BANS: 3 };
const KIND_TEXT = 0, KIND_IMAGE = 1, VERSION = 3, PROTOCOL = 2; // PROTOCOL matches HUSH_PROTO
const AUTH_CONTEXT = "hush-auth-v3", MSG_CONTEXT = "hush-msg-v3";
const NONCE = 24, MAC = 16, SIG = 64, HEAD = 26, CHUNK = 48 * 1024;
export const MAX_TEXT = 4000;
export const MAX_IMAGE = 25 * 1024 * 1024;
export const KEY_MAX = 64;
export const NAME_RE = /^[A-Za-z0-9_.-]{1,24}$/;
export const IMAGE_TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp" };
const PAGE = 50;

const enc = new TextEncoder(), dec = new TextDecoder();

// A libsodium Ed25519 secret key is seed || public key.
export const publicKey = sk => sk.slice(32);

export function fingerprint(sodium, pk) {
  return sodium.to_hex(sodium.crypto_generichash(16, pk)).match(/.{4}/g).join(" ");
}

const KEY_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

// Normalize a typed chat key: case, dashes and spaces don't matter, o/i/l
// count as 0/1/1. null if it can't be a key. Keys are 8 chars, old ones 24.
export function normalizeKey(typed) {
  let norm = "";
  for (let ch of typed.toLowerCase()) {
    if (ch === "-" || ch === " ") continue;
    if (ch === "o") ch = "0";
    else if (ch === "i" || ch === "l") ch = "1";
    if (!KEY_ALPHABET.includes(ch) || norm.length === 24) return null;
    norm += ch;
  }
  return norm.length === 8 || norm.length === 24 ? norm : null;
}

// A new random chat key, as xxxx-xxxx.
export function newChatKey(sodium) {
  let k = "";
  for (let i = 0; i < 8; i++) k += (i === 4 ? "-" : "") + KEY_ALPHABET[sodium.randombytes_uniform(32)];
  return k;
}

// The login token (all the server sees) and the chat's encryption key, from
// a chat key as typed. Same as chat_key_derive() in src/proto.c: short keys
// go through Argon2id (a tenth of a second or so), so results are kept.
const derived = new Map();
export function deriveChatKey(sodium, typed) {
  const norm = normalizeKey(typed);
  if (!norm) return null;
  if (derived.has(norm)) return derived.get(norm);
  const gh = (data, ctx) => sodium.crypto_generichash(32, data, enc.encode(ctx));
  let out;
  if (norm.length === 24) {
    out = { token: gh(enc.encode(norm), "hush-chat-login-v3"), chatKey: gh(enc.encode(norm), "hush-chat-crypt-v3") };
  } else {
    const master = sodium.crypto_pwhash(64, enc.encode(norm), enc.encode("hush-chat-key-v4"), 3, 128 * 1024 * 1024,
                                        sodium.crypto_pwhash_ALG_ARGON2ID13);
    out = { token: gh(master, "hush-chat-login-v4"), chatKey: gh(master, "hush-chat-crypt-v4") };
    master.fill(0);
  }
  derived.set(norm, out);
  return out;
}

// Untrusted text is only ever shown with textContent, but it could still
// disguise itself with control characters or bidi overrides, so drop those.
export function clean(s) {
  return s.replace(/[\t\n]/g, " ").replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, "?");
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const u16 = v => Uint8Array.of(v >> 8, v & 255);
const u32v = v => Uint8Array.of(v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
const u32 = v => Uint8Array.of(v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
const view = p => new DataView(p.buffer, p.byteOffset, p.byteLength);
const nameBytes = name => { const b = enc.encode(name); return concat(Uint8Array.of(b.length), b); };

// [name, offset after it], or null. With emptyOk, a zero-length name ("the whole chat") is allowed.
function readName(p, off = 0, emptyOk = false) {
  if (off >= p.length || off + 1 + p[off] > p.length) return null;
  if (p[off] === 0) return emptyOk ? ["", off + 1] : null;
  const s = dec.decode(p.subarray(off + 1, off + 1 + p[off]));
  return NAME_RE.test(s) ? [s, off + 1 + p[off]] : null;
}

// [text, offset after it] for a u8-length printable ASCII field (addresses), or null.
function readText(p, off, emptyOk = false) {
  if (off >= p.length || off + 1 + p[off] > p.length || (!p[off] && !emptyOk)) return null;
  const t = dec.decode(p.subarray(off + 1, off + 1 + p[off]));
  return /^[\x21-\x7e]*$/.test(t) ? [t, off + 1 + p[off]] : null;
}

// Admin requests (MANAGE), for an admin in a chat or logged in only to manage (AdminLink).
// The server answers each one in order: a list with ITEMs and a LIST_END, anything else
// with a DONE. Every method returns a promise: the list, or the server's sentence.
export class Manager {
  constructor(sodium, send) {
    this.s = sodium;
    this.send = send;
    this.waiting = [];
  }

  request(op, ...args) {
    return new Promise((resolve, reject) => {
      this.waiting.push({ resolve, reject, items: [] });
      this.send(T.MANAGE, Uint8Array.of(op), ...args);
    });
  }

  list(what, chat = null) { return this.request(MG.LIST, Uint8Array.of(what), ...(chat === null ? [] : [nameBytes(chat)])); }
  sessions() { return this.list(LIST.SESSIONS); }
  chats() { return this.list(LIST.CHATS); }
  members(chat) { return this.list(LIST.MEMBERS, chat); }
  bans() { return this.list(LIST.BANS); }
  kick(id) { return this.request(MG.KICK, u32v(id)); }
  remove(chat, name) { return this.request(MG.REMOVE, nameBytes(chat), nameBytes(name)); }
  ban(address) { return this.request(MG.BAN, nameBytes(address)); }
  unban(address) { return this.request(MG.UNBAN, nameBytes(address)); }
  share(chat, name, days = 0) { return this.request(MG.SHARE, nameBytes(chat), nameBytes(name), u16(days)); }
  clear(chat) { return this.request(MG.CLEAR, nameBytes(chat)); }
  revoke(chat) { return this.request(MG.REVOKE, nameBytes(chat)); }
  rename(chat, label) { return this.request(MG.RENAME, nameBytes(chat), nameBytes(label)); }
  decide(chat, name, approve) { return this.request(MG.DECIDE, nameBytes(chat), Uint8Array.of(approve ? 1 : 0), nameBytes(name)); }

  // A frame for us? Returns true if it was.
  onFrame(type, p) {
    const w = this.waiting[0];
    if (type === T.ITEM) {
      const item = this.item(p);
      if (w && item) w.items.push(item);
    } else if (type === T.LIST_END) {
      if (w) { this.waiting.shift(); w.resolve(w.items); }
    } else if (type === T.DONE && p.length >= 2) {
      const text = clean(dec.decode(p.subarray(2)));
      if (w) { this.waiting.shift(); if (p[1]) w.resolve(text); else w.reject(new Error(text)); }
    } else {
      return false;
    }
    return true;
  }

  fail(err) {
    for (const w of this.waiting.splice(0)) w.reject(err);
  }

  item(p) {
    const v = p.length ? view(p) : null, big = o => Number(v.getBigUint64(o));
    if (p[0] === LIST.SESSIONS && p.length >= 14) {
      const a = readText(p, 14), n = a && readName(p, a[1], true), c = n && readName(p, n[1], true);
      if (!c || c[1] !== p.length) return null;
      const f = p[5];
      return { id: v.getUint32(1), web: !!(f & 1), admin: !!(f & 2), waiting: !!(f & 4), you: !!(f & 8), login: !!(f & 16),
               connected: big(6), address: a[0], name: n[0], chat: c[0] };
    }
    if (p[0] === LIST.CHATS) {
      const l = readName(p, 1);
      if (!l || p.length - l[1] !== 37) return null;
      const o = l[1];
      return { label: l[0], old: p[o] === 1, members: v.getUint32(o + 1), waiting: v.getUint32(o + 5),
               online: v.getUint32(o + 9), messages: big(o + 13), images: big(o + 21), bytes: big(o + 29) };
    }
    if (p[0] === LIST.MEMBERS) {
      const n = readName(p, 1);
      if (!n || p.length - n[1] !== 50) return null;
      const o = n[1];
      return { name: n[0], fp: fingerprint(this.s, p.subarray(o, o + 32)), state: ["waiting", "in", "out"][p[o + 32]] || "out",
               online: !!(p[o + 33] & 1), admin: !!(p[o + 33] & 2), joined: big(o + 34), after: big(o + 42) };
    }
    if (p[0] === LIST.BANS) {
      const a = readText(p, 1), b = a && a[1] + 8 <= p.length && readName(p, a[1] + 8, true);
      if (!b || b[1] !== p.length) return null;
      return { address: a[0], time: big(a[1]), by: b[0] };
    }
    return null;
  }
}

// Admins: log in without a chat, to manage the server (the home page's "Manage server").
// Events: ready, closed {error}. Requests go through .manage once ready.
export class AdminLink {
  constructor({ sodium, url, name, secretKey, WebSocket: WS = globalThis.WebSocket }, onEvent) {
    this.s = sodium;
    this.ready = false;
    this.lastError = null;
    this.manage = new Manager(sodium, (type, ...parts) => {
      if (this.ws.readyState === 1) this.ws.send(concat(Uint8Array.of(type), ...parts));
    });
    this.ws = new WS(url);
    this.ws.binaryType = "arraybuffer";
    const send = (type, ...parts) => this.ws.send(concat(Uint8Array.of(type), ...parts));
    this.ws.onopen = () => send(T.HELLO, nameBytes(name), publicKey(secretKey), new Uint8Array(32), Uint8Array.of(PROTOCOL));
    this.ws.onmessage = e => {
      const f = new Uint8Array(e.data), type = f[0], p = f.subarray(1);
      if (type === T.ERROR) this.lastError = clean(dec.decode(p));
      else if (this.ready) this.manage.onFrame(type, p);
      else if (type === T.CHALLENGE && p.length === 32) send(T.AUTH, sodium.crypto_sign_detached(concat(enc.encode(AUTH_CONTEXT), p), secretKey));
      else if (type === T.ADMIN) { this.ready = true; onEvent({ type: "ready" }); }
    };
    this.ws.onclose = () => {
      this.manage.fail(new Error(this.lastError || "disconnected"));
      onEvent({ type: "closed", error: this.lastError });
    };
  }

  close() { this.ws.close(); }
}

// Admins: create a chat without being in one (the home page's "Create your
// own"). Logs in with no chat key, which the server allows only for admins.
// The key is made here and only its login token is sent. Resolves to {label, key}.
export function createChat({ sodium, url, name, secretKey, WebSocket: WS = globalThis.WebSocket }, label) {
  if (!NAME_RE.test(label)) return Promise.reject(new Error("a chat name is 1-24 letters, digits, _ . or -"));
  const key = newChatKey(sodium), { token } = deriveChatKey(sodium, key);
  return new Promise((resolve, reject) => {
    const ws = new WS(url);
    let done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      ws.close();
      if (err) reject(new Error(err));
      else resolve(value);
    };
    const send = (type, ...parts) => ws.send(concat(Uint8Array.of(type), ...parts));
    ws.binaryType = "arraybuffer";
    ws.onopen = () => send(T.HELLO, nameBytes(name), publicKey(secretKey), new Uint8Array(32), Uint8Array.of(PROTOCOL));
    ws.onmessage = e => {
      const f = new Uint8Array(e.data), type = f[0], p = f.subarray(1);
      if (type === T.ERROR) finish(clean(dec.decode(p)));
      else if (type === T.CHALLENGE && p.length === 32)
        send(T.AUTH, sodium.crypto_sign_detached(concat(enc.encode(AUTH_CONTEXT), p), secretKey));
      else if (type === T.ADMIN) send(T.NEWCHAT, nameBytes(label), token);
      else if (type === T.CREATED && readName(p) && readName(p)[0] === label) finish(null, { label, key });
      else finish("unexpected reply from the server");
    };
    ws.onclose = () => finish("couldn't reach the server");
  });
}

// Events passed to onEvent, as { type, ... }:
//   waiting {label}           on the chat's waitlist until an admin decides
//   ready {label, admin}      logged in to the chat called label
//   pending {name, fp, waiting}   admins: someone wants in (waiting) or was decided
//   peer {name, online, joined, first, trust: "ok"|"changed"|"bad", verified, fp, oldFp, wasOnline}
//   leave {name}              went offline
//   message {msg}             a new message (msg: see openMessage)
//   history {messages, dir, more}   a page of stored messages, oldest first
//   shared {days}             an admin let you see more history (days, or 0 for all of it). It loads as history
//   removed {name}            an admin removed name from the chat
//   cleared {}                an admin deleted the chat's history
//   renamed {label}           the chat has a new name
//   notice {level: "info"|"warn", text}
//   error {text}              the server refused something
//   closed {error, wasReady, quit}  error is set if the server refused us
export class Session {
  constructor({ sodium, url, name, key, secretKey, known, sinceId = 0, WebSocket: WS = globalThis.WebSocket }, onEvent) {
    const derived = deriveChatKey(sodium, key);
    if (!derived) throw new Error("that isn't a chat key");
    this.s = sodium;
    this.name = name;
    this.token = derived.token;
    this.chatKey = derived.chatKey;
    this.chatId = sodium.crypto_generichash(32, derived.chatKey);
    this.sk = secretKey;
    this.pk = publicKey(secretKey);
    this.xsk = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey);
    this.known = known;
    this.emit = onEvent;
    this.peers = new Map();
    this.seen = new Set();
    this.batch = [];
    this.oldestId = 0;
    this.newestId = sinceId;
    this.sinceId = sinceId;
    this.ready = false;
    this.lastError = null;
    this.quit = false;
    this.upload = null;
    this.admin = false;
    this.pending = new Map(); // admins: name -> fingerprint of people waiting
    this.manage = new Manager(sodium, (type, ...parts) => this.send(type, ...parts));
    this.exporting = null;
    this.fetches = new Map(); // blob id hex -> {image, resolve, reject, parts, size}
    this.fetchQueue = [];
    this.ws = new WS(url);
    this.ws.binaryType = "arraybuffer";
    this.ws.onopen = () => this.send(T.HELLO, nameBytes(this.name), this.pk, this.token, Uint8Array.of(PROTOCOL));
    this.ws.onmessage = e => this.onFrame(new Uint8Array(e.data));
    // Close code 4000 means the server refused us, anything else is a dropped connection.
    this.ws.onclose = e => {
      const err = new Error("disconnected");
      if (this.upload) this.upload.reject(err);
      if (this.exporting) this.exporting.reject(err);
      for (const f of this.fetches.values()) f.reject(err);
      for (const f of this.fetchQueue) f.reject(err);
      this.manage.fail(err);
      this.fetches.clear();
      this.fetchQueue = [];
      this.emit({ type: "closed", wasReady: this.ready, quit: this.quit,
                  error: e.code === 4000 || !this.ready ? this.lastError : null });
    };
  }

  get myFingerprint() { return fingerprint(this.s, this.pk); }

  close() { this.quit = true; this.ws.close(); }

  send(type, ...parts) {
    if (this.ws.readyState === 1) this.ws.send(concat(Uint8Array.of(type), ...parts));
  }

  notice(text, level = "info") { this.emit({ type: "notice", level, text }); }

  history(dir, anchor, limit = PAGE) {
    const p = new Uint8Array(11);
    p[0] = dir;
    view(p).setBigUint64(1, BigInt(anchor));
    view(p).setUint16(9, limit);
    this.send(T.HISTORY, p);
  }

  // Ask for older messages. They arrive as a "history" event.
  loadOlder() { if (this.oldestId && !this.exporting) this.history(HIST_OLDER, this.oldestId); }

  onFrame(f) {
    if (!f.length) return;
    const type = f[0], p = f.subarray(1);
    if (type === T.ERROR) {
      this.lastError = clean(dec.decode(p));
      if (this.upload && /image/.test(this.lastError)) this.upload.reject(new Error(this.lastError));
      this.emit({ type: "error", text: this.lastError });
    } else if (!this.ready) {
      if (type === T.CHALLENGE && p.length === 32) {
        this.send(T.AUTH, this.s.crypto_sign_detached(concat(enc.encode(AUTH_CONTEXT), p), this.sk));
      } else if (type === T.WAITING && readName(p)) {
        this.emit({ type: "waiting", label: readName(p)[0] });
      } else if (type === T.WELCOME && readName(p)) {
        const [label, off] = readName(p);
        this.label = label;
        this.ready = true;
        this.admin = off < p.length && (p[off] & WELCOME_ADMIN) !== 0;
        this.lastError = null;
        this.emit({ type: "ready", label, admin: this.admin });
        // Catch up after a reconnect, or start with the latest page.
        if (this.sinceId) this.history(HIST_NEWER, this.sinceId, 200);
        else this.history(HIST_OLDER, 0);
      } else {
        this.lastError = "unexpected reply from the server";
        this.ws.close();
      }
    } else if (type === T.PEER) this.onPeer(p);
    else if (type === T.LEAVE) this.onLeave(p);
    else if (type === T.MSG) this.onMsg(p);
    else if (type === T.HISTORY_END && p.length === 2) this.onHistoryEnd(p[0], p[1] === 1);
    else if (type === T.UPLOADED && p.length === 16 && this.upload) this.upload.resolve(p.slice());
    else if (type === T.BLOB && p.length >= 17) this.onBlob(p);
    else if (type === T.PENDING) this.onPending(p);
    else if (this.manage.onFrame(type, p)) { /* an admin request's answer */ }
    else if (type === T.CLEARED) {
      this.oldestId = this.newestId = 0;
      this.seen.clear();
      this.emit({ type: "cleared" });
    } else if (type === T.RENAMED && readName(p)) {
      this.label = readName(p)[0];
      this.emit({ type: "renamed", label: this.label });
    } else if (type === T.SHARED && p.length === 2) {
      this.emit({ type: "shared", days: view(p).getUint16(0) });
      if (!this.exporting) this.history(HIST_OLDER, this.oldestId);
    }
  }

  onPending(p) {
    const r = p.length > 1 && readName(p, 1);
    if (!r || p.length - r[1] !== 32) return;
    const name = r[0], fp = fingerprint(this.s, p.subarray(r[1]));
    if (p[0]) this.pending.set(name, fp);
    else this.pending.delete(name);
    this.emit({ type: "pending", name, fp, waiting: p[0] === 1 });
  }

  // Admins: let someone on the waitlist in, or turn them away. With days (0 for all
  // of it), they also get to see that much of the history from before.
  decide(name, approve, days = null) {
    if (!this.admin) return this.notice("only an admin can do that", "warn");
    if (!NAME_RE.test(name)) return this.notice(`usage: /${approve ? "approve" : "deny"} NAME`);
    this.send(T.DECIDE, Uint8Array.of(approve ? 1 : 0), nameBytes(name));
    if (approve && days !== null) this.share(name, days);
  }

  // Admins: let a member see the last days days of history, or all of it with 0.
  share(name, days = 0) {
    if (!this.admin) return this.notice("only an admin can do that", "warn");
    this.report(this.manage.share(this.label, name, days));
  }

  // Say how an admin request went.
  report(promise) {
    promise.then(text => { if (typeof text === "string") this.notice(text); }, e => this.notice(e.message, "warn"));
  }

  // Everything you sent in this chat and the DMs sent to you, decrypted:
  // resolves to a list of messages (see openMessage), oldest first.
  exportMine() {
    if (this.exporting) return Promise.reject(new Error("already exporting"));
    return new Promise((resolve, reject) => {
      this.exporting = { items: [], lastId: 0, resolve, reject };
      this.history(HIST_MINE, 0, 200);
    });
  }

  onPeer(p) {
    const r = readName(p);
    if (!r || p.length - r[1] !== 33 || r[0] === this.name) return;
    const [name, off] = r, pk = p.slice(off, off + 32), flags = p[off + 32];
    if (flags & PEER_REMOVED) {
      if (this.peers.delete(name)) this.emit({ type: "removed", name });
      return;
    }
    let pe = this.peers.get(name);
    if (!pe) this.peers.set(name, pe = { name, online: false });
    const wasOnline = pe.online;
    pe.pk = pk;
    pe.online = (flags & PEER_ONLINE) !== 0;

    let kn = this.known.get(name);
    const first = !kn;
    if (first) this.known.set(name, kn = { pk: this.s.to_hex(pk), verified: false });
    pe.trust = kn.pk === this.s.to_hex(pk) ? "ok" : "changed";
    if (pe.trust === "ok" && !this.derive(pe)) pe.trust = "bad";
    const oldFp = pe.trust === "changed" ? fingerprint(this.s, this.s.from_hex(kn.pk)) : null;
    this.emit({ type: "peer", name, online: pe.online, joined: (flags & PEER_NEW) !== 0, wasOnline, first,
                trust: pe.trust, verified: kn.verified, fp: fingerprint(this.s, pk), oldFp });
  }

  derive(pe) {
    try {
      pe.key = this.s.crypto_box_beforenm(this.s.crypto_sign_ed25519_pk_to_curve25519(pe.pk), this.xsk);
      return true;
    } catch {
      return false;
    }
  }

  onLeave(p) {
    const r = readName(p), pe = r && this.peers.get(r[0]);
    if (!pe) return;
    pe.online = false;
    this.emit({ type: "leave", name: pe.name });
  }

  onMsg(p) {
    if (p.length < 17) return;
    const id = Number(view(p).getBigUint64(0)), live = p[16] === 1;
    const a = readName(p, 17), b = a && readName(p, a[1], true);
    if (!b) return;
    if (this.exporting && !live) {
      const e = this.exporting;
      e.lastId = id;
      e.items.push(this.openMessage(id, a[0], b[0], p.subarray(b[1]), false) ||
                   { id, from: a[0], to: b[0], error: "could not be decrypted or verified" });
      return;
    }
    if (!live) this.oldestId = this.oldestId ? Math.min(this.oldestId, id) : id;
    this.newestId = Math.max(this.newestId, id);
    const msg = this.openMessage(id, a[0], b[0], p.subarray(b[1]));
    if (!msg) return;
    if (live) this.emit({ type: "message", msg });
    else this.batch.push(msg);
  }

  onHistoryEnd(dir, more) {
    if (dir === HIST_MINE && this.exporting) {
      const e = this.exporting;
      if (more) this.history(HIST_MINE, e.lastId, 200);
      else { this.exporting = null; e.resolve(e.items); }
      return;
    }
    const messages = this.batch;
    this.batch = [];
    this.emit({ type: "history", messages, dir, more });
    if (dir === HIST_NEWER && more) this.history(HIST_NEWER, this.newestId, 200); // keep catching up
  }

  // Decrypt and check one stored message. Returns
  // {id, time, from, to, dm, text} or {..., image: {fileKey, blob, size, width, height, mime, caption}},
  // or null (after a notice) if it can't be trusted.
  openMessage(id, from, to, body, dedupe = true) {
    const s = this.s, mine = from === this.name;
    const pe = mine ? null : this.peers.get(from);
    if (!mine && (!pe || pe.trust !== "ok")) {
      this.notice(`a message from ${from} isn't shown: ${pe ? "their key changed (see /help)" : "unknown sender"}`, "warn");
      return null;
    }
    let plain;
    try {
      const nonce = body.subarray(0, NONCE), ct = body.subarray(NONCE);
      if (to) {
        const dm = this.peers.get(mine ? to : from);
        if (!dm || dm.trust !== "ok") throw new Error("no key");
        plain = s.crypto_box_open_easy_afternm(ct, nonce, dm.key);
      } else {
        plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, this.chatKey);
      }
    } catch {
      this.notice(`a message from ${from} failed to decrypt (tampered with?)`, "warn");
      return null;
    }
    const signedLen = plain.length - SIG;
    const head = plain.subarray(0, Math.max(signedLen, 0));
    const a = signedLen >= HEAD + 2 && plain[0] === VERSION && readName(head, HEAD);
    const b = a && readName(head, a[1], true);
    if (!b || a[0] !== from || b[0] !== to) {
      this.notice(`dropped a message relabelled as coming from ${from}`, "warn");
      return null;
    }
    const signedData = concat(enc.encode(MSG_CONTEXT), this.chatId, head);
    if (!s.crypto_sign_verify_detached(plain.subarray(signedLen), signedData, mine ? this.pk : pe.pk)) {
      this.notice(`a message claiming to be from ${from} has a bad signature`, "warn");
      return null;
    }
    const uid = s.to_hex(plain.subarray(10, 26));
    if (dedupe && this.seen.has(uid)) return null;
    if (dedupe) this.seen.add(uid);

    const msg = { id, time: Number(view(plain).getBigUint64(2)), from, to, dm: to !== "" };
    const c = head.subarray(b[1]);
    if (plain[1] === KIND_TEXT) {
      msg.text = clean(dec.decode(c.subarray(0, MAX_TEXT)));
    } else if (plain[1] === KIND_IMAGE && c.length >= 57 && c[56] > 0 && c[56] < 32 && c.length >= 57 + c[56]) {
      const mime = dec.decode(c.subarray(57, 57 + c[56]));
      if (!IMAGE_TYPES[mime]) {
        this.notice(`${from} sent a file of a type that isn't shown`, "warn");
        return null;
      }
      msg.image = { fileKey: c.slice(0, 32), blob: c.slice(32, 48), size: view(c).getUint32(48),
                    width: view(c).getUint16(52), height: view(c).getUint16(54), mime,
                    caption: clean(dec.decode(c.subarray(57 + c[56]).subarray(0, MAX_TEXT))) };
    } else {
      return null;
    }
    plain.fill(0);
    return msg;
  }

  // Sign, encrypt and post. It comes back as a "message" event once stored.
  post(to, kind, content) {
    const s = this.s, time = new Uint8Array(8);
    view(time).setBigUint64(0, BigInt(Date.now()));
    const plain = concat(Uint8Array.of(VERSION, kind), time, s.randombytes_buf(16),
                         nameBytes(this.name), nameBytes(to ? to.name : ""), content);
    const sig = s.crypto_sign_detached(concat(enc.encode(MSG_CONTEXT), this.chatId, plain), this.sk);
    const full = concat(plain, sig), nonce = s.randombytes_buf(NONCE);
    const ct = to ? s.crypto_box_easy_afternm(full, nonce, to.key)
                  : s.crypto_aead_xchacha20poly1305_ietf_encrypt(full, null, null, nonce, this.chatKey);
    this.send(T.POST, nameBytes(to ? to.name : ""), nonce, ct);
    full.fill(0);
  }

  // Encrypt and upload an image, then post it. bytes should already be
  // stripped of metadata (app.js re-encodes photos). Resolves when posted.
  async sendImage(bytes, { mime, width = 0, height = 0, caption = "" }, onProgress = () => {}) {
    if (this.upload) throw new Error("wait for the image you're sending to finish");
    if (!IMAGE_TYPES[mime]) throw new Error("only jpeg, png, gif and webp images can be sent");
    if (bytes.length > MAX_IMAGE) throw new Error("image too big (25 MB at most)");
    const s = this.s, fileKey = s.crypto_aead_xchacha20poly1305_ietf_keygen(), nonce = s.randombytes_buf(NONCE);
    const blob = concat(nonce, s.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, nonce, fileKey));
    const done = new Promise((resolve, reject) => { this.upload = { resolve, reject }; });
    done.catch(() => {}); // handled below, or by the await
    try {
      for (let off = 0; off < blob.length; off += CHUNK) {
        const end = Math.min(off + CHUNK, blob.length);
        const flags = (off === 0 ? UP_FIRST : 0) | (end === blob.length ? UP_LAST : 0);
        this.send(T.UPLOAD, Uint8Array.of(flags), blob.subarray(off, end));
        onProgress(end / blob.length);
        while (this.ws.readyState === 1 && this.ws.bufferedAmount > 1 << 20) await new Promise(r => setTimeout(r, 50));
        if (this.ws.readyState !== 1) throw new Error("disconnected");
      }
      const id = await done;
      const m = enc.encode(mime), meta = concat(u32(bytes.length), u16(width), u16(height), Uint8Array.of(m.length));
      this.post(null, KIND_IMAGE, concat(fileKey, id, meta, m, enc.encode(caption).subarray(0, MAX_TEXT - 100)));
    } finally {
      this.upload = null;
      fileKey.fill(0);
    }
  }

  // Download and decrypt an image from a message. Resolves to its bytes.
  fetchImage(image) {
    return new Promise((resolve, reject) => {
      this.fetchQueue.push({ image, resolve, reject });
      this.pumpFetches();
    });
  }

  pumpFetches() {
    while (this.fetches.size < 8 && this.fetchQueue.length) {
      const f = this.fetchQueue.shift(), id = this.s.to_hex(f.image.blob);
      const same = this.fetches.get(id);
      if (same) { // already on its way: share the result
        const [res, rej] = [same.resolve, same.reject];
        same.resolve = v => { res(v); f.resolve(v); };
        same.reject = e => { rej(e); f.reject(e); };
        continue;
      }
      this.fetches.set(id, { ...f, parts: [], size: 0 });
      this.send(T.FETCH, f.image.blob);
    }
  }

  onBlob(p) {
    const id = this.s.to_hex(p.subarray(0, 16)), status = p[16], f = this.fetches.get(id);
    if (!f) return;
    if (status === BLOB_MISSING) {
      this.fetches.delete(id);
      f.reject(new Error("the server doesn't have this image any more"));
    } else {
      f.parts.push(p.slice(17));
      f.size += p.length - 17;
      if (f.size > MAX_IMAGE + NONCE + MAC) {
        this.fetches.delete(id);
        f.reject(new Error("image too big"));
      } else if (status === BLOB_LAST) {
        this.fetches.delete(id);
        try {
          const all = concat(...f.parts);
          f.resolve(this.s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, all.subarray(NONCE), null,
                                                                      all.subarray(0, NONCE), f.image.fileKey));
        } catch {
          f.reject(new Error("the image failed to decrypt (tampered with?)"));
        }
      }
    }
    this.pumpFetches();
  }

  online() {
    return [...this.peers.values()].filter(pe => pe.online).map(pe => pe.name).sort();
  }

  // One line typed by the user: a message or a /command.
  input(line) {
    const s = line.replace(/ +$/, "");
    if (!s) return;
    if (s[0] === "/" && s[1] !== "/") {
      const m = /^\/(\S+)\s*(.*)$/.exec(s), cmd = m ? m[1] : "", arg = m ? m[2] : "";
      if (cmd === "quit" || cmd === "q") this.close();
      else if (cmd === "help" || cmd === "h") this.help();
      else if (cmd === "who" || cmd === "w") this.who();
      else if (cmd === "msg" || cmd === "m") this.dm(arg);
      else if (cmd === "fp") this.fp(arg);
      else if (cmd === "verify") this.verify(arg);
      else if (cmd === "trust") this.trust(arg);
      else if (cmd === "approve" || cmd === "share") this.shareCommand(cmd, arg);
      else if (cmd === "deny") this.decide(arg, false);
      else if (cmd === "waiting") this.listWaiting();
      else if (["sessions", "kick", "chats", "members", "remove", "ban", "unban", "bans"].includes(cmd)) this.adminCommand(cmd, arg);
      else this.notice("unknown command; try /help", "warn");
      return;
    }
    const text = s[0] === "/" ? s.slice(1) : s;
    if (this.fits(text)) this.post(null, KIND_TEXT, enc.encode(text));
  }

  // /approve NAME [DAYS|all], /share NAME [DAYS]
  shareCommand(cmd, arg) {
    const m = /^(\S+)(?:\s+(all|\d+))?$/.exec(arg), days = m && m[2] ? (m[2] === "all" ? 0 : Number(m[2])) : null;
    if (!m || (m[2] && m[2] !== "all" && (days < 1 || days > 65535)))
      return this.notice(`usage: /${cmd} NAME [DAYS|all]`);
    if (cmd === "approve") this.decide(m[1], true, days);
    else this.share(m[1], days ?? 0);
  }

  // /sessions, /kick N, /chats, /members [CHAT], /remove NAME, /ban ADDRESS, /unban ADDRESS, /bans
  adminCommand(cmd, arg) {
    if (!this.admin) return this.notice("only an admin can do that", "warn");
    const m = this.manage, when = ms => new Date(ms).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
    const show = (title, rows) => this.notice(`${title}\n${rows.length ? rows.join("\n") : "  (none)"}`);
    if (cmd === "sessions")
      return m.sessions().then(list => show("connected:", list.map(x =>
        `  #${x.id}  ${(x.name || "?").padEnd(12)}  ${x.chat ? `in ${x.chat}` : x.login ? "logging in" : "managing"}` +
        `${x.waiting ? " (waiting)" : ""}  ${x.web ? "web" : "terminal"}  ${x.address}  since ${when(x.connected)}${x.you ? "  (you)" : ""}`)),
      e => this.notice(e.message, "warn"));
    if (cmd === "chats")
      return m.chats().then(list => show("chats:", list.map(x => x.old ? `  ${x.label.padEnd(24)}  old key, can only be deleted` :
        `  ${x.label.padEnd(24)}  ${x.members} members, ${x.waiting} waiting, ${x.online} online, ${x.messages} messages, ` +
        `${x.images} images (${(x.bytes / 1048576).toFixed(1)} MB)`)), e => this.notice(e.message, "warn"));
    if (cmd === "members")
      return m.members(arg || this.label).then(list => show(`in ${arg || this.label}:`, list.map(x =>
        `  ${x.name.padEnd(12)}  ${x.fp}  ${x.state === "in" ? "in" : x.state === "waiting" ? "waiting" : "turned away"}` +
        `${x.online ? ", online" : ""}${x.admin ? ", admin" : ""}` +
        (x.state !== "in" ? "" : x.after ? `, sees history after ${when(x.after)}` : ", sees all history"))),
      e => this.notice(e.message, "warn"));
    if (cmd === "bans")
      return m.bans().then(list => show("banned:", list.map(x =>
        `  ${x.address.padEnd(24)}  ${x.time ? when(x.time) : ""}${x.by ? `  by ${x.by}` : ""}`)), e => this.notice(e.message, "warn"));
    if (cmd === "kick") {
      if (!/^#?\d+$/.test(arg)) return this.notice("usage: /kick N   (N from /sessions)");
      return this.report(m.kick(Number(arg.replace("#", ""))));
    }
    if (cmd === "remove") {
      if (!NAME_RE.test(arg)) return this.notice("usage: /remove NAME");
      return this.report(m.remove(this.label, arg));
    }
    if (!/^\S+$/.test(arg)) return this.notice(`usage: /${cmd} ADDRESS`);
    this.report(cmd === "ban" ? m.ban(arg) : m.unban(arg));
  }

  fits(text) {
    if (enc.encode(text).length <= MAX_TEXT) return true;
    this.notice(`message too long (at most ${MAX_TEXT} bytes)`, "warn");
    return false;
  }

  help() {
    this.notice("Type a message and press Enter to send it to everyone in the chat.\n" +
      "  /msg NAME TEXT   private message to one person (they get it even if offline)\n" +
      "  /who             who's in the chat, with fingerprints\n" +
      "  /fp [NAME]       your fingerprint, or NAME's\n" +
      "  /verify NAME     mark NAME as verified after comparing fingerprints\n" +
      "  /trust NAME      accept NAME's new key after it changed (verify it first!)\n" +
      "  /quit            leave\n" +
      "  //text           send a message that starts with /\n" +
      "Send an image with the + button, or paste one. \"My data\" downloads everything you sent." +
      (this.admin ? "\nAs an admin:\n" +
        "  /waiting         who's waiting to join\n" +
        "  /approve NAME [DAYS|all]  let NAME in (check their fingerprint first), and let\n" +
        "                   them see the last DAYS days of history, or all of it\n" +
        "  /deny NAME       turn NAME away\n" +
        "  /share NAME [DAYS]  let NAME see history from before they joined: all of it,\n" +
        "                   or the last DAYS days\n" +
        "  /members [CHAT]  who's in this chat (or CHAT), and how much history they see\n" +
        "  /remove NAME     take NAME out of this chat (they'd have to be let in again)\n" +
        "  /sessions        everyone connected to the server\n" +
        "  /kick N          disconnect session N\n" +
        "  /chats           every chat on the server\n" +
        "  /ban ADDRESS     refuse an IP address, /unban ADDRESS, /bans to list them\n" +
        "Create chats on the home page: + Add session, then Create your own." : ""));
  }

  listWaiting() {
    if (!this.admin) return this.notice("only an admin can see the waitlist", "warn");
    if (!this.pending.size) return this.notice("nobody is waiting to join");
    this.notice([...this.pending].map(([n, fp]) => `  ${n} (${fp}): /approve ${n} or /deny ${n}`).join("\n"));
  }

  who() {
    const lines = ["in this chat:"];
    for (const pe of [...this.peers.values()].sort((a, b) => b.online - a.online || a.name.localeCompare(b.name))) {
      const kn = this.known.get(pe.name);
      const label = pe.trust !== "ok" ? "KEY CHANGED" : kn && kn.verified ? "verified" : "unverified";
      lines.push(`  ${pe.name.padEnd(12)}  ${fingerprint(this.s, pe.pk)}  ${label}${pe.online ? "  online" : ""}`);
    }
    if (lines.length === 1) lines.push("  (just you so far)");
    this.notice(lines.join("\n"));
  }

  dm(arg) {
    const m = /^(\S+)\s+(.+)$/.exec(arg);
    if (!m) return this.notice("usage: /msg NAME TEXT");
    const pe = this.peers.get(m[1]);
    if (!pe) return this.notice(`there is no ${m[1]} in this chat`, "warn");
    if (pe.trust !== "ok") return this.notice(`not sent to ${pe.name}: their key changed, see /help`, "warn");
    if (this.fits(m[2])) this.post(pe, KIND_TEXT, enc.encode(m[2]));
  }

  fp(name) {
    if (!name) return this.notice(`your fingerprint: ${this.myFingerprint}`);
    const pe = this.peers.get(name), kn = this.known.get(name);
    if (!pe && !kn) return this.notice(`never seen anyone called ${name}`, "warn");
    const pk = kn ? this.s.from_hex(kn.pk) : pe.pk;
    this.notice(`${name}: ${fingerprint(this.s, pk)} (${kn && kn.verified ? "verified" : "unverified"})`);
    if (pe && pe.trust === "changed") this.notice(`  their NEW key: ${fingerprint(this.s, pe.pk)}`, "warn");
  }

  verify(name) {
    const kn = this.known.get(name), pe = this.peers.get(name);
    if (!kn) return this.notice(`never seen anyone called ${name}`, "warn");
    if (pe && pe.trust !== "ok") return this.notice(`${name}'s key changed; confirm the new one and /trust ${name} first`, "warn");
    this.known.set(name, { ...kn, verified: true });
    this.notice(`${name} marked as verified (${fingerprint(this.s, this.s.from_hex(kn.pk))})`);
  }

  trust(name) {
    const pe = this.peers.get(name), kn = this.known.get(name);
    if (!pe || !kn || pe.trust !== "changed") return this.notice(`${name}'s key hasn't changed; nothing to do`);
    this.known.set(name, { pk: this.s.to_hex(pe.pk), verified: false });
    pe.trust = this.derive(pe) ? "ok" : "bad";
    this.notice(`accepted ${name}'s new key ${fingerprint(this.s, pe.pk)} (unverified)`);
  }
}
