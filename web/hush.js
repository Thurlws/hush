// The hush protocol for the browser: the same handshake, encryption and
// trust rules as src/client.c, so browser and terminal users can talk.
// No DOM in here; app.js draws the page, and tests can run this in Node.

const T = { HELLO: 1, AUTH: 2, SEND: 3, CHALLENGE: 10, WELCOME: 11, PEER: 12, LEAVE: 13, DELIVER: 14, ERROR: 15 };
const AUTH_CONTEXT = "hush-auth-v2";
const KIND_ROOM = 0, KIND_DM = 1;
const PLAIN_MIN = 10; // u8 kind | u64 counter | u8 len | sender name | text
const NONCE = 24, MAC = 16;
export const MAX_TEXT = 4000;
export const KEY_MAX = 64;
export const NAME_RE = /^[A-Za-z0-9_.-]{1,24}$/;

const enc = new TextEncoder(), dec = new TextDecoder();

// A libsodium Ed25519 secret key is seed || public key.
export const publicKey = sk => sk.slice(32);

export function fingerprint(sodium, pk) {
  return sodium.to_hex(sodium.crypto_generichash(16, pk)).match(/.{4}/g).join(" ");
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

function nameBytes(name) {
  const b = enc.encode(name);
  return concat(Uint8Array.of(b.length), b);
}

// [name, offset after it], or null if it isn't a valid name.
function readName(p, off = 0) {
  if (off >= p.length || off + 1 + p[off] > p.length) return null;
  const s = dec.decode(p.subarray(off + 1, off + 1 + p[off]));
  return NAME_RE.test(s) ? [s, off + 1 + p[off]] : null;
}

// Events passed to onEvent, as { type, ... }:
//   ready {label}            logged in to the chat called label
//   peer {name, joined, first, trust: "ok"|"changed"|"bad", verified, fp, oldFp}
//   leave {name}
//   message {from, text, dm, to}   to is set for your own DMs
//   notice {level: "info"|"warn", text}
//   error {text}             the server refused something
//   closed {error, wasReady, quit}   error is set if the server refused us
export class Session {
  constructor({ sodium, url, name, key, secretKey, known, WebSocket: WS = globalThis.WebSocket }, onEvent) {
    this.s = sodium;
    this.name = name;
    this.key = key;
    this.sk = secretKey;
    this.pk = publicKey(secretKey);
    this.xsk = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey);
    this.known = known;
    this.emit = onEvent;
    this.peers = new Map();
    this.ctr = 0n;
    this.ready = false;
    this.lastError = null;
    this.quit = false;
    this.ws = new WS(url);
    this.ws.binaryType = "arraybuffer";
    this.ws.onopen = () => this.hello();
    this.ws.onmessage = e => this.onFrame(new Uint8Array(e.data));
    // The server closes with code 4000 when it refuses us; anything else is a dropped connection.
    this.ws.onclose = e => this.emit({ type: "closed", wasReady: this.ready, quit: this.quit,
                                       error: e.code === 4000 || !this.ready ? this.lastError : null });
  }

  get myFingerprint() { return fingerprint(this.s, this.pk); }

  close() { this.quit = true; this.ws.close(); }

  send(type, ...parts) {
    if (this.ws.readyState === 1) this.ws.send(concat(Uint8Array.of(type), ...parts));
  }

  notice(text, level = "info") { this.emit({ type: "notice", level, text }); }

  hello() {
    const key = enc.encode(this.key);
    this.key = null;
    this.send(T.HELLO, nameBytes(this.name), this.pk, Uint8Array.of(key.length), key);
  }

  onFrame(f) {
    if (!f.length) return;
    const type = f[0], p = f.subarray(1);
    if (type === T.ERROR) {
      this.lastError = clean(dec.decode(p));
      this.emit({ type: "error", text: this.lastError });
    } else if (!this.ready) {
      if (type === T.CHALLENGE && p.length === 32) {
        this.send(T.AUTH, this.s.crypto_sign_detached(concat(enc.encode(AUTH_CONTEXT), p), this.sk));
      } else if (type === T.WELCOME && readName(p)) {
        this.ready = true;
        this.lastError = null;
        this.emit({ type: "ready", label: readName(p)[0] });
      } else {
        this.lastError = "unexpected reply from the server";
        this.ws.close();
      }
    } else if (type === T.PEER) this.onPeer(p);
    else if (type === T.LEAVE) this.onLeave(p);
    else if (type === T.DELIVER) this.onDeliver(p);
  }

  onPeer(p) {
    const r = readName(p);
    if (!r || p.length - r[1] !== 33 || r[0] === this.name) return;
    const [name, off] = r, pk = p.slice(off, off + 32), joined = p[off + 32] === 1;
    let pe = this.peers.get(name);
    if (!pe) this.peers.set(name, pe = { name, lastCtr: 0n });
    pe.pk = pk;
    pe.online = true;

    let kn = this.known.get(name);
    const first = !kn;
    if (first) this.known.set(name, kn = { pk: this.s.to_hex(pk), verified: false });
    pe.trust = kn.pk === this.s.to_hex(pk) ? "ok" : "changed";
    if (pe.trust === "ok" && !this.derive(pe)) pe.trust = "bad";
    const oldFp = pe.trust === "changed" ? fingerprint(this.s, this.s.from_hex(kn.pk)) : null;
    this.emit({ type: "peer", name, joined, first, trust: pe.trust, verified: kn.verified,
                fp: fingerprint(this.s, pk), oldFp });
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

  onDeliver(p) {
    const r = readName(p);
    if (!r) return;
    const [name, off] = r, blob = p.subarray(off), pe = this.peers.get(name);
    if (!pe || pe.trust !== "ok") return this.notice(`dropped a message from ${name} (key not trusted)`, "warn");
    if (blob.length < NONCE + MAC + PLAIN_MIN || blob.length > NONCE + MAC + PLAIN_MIN + 24 + MAX_TEXT)
      return this.notice(`dropped a malformed message from ${name}`, "warn");
    let plain;
    try {
      plain = this.s.crypto_box_open_easy_afternm(blob.subarray(NONCE), blob.subarray(0, NONCE), pe.key);
    } catch {
      return this.notice(`a message from ${name} failed to decrypt (tampered with?)`, "warn");
    }
    const ctr = new DataView(plain.buffer, plain.byteOffset).getBigUint64(1);
    const nl = plain[9], hdr = PLAIN_MIN + nl;
    if (hdr > plain.length || dec.decode(plain.subarray(PLAIN_MIN, hdr)) !== name)
      return this.notice(`dropped a message relabelled as coming from ${name}`, "warn");
    if (ctr <= pe.lastCtr) return this.notice(`dropped a replayed message from ${name}`, "warn");
    pe.lastCtr = ctr;
    this.emit({ type: "message", from: name, text: clean(dec.decode(plain.subarray(hdr))), dm: plain[0] === KIND_DM });
  }

  // Encrypt text for every online trusted peer (or just `only`). Returns how many copies went out.
  sendText(kind, only, text) {
    const t = enc.encode(text), me = enc.encode(this.name);
    const now = BigInt(Date.now()) * 1000n;
    this.ctr = now > this.ctr ? now : this.ctr + 1n;
    const plain = new Uint8Array(PLAIN_MIN + me.length + t.length);
    plain[0] = kind;
    new DataView(plain.buffer).setBigUint64(1, this.ctr);
    plain[9] = me.length;
    plain.set(me, PLAIN_MIN);
    plain.set(t, PLAIN_MIN + me.length);

    let sent = 0;
    for (const pe of this.peers.values()) {
      if ((only && pe !== only) || !pe.online) continue;
      if (pe.trust !== "ok") {
        this.notice(`not sent to ${pe.name}: their key changed, see /help`, "warn");
        continue;
      }
      const nonce = this.s.randombytes_buf(NONCE);
      this.send(T.SEND, nameBytes(pe.name), nonce, this.s.crypto_box_easy_afternm(plain, nonce, pe.key));
      sent++;
    }
    plain.fill(0);
    return sent;
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
      else this.notice("unknown command; try /help", "warn");
      return;
    }
    const text = s[0] === "/" ? s.slice(1) : s;
    if (!this.fits(text)) return;
    if (this.sendText(KIND_ROOM, null, text) > 0) this.emit({ type: "message", from: this.name, text: clean(text), dm: false });
    else if (!this.online().length) this.notice("(message not sent: nobody else is here)");
  }

  fits(text) {
    if (enc.encode(text).length <= MAX_TEXT) return true;
    this.notice(`message too long (at most ${MAX_TEXT} bytes)`, "warn");
    return false;
  }

  help() {
    this.notice("Type a message and press Enter to send it to everyone here.\n" +
      "  /msg NAME TEXT   private message to one person\n" +
      "  /who             who's here, with fingerprints\n" +
      "  /fp [NAME]       your fingerprint, or NAME's\n" +
      "  /verify NAME     mark NAME as verified after comparing fingerprints\n" +
      "  /trust NAME      accept NAME's new key after it changed (verify it first!)\n" +
      "  /quit            leave\n" +
      "  //text           send a message that starts with /");
  }

  who() {
    const lines = ["here:"];
    for (const name of this.online()) {
      const pe = this.peers.get(name), kn = this.known.get(name);
      const label = pe.trust !== "ok" ? "KEY CHANGED" : kn && kn.verified ? "verified" : "unverified";
      lines.push(`  ${name.padEnd(12)}  ${fingerprint(this.s, pe.pk)}  ${label}`);
    }
    if (lines.length === 1) lines.push("  (just you)");
    this.notice(lines.join("\n"));
  }

  dm(arg) {
    const m = /^(\S+)\s+(.+)$/.exec(arg);
    if (!m) return this.notice("usage: /msg NAME TEXT");
    const pe = this.peers.get(m[1]);
    if (!pe || !pe.online) return this.notice(`${m[1]} is not here`, "warn");
    if (this.fits(m[2]) && this.sendText(KIND_DM, pe, m[2]) > 0)
      this.emit({ type: "message", from: this.name, text: clean(m[2]), dm: true, to: pe.name });
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
    pe.lastCtr = 0n;
    this.notice(`accepted ${name}'s new key ${fingerprint(this.s, pe.pk)} (unverified)`);
  }
}
