// Drives the web client's protocol code (web/hush.js) from the command line,
// the way test.sh drives hush: stdin lines are typed, events are printed.
//   node test-web.mjs NAME KEY URL ORIGIN [IDENTITY-FILE]
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import sodium from "./web/sodium.mjs";
import { Session } from "./web/hush.js";

await sodium.ready;
const [name, key, url, origin, idFile] = process.argv.slice(2);

let sk;
try { sk = sodium.from_hex(readFileSync(idFile, "utf8").trim()); } catch { sk = null; }
if (!sk || sk.length !== 64) {
  sk = sodium.crypto_sign_keypair().privateKey;
  if (idFile) writeFileSync(idFile, sodium.to_hex(sk));
}
const knownMap = new Map();
const known = { get: n => knownMap.get(n) || null, set: (n, r) => knownMap.set(n, r) };

// Browsers always send Origin on a WebSocket handshake; Node doesn't unless asked.
class WS extends WebSocket {
  constructor(u) { super(u, { headers: origin ? { Origin: origin } : {} }); }
}

const queue = [];
const s = new Session({ sodium, url, name, key, secretKey: sk, known, WebSocket: WS }, ev => {
  switch (ev.type) {
  case "ready": console.log(`connected as ${name}, chat: ${ev.label}`); queue.splice(0).forEach(l => s.input(l)); break;
  case "peer":
    if (ev.trust === "changed") console.log(`!!! WARNING: ${ev.name}'s key has CHANGED !!!`);
    else console.log(`* ${ev.name} ${ev.joined ? "joined" : "is here"}${ev.first ? ". First time seeing them" : ""}`);
    break;
  case "leave": console.log(`* ${ev.name} left`); break;
  case "message": console.log(`${ev.dm ? (ev.to ? `[dm to ${ev.to}] ` : "[dm] ") : ""}${ev.from}: ${ev.text}`); break;
  case "notice": console.log(ev.text); break;
  case "error": console.log(`! server: ${ev.text}`); break;
  case "closed": console.log(`closed${ev.error ? `: ${ev.error}` : ""}`); process.exit(0);
  }
});
const rl = createInterface({ input: process.stdin });
rl.on("line", l => (s.ready ? s.input(l) : queue.push(l)));
rl.on("close", () => setTimeout(() => s.close(), 300));
