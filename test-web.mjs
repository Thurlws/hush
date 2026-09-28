// Drives the web client's protocol code (web/hush.js) from the command line,
// the way test.sh drives hush: stdin lines are typed, events are printed.
//   node test-web.mjs NAME KEY URL ORIGIN [IDENTITY-FILE]
// Besides the chat commands: "/img FILE [caption]" sends an image as is,
// "/save FILE" saves the newest image seen, and "/mydata FILE" writes what
// "My data" would put in messages.json. "/newchat NAME" creates a chat (admins).
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

let lastImage = null;
function show(m) {
  const tag = m.dm ? (m.from === name ? `[dm to ${m.to}] ` : "[dm] ") : "";
  if (m.image) {
    lastImage = m.image;
    console.log(`${tag}${m.from}: [image ${m.image.width}x${m.image.height} ${m.image.mime}] ${m.image.caption}`);
  } else {
    console.log(`${tag}${m.from}: ${m.text}`);
  }
}

const queue = [];
const s = new Session({ sodium, url, name, key, secretKey: sk, known, WebSocket: WS }, ev => {
  switch (ev.type) {
  case "waiting": console.log(`waiting for approval to join ${ev.label}`); break;
  case "ready":
    console.log(`connected as ${name}, chat: ${ev.label}${ev.admin ? " (admin)" : ""}`);
    queue.splice(0).forEach(run);
    break;
  case "pending": if (ev.waiting) console.log(`* ${ev.name} wants to join`); break;
  case "peer":
    if (ev.trust === "changed") console.log(`!!! WARNING: ${ev.name}'s key has CHANGED !!!`);
    else if (ev.first || ev.joined || (ev.online && !ev.wasOnline)) console.log(`* ${ev.name} ${ev.online ? "is online" : "is in this chat"}`);
    break;
  case "leave": console.log(`* ${ev.name} went offline`); break;
  case "message": show(ev.msg); break;
  case "history": ev.messages.forEach(show); if (ev.more) console.log("(more history)"); break;
  case "notice": console.log(ev.text); break;
  case "error": console.log(`! server: ${ev.text}`); break;
  case "closed": console.log(`closed${ev.error ? `: ${ev.error}` : ""}`); process.exit(0);
  }
});

async function run(l) {
  const img = /^\/img (\S+) ?(.*)$/.exec(l), save = /^\/save (\S+)$/.exec(l), mine = /^\/mydata (\S+)$/.exec(l);
  try {
    if (img) {
      const mime = { jpg: "image/jpeg", png: "image/png", gif: "image/gif", webp: "image/webp" }[img[1].split(".").pop()];
      await s.sendImage(new Uint8Array(readFileSync(img[1])), { mime, width: 1, height: 1, caption: img[2] });
      console.log("image sent");
    } else if (/^\/newchat /.test(l)) {
      const { label, key } = await s.createChat(l.slice(9));
      console.log(`created ${label} with key ${key}`);
    } else if (mine) {
      const items = await s.exportMine();
      writeFileSync(mine[1], JSON.stringify(items.map(m => ({ from: m.from, to: m.to, text: m.text, image: !!m.image })), null, 1));
      console.log(`my data: ${items.length} messages`);
    } else if (save) {
      writeFileSync(save[1], await s.fetchImage(lastImage));
      console.log(`saved ${save[1]}`);
    } else {
      s.input(l);
    }
  } catch (e) {
    console.log(`! ${e.message}`);
  }
}

const rl = createInterface({ input: process.stdin });
rl.on("line", l => (s.ready ? run(l) : queue.push(l)));
rl.on("close", () => setTimeout(() => s.close(), 300));
