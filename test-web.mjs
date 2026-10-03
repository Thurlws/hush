// Drives the web client's protocol code (web/hush.js) from the command line,
// the way test.sh drives hush: stdin lines are typed, events are printed.
//   node test-web.mjs NAME KEY URL ORIGIN [IDENTITY-FILE]
// Besides the chat commands: "/img FILE [caption]" sends an image as is,
// "/save FILE" saves the newest image seen, and "/mydata FILE" writes what
// "My data" would put in messages.json. "/newchat NAME" creates a chat the
// way the home page's "Create your own" does (admins).
// For server tests: "/raw TYPE HEX" sends any frame, even while waiting,
// "/garbage N" sends N random frames, "/lastblob" prints the newest image's
// blob id, and every BLOB reply is printed with its status.
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import sodium from "./web/sodium.mjs";
import { Session, createChat } from "./web/hush.js";

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

// Browsers always send Origin on the WebSocket handshake, Node only when asked.
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
const hex = b => Buffer.from(b).toString("hex");
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
  case "done": console.log(`${ev.ok ? "" : "! "}${ev.text}`); break;
  case "shared": console.log(`* history shared with you (${ev.days || "all"})`); break;
  case "error": console.log(`! server: ${ev.text}`); break;
  case "closed": console.log(`closed${ev.error ? `: ${ev.error}` : ""}`); process.exit(0);
  }
});

const onFrame = s.onFrame.bind(s);
s.onFrame = f => {
  if (f[0] === 18 && f.length >= 18) console.log(`blob ${hex(f.subarray(1, 17))} status ${f[17]}`);
  onFrame(f);
};

function raw(l) {
  const r = /^\/raw (\d+) ?([0-9a-f]*)$/.exec(l), g = /^\/garbage (\d+)$/.exec(l);
  if (r) s.send(Number(r[1]), Buffer.from(r[2], "hex"));
  for (let i = 0; g && i < Number(g[1]); i++)
    s.send(sodium.randombytes_uniform(32), sodium.randombytes_buf(sodium.randombytes_uniform(300)));
  return !!(r || g);
}

async function run(l) {
  const img = /^\/img (\S+) ?(.*)$/.exec(l), save = /^\/save (\S+)$/.exec(l), mine = /^\/mydata (\S+)$/.exec(l);
  try {
    if (img) {
      const mime = { jpg: "image/jpeg", png: "image/png", gif: "image/gif", webp: "image/webp" }[img[1].split(".").pop()];
      await s.sendImage(new Uint8Array(readFileSync(img[1])), { mime, width: 1, height: 1, caption: img[2] });
      console.log("image sent");
    } else if (/^\/newchat /.test(l)) {
      const { label, key } = await createChat({ sodium, url, name, secretKey: sk, WebSocket: WS }, l.slice(9));
      console.log(`created ${label} with key ${key}`);
    } else if (mine) {
      const items = await s.exportMine();
      writeFileSync(mine[1], JSON.stringify(items.map(m => ({ from: m.from, to: m.to, text: m.text, image: !!m.image })), null, 1));
      console.log(`my data: ${items.length} messages`);
    } else if (l === "/lastblob") {
      console.log(`lastblob ${lastImage ? hex(lastImage.blob) : "none"}`);
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
rl.on("line", l => raw(l) || (s.ready ? run(l) : queue.push(l)));
rl.on("close", () => setTimeout(() => s.close(), 300));
