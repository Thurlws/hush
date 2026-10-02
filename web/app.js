// The page: login form, chat log, input and images. The protocol is in hush.js.
import sodium from "./sodium.mjs";
import { Session, NAME_RE, KEY_MAX, MAX_IMAGE, IMAGE_TYPES, fingerprint, publicKey, normalizeKey, createChat } from "./hush.js";
import { zip } from "./zip.js";

const $ = id => document.getElementById(id);

// Storage can be blocked (private windows, strict settings), so work without it.
function storage(area) {
  return {
    get(k) { try { return area().getItem(k); } catch { return null; } },
    set(k, v) { try { area().setItem(k, v); return true; } catch { return false; } },
    del(k) { try { area().removeItem(k); } catch { /* nothing to remove */ } },
  };
}
const local = storage(() => localStorage), tab = storage(() => sessionStorage);

await sodium.ready;

// Your identity key is made here and never leaves this browser.
let sk = null;
try { sk = sodium.from_hex(local.get("hush.identity") || ""); } catch { sk = null; }
if (!sk || sk.length !== 64) {
  sk = sodium.crypto_sign_keypair().privateKey;
  if (!local.set("hush.identity", sodium.to_hex(sk)))
    $("login-error").textContent = "This browser won't keep your key, so you'll be a new person on every visit.";
}
const myFp = fingerprint(sodium, publicKey(sk));

// Keys pinned the first time we saw each person (a Map, since names like __proto__ are valid).
const knownMap = new Map();
try {
  for (const [n, r] of Object.entries(JSON.parse(local.get("hush.known") || "{}")))
    if (NAME_RE.test(n) && r && typeof r.pk === "string") knownMap.set(n, { pk: r.pk, verified: r.verified === true });
} catch { /* start fresh */ }
const known = {
  get: n => knownMap.get(n) || null,
  set(n, rec) { knownMap.set(n, rec); local.set("hush.known", JSON.stringify(Object.fromEntries(knownMap))); },
};

let chat = null, retries = 0, retryTimer = null, lastId = 0;
const shown = new Set(); // message ids on the page
const imageUrls = new Map(); // blob id -> object URL of the decrypted image
const history = [];
let hi = 0;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// Same colour choice as the terminal client (djb2 hash mod 6).
function hue(name) {
  let h = 5381;
  for (const c of new TextEncoder().encode(name)) h = (h * 33 + c) >>> 0;
  return "n" + (h % 6);
}

const nearBottom = () => { const l = $("log"); return l.scrollHeight - l.scrollTop - l.clientHeight < 80; };
const toBottom = () => { $("log").scrollTop = $("log").scrollHeight; };

function append(node) {
  const stick = nearBottom();
  $("msgs").append(node);
  if (stick) toBottom();
}

// All text reaches the page through textContent, never as HTML.
const line = (cls, text) => append(el("div", cls, text));

function stamp(ms) {
  const d = new Date(ms), now = new Date();
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return d.toDateString() === now.toDateString() ? time
    : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
}

const lazy = new IntersectionObserver(entries => {
  for (const e of entries) if (e.isIntersecting) { lazy.unobserve(e.target); e.target.load(); }
}, { root: null, rootMargin: "400px" });

function imageBox(msg) {
  const { image } = msg, id = sodium.to_hex(image.blob);
  const box = el("button", "img");
  box.type = "button";
  if (image.width && image.height) box.style.aspectRatio = `${image.width} / ${image.height}`;
  const label = el("span", "img-label", `image · ${(image.size / 1048576).toFixed(1)} MB`);
  box.append(label);
  box.load = async () => {
    try {
      let url = imageUrls.get(id);
      if (!url) {
        if (!chat || !chat.ready) throw new Error("not connected");
        label.textContent = "loading…";
        const bytes = await chat.fetchImage(image);
        url = URL.createObjectURL(new Blob([bytes], { type: image.mime }));
        imageUrls.set(id, url);
      }
      const img = el("img");
      img.alt = image.caption || `image from ${msg.from}`;
      img.src = url;
      box.replaceChildren(img);
      box.onclick = () => openViewer(url, `hush-${msg.id}.${IMAGE_TYPES[image.mime]}`, img.alt);
    } catch (e) {
      label.textContent = `${e.message}; tap to retry`;
      box.onclick = () => { box.onclick = null; box.load(); };
    }
  };
  lazy.observe(box);
  return box;
}

function messageNode(msg) {
  const div = el("div", "msg");
  div.append(el("span", "ts", stamp(msg.time) + " "));
  if (msg.dm) div.append(el("span", "tag", msg.from === chat.name ? `[dm to ${msg.to}] ` : "[dm] "));
  div.append(el("span", "name " + hue(msg.from), msg.from), ": ");
  if (msg.image) {
    if (msg.image.caption) div.append(msg.image.caption);
    div.append(imageBox(msg));
  } else {
    div.append(msg.text);
  }
  return div;
}

function addMessages(messages, where) {
  const fresh = messages.filter(m => !shown.has(m.id));
  for (const m of fresh) { shown.add(m.id); lastId = Math.max(lastId, m.id); }
  if (!fresh.length) return;
  const nodes = fresh.map(messageNode);
  if (where === "top") { // keep what's on screen in place
    const log = $("log"), before = log.scrollHeight;
    $("msgs").prepend(...nodes);
    log.scrollTop += log.scrollHeight - before;
  } else {
    const stick = nearBottom();
    $("msgs").append(...nodes);
    if (stick) toBottom();
  }
}

function openViewer(url, filename, alt) {
  const img = $("viewer-img");
  img.src = url;
  img.alt = alt;
  $("viewer-save").href = url;
  $("viewer-save").download = filename;
  $("viewer").hidden = false;
  $("viewer-close").focus();
}

function closeViewer() {
  $("viewer").hidden = true;
  $("viewer-img").removeAttribute("src");
  $("msg").focus();
}

// Redraw photos before sending so only the pixels survive (no GPS or other
// metadata). GIFs go as is so they stay animated. They carry no location.
async function prepareImage(file) {
  let bmp;
  try { bmp = await createImageBitmap(file); } catch { throw new Error("can't read that image"); }
  const w0 = bmp.width, h0 = bmp.height;
  if (file.type === "image/gif") {
    bmp.close();
    if (file.size > MAX_IMAGE) throw new Error("image too big (25 MB at most)");
    return { bytes: new Uint8Array(await file.arrayBuffer()), mime: "image/gif", width: w0, height: h0 };
  }
  const scale = Math.min(1, 4096 / Math.max(w0, h0));
  const canvas = el("canvas");
  canvas.width = Math.max(1, Math.round(w0 * scale));
  canvas.height = Math.max(1, Math.round(h0 * scale));
  canvas.getContext("2d").drawImage(bmp, 0, 0, canvas.width, canvas.height);
  bmp.close();
  const tries = file.type === "image/png" ? [["image/png"], ["image/jpeg", 0.9]] : [["image/jpeg", 0.9], ["image/jpeg", 0.75]];
  for (const [type, q] of tries) {
    const blob = await new Promise(r => canvas.toBlob(r, type, q));
    if (blob && blob.size <= MAX_IMAGE)
      return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: type, width: canvas.width, height: canvas.height };
  }
  throw new Error("image too big (25 MB at most)");
}

async function sendImage(file) {
  if (!chat || !chat.ready) return line("warn", "! not connected right now");
  const caption = $("msg").value.trim();
  const status = el("div", "info", "preparing image…");
  append(status);
  try {
    const img = await prepareImage(file);
    $("msg").value = caption ? "" : $("msg").value;
    await chat.sendImage(img.bytes, { ...img, caption }, f => { status.textContent = `sending image… ${Math.round(f * 100)}%`; });
    status.remove();
  } catch (e) {
    status.className = "warn";
    status.textContent = `! image not sent: ${e.message}`;
  }
}

// Everything you sent here and the DMs sent to you, decrypted in this
// browser and saved as a zip: messages.json plus the images.
async function saveMyData() {
  if (!chat || !chat.ready) return line("warn", "! not connected right now");
  $("mydata").disabled = true;
  const status = el("div", "info", "collecting your data…");
  append(status);
  try {
    const items = await chat.exportMine(), files = [], messages = [];
    let images = 0;
    for (const m of items) {
      const e = { id: m.id, time: m.time ? new Date(m.time).toISOString() : undefined, from: m.from, to: m.to || undefined };
      if (m.error) {
        e.error = m.error;
      } else if (m.image) {
        const name = `images/${m.id}.${IMAGE_TYPES[m.image.mime]}`;
        status.textContent = `downloading your images… ${++images}`;
        try {
          files.push({ name, data: await chat.fetchImage(m.image) });
          e.image = name;
        } catch (err) {
          e.image = null;
          e.error = err.message;
        }
        e.caption = m.image.caption;
      } else {
        e.text = m.text;
      }
      messages.push(e);
    }
    const chatName = $("label").textContent, now = new Date();
    const doc = { chat: chatName, name: chat.name, fingerprint: myFp, exported: now.toISOString(),
                  contents: "everything you sent in this chat, and the private messages sent to you", messages };
    files.unshift({ name: "messages.json", data: new TextEncoder().encode(JSON.stringify(doc, null, 2) + "\n") });
    const url = URL.createObjectURL(zip(files, now));
    const a = el("a");
    a.href = url;
    a.download = `hush-mydata-${chatName}-${now.toISOString().slice(0, 10)}.zip`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    status.textContent = `saved your data: ${messages.length} messages, ${files.length - 1} images`;
  } catch (e) {
    status.className = "warn";
    status.textContent = `! couldn't save your data: ${e.message}`;
  } finally {
    $("mydata").disabled = false;
  }
}

// Admins only: a Waitlist button with a count, which opens the list.
function showWaitlist() {
  const admin = !!(chat && chat.admin), n = admin ? chat.pending.size : 0;
  $("waitlist-btn").hidden = !admin;
  $("waitlist-count").textContent = n ? String(n) : "";
  $("waitlist-count").hidden = !n;
  const list = $("waitlist-list");
  list.replaceChildren();
  if (admin)
    for (const [name, fp] of chat.pending) {
      const row = el("div", "request");
      const approve = el("button", "approve", "Approve"), deny = el("button", "deny", "Deny");
      approve.type = deny.type = "button";
      approve.onclick = () => { approve.disabled = deny.disabled = true; chat.decide(name, true); };
      deny.onclick = () => { approve.disabled = deny.disabled = true; chat.decide(name, false); };
      const who = el("div", "who-box");
      who.append(el("span", "who", name), el("span", "fp", fp));
      row.append(who, approve, deny);
      list.append(row);
    }
  $("waitlist-empty").hidden = n > 0;
  if (!admin) $("waitlist").hidden = true;
}

function toggleWaitlist(open = $("waitlist").hidden) {
  $("waitlist").hidden = !open;
  $("waitlist-btn").setAttribute("aria-expanded", String(open));
  if (open) $("waitlist-close").focus();
}

function showWaiting(label) {
  $("login").hidden = true;
  $("chat").hidden = true;
  $("waiting").hidden = false;
  $("wait-label").textContent = label;
  $("wait-fp").textContent = myFp;
  document.title = "hush · waiting";
}

function showPeer(ev) {
  if (ev.trust === "bad") line("warn", `! ${ev.name} presented an invalid key; ignoring them`);
  else if (ev.trust === "changed")
    line("warn", `!!! WARNING: ${ev.name}'s key has CHANGED !!!\n` +
      "Either they reset their identity (new browser or device), or someone (the server?) is\n" +
      "trying to pose as them. Nothing will be sent to or accepted from them.\n" +
      `  pinned: ${ev.oldFp}\n  now:    ${ev.fp}\n` +
      `Call them, compare the new fingerprint, then type /trust ${ev.name}`);
  else if (ev.first)
    line("sys", `* ${ev.name} ${ev.joined ? "joined the chat" : ev.online ? "is online" : "is in this chat"}. ` +
      `First time seeing them: fingerprint ${ev.fp}\n` +
      `  Compare it with them on another channel (e.g. a call), then type /verify ${ev.name}`);
  else if (ev.joined) line("sys", `* ${ev.name} joined the chat`);
  else if (ev.online && !ev.wasOnline) line("sys", `* ${ev.name} is online${ev.verified ? "" : " (unverified)"}`);
}

function showOnline() {
  const names = chat ? chat.online() : [];
  $("online").textContent = names.length ? `${names.length + 1} online` : "just you online";
  $("online").title = [chat ? chat.name : "", ...names].join(", ");
}

const setStatus = s => { $("dot").className = s; };

function showLogin(err) {
  clearTimeout(retryTimer);
  chat = null;
  lastId = 0;
  shown.clear();
  $("chat").hidden = true;
  $("waiting").hidden = true;
  $("waitlist").hidden = true;
  $("login").hidden = false;
  $("join").disabled = false;
  $("join").textContent = mode === "create" ? "Create" : "Join";
  $("login-error").textContent = err || "";
  document.title = "hush";
  showSessions();
  if (!$("login-form").hidden) focusForm();
}

// The Add session form joins with a key, or (admins) creates a new chat.
let mode = "join";
function setMode(m) {
  mode = m;
  $("join-fields").hidden = m !== "join";
  $("create-fields").hidden = m !== "create";
  $("join").textContent = m === "join" ? "Join" : "Create";
  $("mode").textContent = m === "join" ? "Create your own" : "Join with a key instead";
  $("login-error").textContent = "";
}

function focusForm() {
  (!$("name").value ? $("name") : mode === "create" ? $("chat-name") : $("key")).focus();
}

const wsUrl = () => (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";

function create(name, label) {
  if (!NAME_RE.test(label)) return showLogin("A chat name can be 1-24 letters, digits, _ . or -");
  $("join").disabled = true;
  $("join").textContent = "Creating…";
  $("login-error").textContent = "";
  setTimeout(async () => { // Argon2id takes a moment, show "Creating…" first
    try {
      const { key } = await createChat({ sodium, url: wsUrl(), name, secretKey: sk }, label);
      local.set("hush.name", name);
      rememberSession(key, name, label);
      showSessions();
      $("sessions-box").hidden = $("login-form").hidden = true;
      $("created").hidden = false;
      $("created-label").textContent = label;
      $("created-key").textContent = key;
      $("created-join").onclick = () => { adding = false; setMode("join"); connect(name, key); };
      $("created-copy").focus();
      $("chat-name").value = "";
    } catch (e) {
      showLogin(capitalize(e.message) + ".");
    }
  }, 30);
}

// Chats you've joined from this browser, so you can rejoin with a click. They
// stay in this browser's storage, next to your identity key.

const sessionId = key => normalizeKey(key);
let sessions = [];
try {
  const list = JSON.parse(local.get("hush.sessions") || "[]");
  if (Array.isArray(list))
    sessions = list.filter(x => x && typeof x.key === "string" && typeof x.name === "string" &&
      NAME_RE.test(x.name) && normalizeKey(x.key))
      .map(x => ({ key: x.key, name: x.name, label: NAME_RE.test(x.label || "") ? x.label : "" }));
} catch { sessions = []; }
const storeSessions = () => local.set("hush.sessions", JSON.stringify(sessions));

// Newest first, one entry per chat and name.
function rememberSession(key, name, label) {
  const id = sessionId(key);
  sessions = sessions.filter(x => !(sessionId(x.key) === id && x.name === name));
  sessions.unshift({ key, name, label });
  storeSessions();
}

let adding = false;
function showSessions() {
  const list = $("sessions");
  list.replaceChildren();
  for (const x of sessions) {
    const li = el("li"), join = el("button", "session"), forget = el("button", "forget", "×");
    join.type = forget.type = "button";
    join.append(el("b", "", x.label || "chat"), el("span", "", `as ${x.name}`));
    join.onclick = () => {
      for (const b of list.querySelectorAll("button")) b.disabled = true;
      join.lastChild.textContent = `as ${x.name} · connecting…`;
      connect(x.name, x.key);
    };
    forget.title = `Remove ${x.label || "this chat"} from this list`;
    forget.setAttribute("aria-label", forget.title);
    forget.onclick = () => {
      if (!confirm(`Remove "${x.label || "this chat"}" from this list? You'll need its key to join again.`)) return;
      sessions = sessions.filter(y => y !== x);
      storeSessions();
      showSessions();
    };
    li.append(join, forget);
    list.append(li);
  }
  const listed = sessions.length > 0 && !adding;
  $("sessions-box").hidden = !listed;
  $("login-form").hidden = listed;
  $("created").hidden = true;
  $("cancel-add").hidden = !sessions.length;
}

function connect(name, key) {
  clearTimeout(retryTimer);
  $("join").disabled = true;
  $("join").textContent = "Connecting…";
  $("login-error").textContent = "";
  const url = wsUrl();
  // Reading a short key takes a moment (Argon2id), so let the page show "Connecting…" first.
  retryTimer = setTimeout(() => {
    const s = new Session({ sodium, url, name, key, secretKey: sk, known, sinceId: lastId }, ev => {
      if (s === chat) onEvent(ev, name, key); // ignore a connection we already gave up on
    });
    chat = s;
  }, 30);
}

function onEvent(ev, name, key) {
  const inChat = !$("chat").hidden, waiting = !$("waiting").hidden;
  switch (ev.type) {
  case "waiting":
    retries = 0;
    local.set("hush.name", name);
    tab.set("hush.session", JSON.stringify({ key, name }));
    rememberSession(key, name, ev.label);
    showWaiting(ev.label);
    break;
  case "pending": showWaitlist(); break;
  case "ready":
    retries = 0;
    local.set("hush.name", name);
    tab.set("hush.session", JSON.stringify({ key, name }));
    rememberSession(key, name, ev.label);
    adding = false;
    $("key").value = "";
    $("label").textContent = ev.label;
    document.title = `hush · ${ev.label}`;
    setStatus("on");
    $("waiting").hidden = true;
    if (inChat) line("sys", "* reconnected");
    else {
      $("login").hidden = true;
      $("chat").hidden = false;
      $("msgs").replaceChildren();
      $("older").hidden = true;
      line("info", `connected as ${name} to the chat "${ev.label}"\nyour fingerprint: ${myFp}\ntype /help for commands` +
        (ev.admin ? "\nyou're an admin: people who want to join are under Waitlist" : ""));
      $("msg").focus();
    }
    showOnline();
    showWaitlist();
    break;
  case "history":
    if (ev.dir === 0) {
      const first = !$("msgs").querySelector(".msg");
      addMessages(ev.messages, first ? "bottom" : "top");
      $("older").hidden = !ev.more;
      $("older").disabled = false;
      if (first) toBottom();
    } else {
      addMessages(ev.messages, "bottom");
    }
    break;
  case "message": addMessages([ev.msg], "bottom"); break;
  case "peer": showPeer(ev); showOnline(); break;
  case "leave": line("sys", `* ${ev.name} went offline`); showOnline(); break;
  case "notice": line(ev.level, ev.text); break;
  case "error": if (inChat && chat && chat.ready) line("warn", `! server: ${ev.text}`); break;
  case "closed":
    if (ev.quit || ev.error) { // left, or the server said no: don't retry
      tab.del("hush.session");
      showLogin(ev.error ? capitalize(ev.error) + "." : "");
    } else if (waiting) { // keep our place in line
      retryTimer = setTimeout(() => connect(name, key), 5000);
    } else if (!inChat) {
      showLogin("Couldn't reach the server. Try again in a moment.");
    } else { // dropped: try again with backoff, then fetch what was missed
      setStatus("off");
      const wait = Math.min(30, 2 ** retries++);
      line("warn", `! disconnected; trying again in ${wait}s`);
      retryTimer = setTimeout(() => connect(name, key), wait * 1000);
    }
    break;
  }
}

const capitalize = s => s.charAt(0).toUpperCase() + s.slice(1);

$("login-form").addEventListener("submit", e => {
  e.preventDefault();
  const key = $("key").value.trim(), name = $("name").value.trim();
  if (!NAME_RE.test(name)) return showLogin("Your name can be 1-24 letters, digits, _ . or -");
  if (mode === "create") return create(name, $("chat-name").value.trim());
  if (!key || key.length > KEY_MAX || !normalizeKey(key))
    return showLogin("That isn't a key. It looks like xxxx-xxxx.");
  connect(name, key);
});

$("send-form").addEventListener("submit", e => {
  e.preventDefault();
  const text = $("msg").value;
  if (!text.trim()) return;
  if (!chat || !chat.ready) return line("warn", "! not connected right now");
  $("msg").value = "";
  history.push(text);
  hi = history.length;
  chat.input(text);
});

$("msg").addEventListener("keydown", e => {
  if (e.key === "ArrowUp" && hi > 0) $("msg").value = history[--hi];
  else if (e.key === "ArrowDown" && hi < history.length) $("msg").value = history[++hi] ?? "";
  else return;
  e.preventDefault();
});

$("msg").addEventListener("paste", e => {
  const file = [...(e.clipboardData?.files || [])].find(f => f.type.startsWith("image/"));
  if (!file) return;
  e.preventDefault();
  sendImage(file);
});

$("attach").addEventListener("click", () => $("file").click());
$("file").addEventListener("change", () => {
  const file = $("file").files[0];
  $("file").value = "";
  if (file) sendImage(file);
});

$("older").addEventListener("click", () => {
  if (!chat || !chat.ready) return;
  $("older").disabled = true;
  chat.loadOlder();
});

$("viewer").addEventListener("click", e => { if (e.target === $("viewer")) closeViewer(); });
$("viewer-close").addEventListener("click", closeViewer);
document.addEventListener("keydown", e => {
  if (e.key !== "Escape") return;
  if (!$("viewer").hidden) closeViewer();
  else if (!$("waitlist").hidden) toggleWaitlist(false);
});
$("waitlist-btn").addEventListener("click", () => toggleWaitlist());
$("waitlist-close").addEventListener("click", () => toggleWaitlist(false));
document.addEventListener("click", e => { // clicking outside the panel closes it
  if (!$("waitlist").hidden && !$("waitlist").contains(e.target) && !$("waitlist-btn").contains(e.target))
    toggleWaitlist(false);
});

$("mydata").addEventListener("click", saveMyData);
$("wait-cancel").addEventListener("click", () => {
  if (chat && chat.ws.readyState < 2) chat.close();
  tab.del("hush.session");
  showLogin();
});

$("leave").addEventListener("click", () => {
  if (chat && chat.ws.readyState < 2) return chat.close();
  tab.del("hush.session");
  showLogin();
});

$("add-session").addEventListener("click", () => {
  adding = true;
  setMode("join");
  showSessions();
  focusForm();
});
$("mode").addEventListener("click", () => {
  setMode(mode === "join" ? "create" : "join");
  focusForm();
});
$("created-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("created-key").textContent);
    $("created-copy").textContent = "Copied";
  } catch { // no clipboard (e.g. plain http): select it for copying by hand
    getSelection().selectAllChildren($("created-key"));
  }
  setTimeout(() => { $("created-copy").textContent = "Copy"; }, 1500);
});
$("cancel-add").addEventListener("click", () => {
  adding = false;
  setMode("join");
  $("login-error").textContent = "";
  showSessions();
});

$("myfp").textContent = myFp;
$("name").value = local.get("hush.name") || "";
// After a reload, go straight back into the chat this tab was in.
let resume = null;
try { resume = JSON.parse(tab.get("hush.session") || "null"); } catch { resume = null; }
if (resume && typeof resume.key === "string" && NAME_RE.test(resume.name || "") && normalizeKey(resume.key))
  connect(resume.name, resume.key);
else showLogin($("login-error").textContent);
