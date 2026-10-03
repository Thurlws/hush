// The page: login form, chat log, input and images. The protocol is in hush.js.
import sodium from "./sodium.mjs";
import { Session, AdminLink, NAME_RE, KEY_MAX, MAX_IMAGE, IMAGE_TYPES, fingerprint, publicKey, normalizeKey, createChat } from "./hush.js";
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

let chat = null, retries = 0, retryTimer = null, lastId = 0, moreOlder = false;
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
  div.dataset.id = msg.id;
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

// Joins, leaves and key warnings aren't messages, so the server doesn't keep them. This
// browser does, per chat and name, each placed after the newest message there was at the
// time, so they're still there after a reload or rejoin. Also remembered: who was last
// seen online, so a reload doesn't announce everyone again.
const LOG_MAX = 300;
let log = null, placed = new Set(), unplaced = [], anchored = false;

function logKey(key, name) {
  const norm = normalizeKey(key) || "";
  return `hush.log.${sodium.to_hex(sodium.crypto_generichash(16, new TextEncoder().encode(norm)))}.${name}`;
}

function loadLog(key, name) {
  const k = logKey(key, name);
  let list = [], on = [];
  try {
    const d = JSON.parse(local.get(k) || "{}");
    if (Array.isArray(d.list))
      list = d.list.filter(e => e && Number.isSafeInteger(e.after) && typeof e.text === "string" &&
        (e.cls === "sys" || e.cls === "warn") && typeof e.who === "string");
    if (Array.isArray(d.on)) on = d.on.filter(x => Array.isArray(x) && typeof x[0] === "string");
  } catch { /* start fresh */ }
  return { key: k, list, online: new Map(on.map(([n, v]) => [n, v === true])) };
}

function saveLog() {
  if (!log) return;
  log.list = log.list.slice(-LOG_MAX);
  local.set(log.key, JSON.stringify({ list: log.list, on: [...log.online] }));
}

const wasOnline = (name, fallback) => log && log.online.has(name) ? log.online.get(name) : fallback;
function setOnline(name, on) {
  if (!log) return;
  log.online.set(name, on);
  saveLog();
}

// One line about who. Before the first page of history there's no message to place it after
// yet, so it waits for that.
function event(who, cls, text) {
  const e = { after: lastId, cls, text, who };
  if (!log) return line(cls, text);
  if (cls === "warn") { // the same warning on every connect only needs saying once
    const last = log.list.findLast(x => x.who === who);
    if (last && last.text === text) return;
  }
  if (!anchored) return unplaced.push(e);
  log.list.push(e);
  saveLog();
  placed.add(e);
  line(cls, text);
}

// Put saved lines back where they belong. A line after a message that isn't on the page
// yet waits for older history, unless there's none.
function placeEvents() {
  if (!log) return;
  const msgs = [...$("msgs").querySelectorAll(".msg")];
  const oldest = msgs.length ? Number(msgs[0].dataset.id) : Infinity;
  for (const e of log.list) {
    if (placed.has(e) || (e.after < oldest && moreOlder)) continue;
    placed.add(e);
    const next = msgs.find(m => Number(m.dataset.id) > e.after);
    const node = el("div", e.cls, e.text);
    if (next) next.before(node);
    else append(node);
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

// Admins only: an Admin button with the waitlist's count, which opens the panel.
let panel = null;
function showWaitlist() {
  const admin = !!(chat && chat.admin), n = admin ? chat.pending.size : 0;
  $("admin-btn").hidden = !admin;
  $("admin-count").textContent = n ? String(n) : "";
  $("admin-count").hidden = !n;
  const list = $("waitlist-list");
  list.replaceChildren();
  if (admin)
    for (const [name, fp] of chat.pending) {
      const row = el("div", "request");
      const approve = el("button", "approve", "Approve"), deny = el("button", "deny", "Deny");
      approve.type = deny.type = "button";
      const hist = historyPicker();
      approve.onclick = () => { approve.disabled = deny.disabled = true; chat.decide(name, true, pickedDays(hist)); };
      deny.onclick = () => { approve.disabled = deny.disabled = true; chat.decide(name, false); };
      const who = el("div", "who-box");
      who.append(el("span", "who", name), el("span", "fp", fp));
      row.append(who, hist, approve, deny);
      list.append(row);
    }
  $("waitlist-empty").hidden = n > 0;
  if (!admin) $("admin").hidden = true;
}

// How much of the history from before they joined someone gets to see.
function historyPicker(none = "no history") {
  const sel = el("select", "history");
  sel.title = "History they can see from before";
  sel.setAttribute("aria-label", sel.title);
  for (const [v, t] of [["", none], ["1", "last day"], ["7", "last 7 days"], ["30", "last 30 days"], ["0", "all history"]])
    sel.append(Object.assign(el("option", "", t), { value: v }));
  return sel;
}
const pickedDays = sel => sel.value === "" ? null : Number(sel.value);

// Admins: tabs over the server's sessions, chats and bans, and in a chat its waitlist and
// members too. The same panel sits in the chat header and on the "Manage server" page.
const DAYS = [["", "no history"], ["1", "last day"], ["7", "last 7 days"], ["30", "last 30 days"], ["0", "all history"]];
const when = ms => new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
const mb = n => `${(n / 1048576).toFixed(1)} MB`;
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

function button(text, cls, onclick) {
  const b = el("button", cls, text);
  b.type = "button";
  b.onclick = onclick;
  return b;
}

function row(title, details, ...actions) {
  const r = el("div", "request"), who = el("div", "who-box"), act = el("div", "actions");
  who.append(el("span", "who", title));
  for (const d of details.filter(Boolean)) who.append(el("span", "fp", d));
  act.append(...actions);
  r.append(who, act);
  return r;
}

function adminPanel({ tabs, status, pane, waitlist = null, manager, chat = null, saved }) {
  const names = chat ? ["Waitlist", "Members", "Sessions", "Chats", "Bans"] : ["Sessions", "Chats", "Bans"];
  let current = null, membersOf = chat, busy = false;
  const say = (text, bad = false) => { status.textContent = text; status.className = bad ? "warn" : "hint"; };

  // Run an admin request, say how it went, then redraw
  async function act(promise) {
    try { say(await promise); } catch (e) { say(e.message, true); }
    refresh();
  }

  const buttons = names.map(n => {
    const b = button(n, "tab", () => show(n));
    b.setAttribute("role", "tab");
    return b;
  });
  tabs.replaceChildren(...buttons);

  function show(name) {
    current = names.includes(name) ? name : names[0];
    if (current !== "Members") membersOf = chat;
    for (const b of buttons) b.setAttribute("aria-selected", String(b.textContent === current));
    local.set(saved, current);
    say("");
    refresh();
  }

  async function refresh() {
    if (busy) return;
    const tab = current;
    if (waitlist) waitlist.hidden = tab !== "Waitlist";
    pane.hidden = tab === "Waitlist";
    if (tab === "Waitlist") return;
    busy = true;
    try {
      const nodes = await draw[tab]();
      if (tab === current) pane.replaceChildren(...nodes);
    } catch (e) {
      say(e.message, true);
    } finally {
      busy = false;
    }
  }

  const draw = {
    async Sessions() {
      const list = await manager().sessions();
      return [el("p", "hint", `${plural(list.length, "connection")} right now.`), ...list.map(x => row(
        `${x.name || "?"}${x.you ? " (you)" : ""}`,
        [`${x.chat ? `in ${x.chat}` : x.login ? "logging in" : "managing the server"}${x.waiting ? ", waiting to be let in" : ""}` +
           `${x.admin ? ", admin" : ""}`,
         `${x.web ? "browser" : "terminal"} from ${x.address}, since ${when(x.connected)}`],
        ...(x.you ? [] : [button("Kick", "", () => act(manager().kick(x.id))),
          button("Ban address", "danger", () => {
            if (confirm(`Ban ${x.address}? Everyone connecting from it is refused until it's unbanned.`)) act(manager().ban(x.address));
          })])))];
    },
    async Chats() {
      const list = await manager().chats();
      return [el("p", "hint", plural(list.length, "chat")), ...list.map(x => row(x.label,
        x.old ? ["an old key from before keys got shorter: it no longer works"]
              : [`${plural(x.members, "member")}, ${x.waiting} waiting, ${x.online} online`,
                 `${plural(x.messages, "message")}, ${plural(x.images, "image")} (${mb(x.bytes)})`],
        ...(x.old ? [] : [
          button("Members", "", () => { membersOf = x.label; current = "Members"; refresh(); }),
          button("Rename", "", () => {
            const to = prompt(`New name for ${x.label} (letters, digits, _ . -)`, x.label);
            if (to && to !== x.label) act(manager().rename(x.label, to.trim()));
          }),
          button("Clear history", "danger", () => {
            if (confirm(`Delete every message and image in ${x.label}? The key keeps working. This can't be undone.`))
              act(manager().clear(x.label));
          })]),
        button("Delete", "danger", () => {
          if (confirm(`Delete the chat ${x.label}? Its key stops working and everything in it is deleted. This can't be undone.`))
            act(manager().revoke(x.label));
        })))];
    },
    async Members() {
      const chatName = membersOf, list = await manager().members(chatName), nodes = [];
      if (chatName !== chat) nodes.push(button("← All chats", "link", () => show("Chats")));
      nodes.push(el("p", "hint", `${chatName}: ${plural(list.filter(x => x.state === "in").length, "member")}. ` +
        "New members see what's said after they're let in. Share more with the picker."));
      for (const x of list) {
        const picker = historyPicker(x.state === "in" ? "how much?" : "no history"), details = [x.fp];
        if (x.state === "in")
          details.push(`${x.online ? "online" : "offline"}${x.admin ? ", admin: sees everything" : x.after ? `, sees history after ${when(x.after)}`
            : ", sees all history"}`);
        else details.push(x.state === "waiting" ? "waiting to be let in" : "turned away");
        const actions = [];
        if (x.state === "in" && !x.admin)
          actions.push(picker, button("Share", "", () => {
            const d = pickedDays(picker);
            if (d === null) return say("Pick how much history to share first.", true);
            act(manager().share(chatName, x.name, d));
          }), button("Remove", "danger", () => {
            if (confirm(`Take ${x.name} out of ${chatName}? If they come back, an admin has to let them in again.`))
              act(manager().remove(chatName, x.name));
          }));
        else if (x.state !== "in")
          actions.push(picker, button(x.state === "waiting" ? "Approve" : "Let in", "approve", async () => {
            const d = pickedDays(picker);
            try {
              say(await manager().decide(chatName, x.name, true));
              if (d !== null) say(await manager().share(chatName, x.name, d));
            } catch (e) { say(e.message, true); }
            refresh();
          }), ...(x.state === "waiting" ? [button("Deny", "", () => act(manager().decide(chatName, x.name, false)))] : []));
        nodes.push(row(x.name, details, ...actions));
      }
      if (!list.length) nodes.push(el("p", "hint", "Nobody yet."));
      return nodes;
    },
    async Bans() {
      const list = await manager().bans();
      const form = el("form", "ban-form"), input = el("input");
      input.placeholder = "IP address, e.g. 203.0.113.9";
      input.setAttribute("aria-label", "IP address to ban");
      form.append(input, Object.assign(el("button", "danger", "Ban"), { type: "submit" }));
      form.onsubmit = e => {
        e.preventDefault();
        const a = input.value.trim();
        if (a) act(manager().ban(a));
      };
      return [form, el("p", "hint", list.length ? "IPv6 addresses are banned per /64, the block one home connection gets."
                                                 : "Nobody is banned."),
              ...list.map(x => row(x.address, [`since ${x.time ? when(x.time) : "?"}${x.by ? `, by ${x.by}` : ""}`],
                button("Unban", "", () => act(manager().unban(x.address)))))];
    },
  };

  // The chat this panel is in got a new name
  function relabel(label) {
    if (membersOf === chat) membersOf = label;
    chat = label;
    refresh();
  }

  show(local.get(saved) || names[0]);
  return { show, refresh, relabel, get current() { return current; } };
}

function toggleAdmin(open = $("admin").hidden) {
  $("admin").hidden = !open;
  $("admin-btn").setAttribute("aria-expanded", String(open));
  if (!open) return;
  const s = chat;
  if (!panel || panel.chat !== s) {
    panel = adminPanel({ tabs: $("admin-tabs"), status: $("admin-status"), pane: $("admin-pane"), waitlist: $("waitlist-pane"),
                         manager: () => s.manage, chat: s.label, saved: "hush.admintab" });
    panel.chat = s;
  } else {
    panel.refresh();
  }
  $("admin-close").focus();
}

// Who's online changed: redraw the panel's lists if one is showing
let redrawTimer = null;
function adminChanged() {
  if (!panel || $("admin").hidden || panel.current === "Waitlist") return;
  clearTimeout(redrawTimer);
  redrawTimer = setTimeout(() => panel.refresh(), 300);
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
  const was = wasOnline(ev.name, ev.wasOnline);
  setOnline(ev.name, ev.online);
  if (ev.trust === "bad") event(ev.name, "warn", `! ${ev.name} presented an invalid key; ignoring them`);
  else if (ev.trust === "changed")
    event(ev.name, "warn", `!!! WARNING: ${ev.name}'s key has CHANGED !!!\n` +
      "Either they reset their identity (new browser or device), or someone (the server?) is\n" +
      "trying to pose as them. Nothing will be sent to or accepted from them.\n" +
      `  pinned: ${ev.oldFp}\n  now:    ${ev.fp}\n` +
      `Call them, compare the new fingerprint, then type /trust ${ev.name}`);
  else if (ev.first)
    event(ev.name, "sys", `* ${ev.name} ${ev.joined ? "joined the chat" : ev.online ? "is online" : "is in this chat"}. ` +
      `First time seeing them: fingerprint ${ev.fp}\n` +
      `  Compare it with them on another channel (e.g. a call), then type /verify ${ev.name}`);
  else if (ev.joined) event(ev.name, "sys", `* ${ev.name} joined the chat`);
  else if (ev.online && !was) event(ev.name, "sys", `* ${ev.name} is online${ev.verified ? "" : " (unverified)"}`);
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
  log = null;
  $("chat").hidden = true;
  $("waiting").hidden = true;
  $("admin").hidden = true;
  $("manage").hidden = true;
  $("login").hidden = false;
  panel = null;
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
      local.del(logKey(x.key, x.name));
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
  case "pending": showWaitlist(); adminChanged(); break;
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
      log = loadLog(key, name);
      placed = new Set();
      unplaced = [];
      anchored = false;
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
      moreOlder = ev.more;
      $("older").hidden = !ev.more;
      $("older").disabled = false;
      if (!anchored) { // the newest message is known now, so lines from before this can go after it
        anchored = true;
        for (const e of unplaced.splice(0)) { e.after = lastId; log.list.push(e); }
        saveLog();
      }
      placeEvents();
      if (first) toBottom();
    } else {
      addMessages(ev.messages, "bottom");
    }
    break;
  case "message": addMessages([ev.msg], "bottom"); break;
  case "peer": showPeer(ev); showOnline(); adminChanged(); break;
  case "leave": setOnline(ev.name, false); event(ev.name, "sys", `* ${ev.name} went offline`); showOnline(); adminChanged(); break;
  case "notice": line(ev.level, ev.text); break;
  case "removed": setOnline(ev.name, false); event(ev.name, "sys", `* ${ev.name} was removed from the chat`); showOnline(); adminChanged(); break;
  case "cleared": // nothing before this is on the server any more
    $("msgs").replaceChildren();
    shown.clear();
    lastId = 0;
    moreOlder = false;
    $("older").hidden = true;
    if (log) { log.list = []; placed = new Set(); saveLog(); }
    event("", "sys", "* an admin deleted this chat's history");
    break;
  case "renamed":
    if (panel) panel.relabel(ev.label);
    $("label").textContent = ev.label;
    document.title = `hush · ${ev.label}`;
    rememberSession(key, name, ev.label);
    event("", "sys", `* this chat is now called ${ev.label}`);
    break;
  case "shared":
    event("", "sys", ev.days ? `* an admin shared the last ${ev.days} day${ev.days === 1 ? "" : "s"} of history with you`
                             : "* an admin shared the chat's history with you");
    break;
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
  else if (!$("admin").hidden) toggleAdmin(false);
});
$("admin-btn").addEventListener("click", () => toggleAdmin());
$("admin-close").addEventListener("click", () => toggleAdmin(false));
document.addEventListener("click", e => { // clicking outside the panel closes it
  if (!$("admin").hidden && e.target.isConnected && !$("admin").contains(e.target) && !$("admin-btn").contains(e.target))
    toggleAdmin(false);
});

// "Manage server": admins log in without a chat, and get the same panel full page.
let link = null;
$("manage-open").addEventListener("click", () => {
  const name = $("name").value.trim() || local.get("hush.name") || "";
  if (!NAME_RE.test(name)) {
    $("login-form").hidden = false;
    $("sessions-box").hidden = true;
    $("name").focus();
    return showLogin("Type your name first: 1-24 letters, digits, _ . or -");
  }
  $("login-error").textContent = "Connecting…";
  const l = new AdminLink({ sodium, url: wsUrl(), name, secretKey: sk }, ev => {
    if (l !== link) return;
    if (ev.type === "ready") {
      $("login").hidden = true;
      $("manage").hidden = false;
      document.title = "hush · manage";
      adminPanel({ tabs: $("manage-tabs"), status: $("manage-status"), pane: $("manage-pane"), manager: () => l.manage,
                   saved: "hush.managetab" });
    } else if (ev.type === "closed") {
      link = null;
      showLogin(ev.error ? capitalize(ev.error) + "." : l.ready ? "Disconnected from the server." : "Couldn't reach the server.");
    }
  });
  link = l;
});
$("manage-close").addEventListener("click", () => {
  const l = link;
  link = null;
  if (l) l.close();
  showLogin();
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
