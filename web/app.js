// The page: login form, chat log and input. The protocol is in hush.js.
import sodium from "./sodium.mjs";
import { Session, NAME_RE, KEY_MAX, fingerprint, publicKey } from "./hush.js";

const $ = id => document.getElementById(id);

// Browser storage can be blocked (private windows, strict settings); cope without it.
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

let chat = null, retries = 0, retryTimer = null;
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

function append(div) {
  const log = $("log");
  const stick = log.scrollHeight - log.scrollTop - log.clientHeight < 60;
  log.append(div);
  if (stick) log.scrollTop = log.scrollHeight;
}

// All text reaches the page through textContent, never as HTML.
const line = (cls, text) => append(el("div", cls, text));

function time() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function showMessage(ev) {
  const div = el("div", "msg");
  div.append(el("span", "ts", time() + " "));
  if (ev.dm) div.append(el("span", "tag", ev.to ? `[dm to ${ev.to}] ` : "[dm] "));
  div.append(el("span", "name " + hue(ev.from), ev.from), ": " + ev.text);
  append(div);
}

function showPeer(ev) {
  const what = ev.joined ? "joined" : "is here";
  if (ev.trust === "bad") line("warn", `! ${ev.name} presented an invalid key; ignoring them`);
  else if (ev.trust === "changed")
    line("warn", `!!! WARNING: ${ev.name}'s key has CHANGED !!!\n` +
      "Either they reset their identity (new browser or device), or someone (the server?) is\n" +
      "trying to read your messages. Nothing will be sent to or accepted from them.\n" +
      `  pinned: ${ev.oldFp}\n  now:    ${ev.fp}\n` +
      `Call them, compare the new fingerprint, then type /trust ${ev.name}`);
  else if (ev.first)
    line("sys", `* ${ev.name} ${what}. First time seeing them: fingerprint ${ev.fp}\n` +
      `  Compare it with them on another channel (e.g. a call), then type /verify ${ev.name}`);
  else line("sys", `* ${ev.name} ${what}${ev.verified ? "" : " (unverified)"}`);
}

function showOnline() {
  const names = chat ? chat.online() : [];
  $("online").textContent = names.length ? `${names.length + 1} here` : "just you";
  $("online").title = [chat ? chat.name : "", ...names].join(", ");
}

function setStatus(s) { $("dot").className = s; }

function showLogin(err) {
  clearTimeout(retryTimer);
  chat = null;
  $("chat").hidden = true;
  $("login").hidden = false;
  $("join").disabled = false;
  $("join").textContent = "Join";
  $("login-error").textContent = err || "";
  document.title = "hush";
  ($("name").value ? $("key") : $("name")).focus();
}

function connect(name, key) {
  clearTimeout(retryTimer);
  $("join").disabled = true;
  $("join").textContent = "Connecting…";
  $("login-error").textContent = "";
  const url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";
  const s = new Session({ sodium, url, name, key, secretKey: sk, known }, ev => {
    if (s === chat) onEvent(ev, name, key); // ignore a connection we already gave up on
  });
  chat = s;
}

function onEvent(ev, name, key) {
  const inChat = !$("chat").hidden;
  switch (ev.type) {
  case "ready":
    retries = 0;
    local.set("hush.name", name);
    tab.set("hush.key", key);
    $("key").value = "";
    $("label").textContent = ev.label;
    document.title = `hush · ${ev.label}`;
    setStatus("on");
    if (inChat) line("sys", "* reconnected");
    else {
      $("login").hidden = true;
      $("chat").hidden = false;
      $("log").replaceChildren();
      line("info", `connected as ${name} to the chat "${ev.label}"\nyour fingerprint: ${myFp}\ntype /help for commands`);
      $("msg").focus();
    }
    showOnline();
    break;
  case "peer": showPeer(ev); showOnline(); break;
  case "leave": line("sys", `* ${ev.name} left`); showOnline(); break;
  case "message": showMessage(ev); break;
  case "notice": line(ev.level, ev.text); break;
  case "error": if (inChat && chat && chat.ready) line("warn", `! server: ${ev.text}`); break;
  case "closed":
    if (ev.quit || ev.error) { // left, or the server said no: don't retry
      tab.del("hush.key");
      showLogin(ev.error ? capitalize(ev.error) + "." : "");
    } else if (!inChat) {
      showLogin("Couldn't reach the server. Try again in a moment.");
    } else { // dropped: try again with backoff
      setStatus("off");
      const wait = Math.min(30, 2 ** retries++);
      line("warn", `! disconnected; trying again in ${wait}s`);
      showOnline();
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
  if (!key || key.length > KEY_MAX) return showLogin("Enter the key you were given.");
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

$("leave").addEventListener("click", () => {
  if (chat && chat.ws.readyState < 2) return chat.close();
  tab.del("hush.key");
  showLogin();
});

$("myfp").textContent = myFp;
$("name").value = local.get("hush.name") || "";
const saved = tab.get("hush.key");
if (saved && NAME_RE.test($("name").value)) connect($("name").value, saved);
else showLogin($("login-error").textContent);
