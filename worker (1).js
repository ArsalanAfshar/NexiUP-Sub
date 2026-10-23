// NexiUP — sub manager. Bindings: D1 "DB", secret "ADMIN_KEY".
// Reads each customer's sub from the Nahan worker (no access to its DB),
// applies fingerprint / cipherSuites / finalmask, shows a status page.
const DEF = {
  brand: "NexiUP", bot: "", channel: "", accent: "#6d5dfc",
  useFp: "1", fp: "unsafe",
  useCs: "1", cs: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
  useFm: "1", fm: '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}',
};
const GB = 1073741824;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const txt = (t, s = 200) => new Response(t, { status: s, headers: { "content-type": "text/plain;charset=utf-8" } });
const html = (h) => new Response(h, { headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" } });
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });

let ready;
const init = (DB) => ready || (ready = DB.batch([
  DB.prepare("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT)"),
  DB.prepare("CREATE TABLE IF NOT EXISTS workers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,host TEXT,route TEXT)"),
  DB.prepare("CREATE TABLE IF NOT EXISTS customers(token TEXT PRIMARY KEY,name TEXT,worker_id INTEGER,sub TEXT,last TEXT,created INTEGER)"),
]).catch((e) => { ready = null; throw e; }));

async function cfg(DB) {
  const { results } = await DB.prepare("SELECT k,v FROM settings").all();
  const o = { ...DEF };
  for (const r of results) if (r.k in DEF) o[r.k] = r.v;
  return o;
}

// Fetch customer's sub from the Nahan worker like a normal client.
async function pull(w, sub) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), 9000);
  try {
    const r = await fetch(`https://${w.host}/${w.route}?sub=${encodeURIComponent(sub)}`, {
      headers: { "User-Agent": "v2rayN/7.0" }, signal: ac.signal, cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!r.ok) throw new Error("bad status");
    const body = (await r.text()).trim();
    const raw = body.includes("://") ? body
      : new TextDecoder().decode(Uint8Array.from(atob(body.replace(/\s/g, "")), (c) => c.charCodeAt(0)));
    let used = 0, total = 0, exp = 0;
    const h = r.headers.get("subscription-userinfo");
    if (h) {
      const g = (k) => +((h.match(new RegExp(k + "=(\\d+)")) || [])[1] || 0);
      used = g("download") + g("upload"); total = g("total"); exp = g("expire");
    }
    const links = [];
    for (const l of raw.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)) {
      if (l.includes("@127.0.0.1:1080")) { // Nahan's fake "info" configs: read, then drop
        if (!h) {
          let n = ""; try { n = decodeURIComponent(l.split("#")[1] || ""); } catch {}
          let m = n.match(/Used:\s*([\d.]+)\s*GB\s*\/\s*([\d.]+)\s*GB/);
          if (m) { used = m[1] * GB; total = m[2] * GB; }
          m = n.match(/Expiry:\s*(\d{4}-\d\d-\d\d)/);
          if (m) exp = Date.parse(m[1] + "T23:59:59Z") / 1000;
        }
        continue;
      }
      links.push(l);
    }
    return { used, total, exp, links, at: Date.now() };
  } finally { clearTimeout(t); }
}

function tune(l, s, i) {
  const [rest, ...nm] = l.split("#");
  const [base, q = ""] = rest.split("?");
  const p = new URLSearchParams(q);
  if (p.get("security") === "tls") {
    if (s.useFp === "1" && s.fp) p.set("fp", s.fp);
    if (s.useCs === "1" && s.cs) p.set("cs", s.cs);
    if (s.useFm === "1" && s.fm) { try { p.set("fm", JSON.stringify(JSON.parse(s.fm))); } catch {} }
  }
  return `${base}?${p}#${encodeURIComponent(`${s.brand}-${i + 1}`)}`;
}

async function sub(req, env, u, token) {
  const c = await env.DB.prepare("SELECT c.*,w.host,w.route FROM customers c JOIN workers w ON w.id=c.worker_id WHERE c.token=?").bind(token).first();
  if (!c) return txt("Not found", 404);
  const s = await cfg(env.DB);
  let d, stale = false;
  try {
    d = await pull(c, c.sub);
    const old = c.last ? JSON.parse(c.last).at : 0;
    if (Date.now() - old > 3e5) await env.DB.prepare("UPDATE customers SET last=? WHERE token=?").bind(JSON.stringify(d), token).run();
  } catch {
    if (!c.last) return txt("Upstream unavailable", 502);
    d = JSON.parse(c.last); stale = true;
  }
  const links = d.links.map((l, i) => tune(l, s, i));
  const ua = req.headers.get("user-agent") || "";
  const browser = !u.searchParams.has("raw") && (req.headers.get("sec-fetch-dest") === "document" ||
    (/text\/html/.test(req.headers.get("accept") || "") && /mozilla/i.test(ua) &&
      !/v2ray|clash|sing|hiddify|nekobox|streisand|shadowrocket|surge|stash|loon|happ|pattn/i.test(ua)));
  if (browser) return html(page(s, c, d, links, u.origin + "/s/" + token, stale));
  return new Response(btoa(links.join("\n")), { headers: {
    "content-type": "text/plain;charset=utf-8", "profile-update-interval": "6",
    "subscription-userinfo": `upload=0; download=${Math.floor(d.used)}; total=${Math.floor(d.total)}; expire=${d.exp}`,
  } });
}

function page(s, c, d, links, subUrl, stale) {
  const now = Date.now();
  const left = d.total ? Math.max(d.total - d.used, 0) : 0;
  const pct = d.total ? left / d.total : 1;
  const days = d.exp ? Math.ceil((d.exp * 1000 - now) / 864e5) : null;
  const expired = d.exp && d.exp * 1000 < now, depleted = d.total && d.used >= d.total;
  const st = expired ? ["منقضی شده", "bad"] : depleted ? ["حجم تمام شده", "bad"] : ["فعال", "ok"];
  const gb = (b) => (b / GB).toFixed(2);
  const date = d.exp ? new Intl.DateTimeFormat("fa-IR", { dateStyle: "long" }).format(new Date(d.exp * 1000)) : "نامحدود";
  const ac = /^#[0-9a-f]{6}$/i.test(s.accent) ? s.accent : DEF.accent;
  const url = (x) => (/^https?:\/\//.test(x) ? esc(x) : "");
  const C = 2 * Math.PI * 64;
  const btn = (u, t) => (url(u) ? `<a class="b" href="${url(u)}" target="_blank" rel="noopener">${t}</a>` : "");
  const row = (l, n) => `<div class="r"><span>${esc(n)}</span><code dir="ltr">${esc(l)}</code><button data-c="${esc(l)}">کپی</button></div>`;
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(s.brand)} | ${esc(c.name)}</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700;800&display=swap" rel="stylesheet">
<style>:root{--bg:#0f1226;--cd:#181c3a;--tx:#f1f2ff;--mu:#9aa0c8;--bd:#292e55;--ac:${ac};--ok:#3ddc97;--bad:#ff6b6b}
@media(prefers-color-scheme:light){:root{--bg:#f1f2fb;--cd:#fff;--tx:#14172e;--mu:#6b7194;--bd:#e2e5f4}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:22px 14px 48px;background:radial-gradient(700px 360px at 85% -8%,color-mix(in srgb,var(--ac) 30%,transparent),transparent),var(--bg);color:var(--tx);font:15px/1.8 Vazirmatn,Tahoma,sans-serif}
.w{max-width:720px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.logo{font:800 24px Vazirmatn,sans-serif;direction:ltr}.logo i{font-style:normal;color:var(--ac)}
.p{padding:3px 14px;border-radius:99px;font-size:13px;border:1px solid currentColor}.ok{color:var(--ok)}.bad{color:var(--bad)}
.cd{background:var(--cd);border:1px solid var(--bd);border-radius:22px;padding:22px;margin-bottom:14px}
.hero{display:grid;grid-template-columns:168px 1fr;gap:22px;align-items:center}@media(max-width:560px){.hero{grid-template-columns:1fr;justify-items:center;text-align:center}}
.ring{position:relative;width:168px;height:168px}.ring svg{transform:rotate(-90deg)}.ring div{position:absolute;inset:0;display:grid;place-content:center;text-align:center}.ring b{font-size:30px;line-height:1.2}.ring small{color:var(--mu)}
h1{margin:0 0 4px;font-size:21px}.g{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:14px}.g div{background:color-mix(in srgb,var(--ac) 9%,transparent);border-radius:14px;padding:10px 6px;text-align:center}.g small{display:block;color:var(--mu);font-size:12px}.g b{font-size:16px}
h2{margin:0 0 12px;font-size:16px}.r{display:flex;gap:10px;align-items:center;padding:8px 0;border-top:1px solid var(--bd)}.r:first-of-type{border:0}.r span{min-width:70px;color:var(--mu);font-size:13px}.r code{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--mu)}
button,.b{font:inherit;font-size:13px;border:0;border-radius:10px;padding:6px 16px;background:var(--ac);color:#fff;cursor:pointer;text-decoration:none;display:inline-block}button:focus-visible,.b:focus-visible{outline:2px solid var(--tx);outline-offset:2px}
.ct{display:flex;gap:10px;flex-wrap:wrap}.ct .b{flex:1;text-align:center;padding:10px}.n{color:var(--mu);font-size:12px;text-align:center;margin-top:18px}</style></head><body><div class="w">
<header><div class="logo">${esc(s.brand)}<i>.</i></div><span class="p ${st[1]}">${st[0]}</span></header>
<section class="cd hero"><div class="ring"><svg width="168" height="168"><circle cx="84" cy="84" r="64" fill="none" stroke="var(--bd)" stroke-width="14"/><circle cx="84" cy="84" r="64" fill="none" stroke="${depleted || expired ? "var(--bad)" : "var(--ac)"}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - pct)}"/></svg><div><b>${d.total ? gb(left) : "∞"}</b><small>گیگابایت باقی‌مانده</small></div></div>
<div><h1>${esc(c.name)}</h1><div style="color:var(--mu)">${d.total ? `${gb(d.used)} از ${gb(d.total)} گیگابایت مصرف شده` : "حجم نامحدود"}</div>
<div class="g"><div><small>روز باقی‌مانده</small><b>${days === null ? "∞" : Math.max(days, 0)}</b></div><div><small>مصرف‌شده</small><b>${gb(d.used)}</b></div><div><small>پایان اعتبار</small><b style="font-size:13px">${date}</b></div></div></div></section>
<section class="cd"><h2>لینک اشتراک</h2><div class="r"><span>ساب</span><code dir="ltr">${esc(subUrl)}</code><button data-c="${esc(subUrl)}">کپی</button></div></section>
<section class="cd"><h2>کانفیگ‌ها</h2>${links.map((l, i) => row(l, `${s.brand}-${i + 1}`)).join("") || '<div style="color:var(--mu)">کانفیگی موجود نیست.</div>'}</section>
${url(s.bot) || url(s.channel) ? `<section class="cd"><h2>پشتیبانی و تمدید</h2><div class="ct">${btn(s.bot, "ربات تلگرام")}${btn(s.channel, "کانال تلگرام")}</div></section>` : ""}
<div class="n">${stale ? "ورکر در دسترس نیست؛ آخرین اطلاعات ذخیره‌شده نمایش داده می‌شود.<br>" : ""}${esc(s.brand)}</div></div>
<script>document.addEventListener("click",e=>{const t=e.target.closest("button[data-c]");if(!t)return;const v=t.dataset.c,o=t.textContent,ok=()=>{t.textContent="کپی شد";setTimeout(()=>t.textContent=o,1200)};(navigator.clipboard?navigator.clipboard.writeText(v):Promise.reject()).then(ok,()=>{const a=document.createElement("textarea");a.value=v;document.body.append(a);a.select();document.execCommand("copy");a.remove();ok()})})</script></body></html>`;
}

async function api(req, env, u, p) {
  if (!env.ADMIN_KEY || req.headers.get("authorization") !== "Bearer " + env.ADMIN_KEY) return json({ e: "auth" }, 401);
  const DB = env.DB, m = req.method;
  const body = m === "POST" ? await req.json().catch(() => ({})) : {};
  if (p === "/api/state") {
    const w = (await DB.prepare("SELECT * FROM workers").all()).results;
    const c = (await DB.prepare("SELECT token,name,worker_id,sub FROM customers ORDER BY created DESC").all()).results;
    return json({ s: await cfg(DB), w, c });
  }
  if (p === "/api/settings") {
    if (body.fm) { try { JSON.parse(body.fm); } catch { return json({ e: "finalmask JSON نامعتبر است" }, 400); } }
    const st = [];
    for (const k in DEF) if (k in body) st.push(DB.prepare("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)").bind(k, String(body[k])));
    if (st.length) await DB.batch(st);
    return json({ ok: 1 });
  }
  if (p === "/api/worker") {
    if (m === "DELETE") { await DB.prepare("DELETE FROM workers WHERE id=?").bind(u.searchParams.get("id")).run(); return json({ ok: 1 }); }
    const host = String(body.host || "").replace(/^https?:\/\//, "").split("/")[0];
    if (!host) return json({ e: "آدرس لازم است" }, 400);
    await DB.prepare("INSERT INTO workers(name,host,route) VALUES(?,?,?)").bind(body.name || host, host, String(body.route || "sync").replace(/^\/+|\/+$/g, "")).run();
    return json({ ok: 1 });
  }
  if (p === "/api/customer") {
    if (m === "DELETE") { await DB.prepare("DELETE FROM customers WHERE token=?").bind(u.searchParams.get("token")).run(); return json({ ok: 1 }); }
    if (!body.worker_id || !body.sub) return json({ e: "ورکر و نام ساب لازم است" }, 400);
    const token = [...crypto.getRandomValues(new Uint8Array(9))].map((b) => (b % 36).toString(36)).join("");
    await DB.prepare("INSERT INTO customers(token,name,worker_id,sub,created) VALUES(?,?,?,?,?)").bind(token, body.name || body.sub, body.worker_id, body.sub, Date.now()).run();
    return json({ token, link: u.origin + "/s/" + token });
  }
  return json({ e: "not found" }, 404);
}

const ADMIN = `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NexiUP Admin</title>
<style>body{font:14px Tahoma,sans-serif;margin:0;padding:16px;background:#f1f2fb;color:#14172e}.w{max-width:820px;margin:auto}section{background:#fff;border-radius:14px;padding:16px;margin-bottom:14px}h2{margin:0 0 10px;font-size:16px}
input,textarea,select{width:100%;padding:8px;border:1px solid #ccd;border-radius:8px;font:inherit;margin:3px 0 8px}textarea{min-height:70px;direction:ltr}.f{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0 10px}
button{background:#6d5dfc;color:#fff;border:0;border-radius:8px;padding:8px 16px;font:inherit;cursor:pointer}button.d{background:#e5484d;padding:4px 10px}.r{display:flex;gap:8px;align-items:center;padding:6px 0;border-top:1px solid #eee}.r code{flex:1;direction:ltr;overflow:hidden;text-overflow:ellipsis;font-size:12px}label.c{display:flex;gap:6px;align-items:center}label.c input{width:auto;margin:0}</style></head><body><div class="w"><h1>NexiUP</h1><div id="o">...</div></div>
<script>
var K=localStorage.k||(localStorage.k=prompt("Admin key")||"");
function E(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;")}
function $(i){return document.getElementById(i)}
function a(m,p,b){return fetch("/api/"+p,{method:m,headers:{authorization:"Bearer "+K,"content-type":"application/json"},body:b?JSON.stringify(b):undefined}).then(function(r){if(r.status==401){localStorage.removeItem("k");alert("کلید اشتباه است");location.reload()}return r.json()})}
var F=[["brand","نام برند"],["bot","لینک ربات تلگرام"],["channel","لینک کانال تلگرام"],["accent","رنگ اصلی (#hex)"]];
function load(){a("GET","state").then(function(d){var s=d.s,h="<section><h2>تنظیمات</h2><div class=f>";
F.forEach(function(f){h+="<label>"+f[1]+"<input id=s_"+f[0]+" value=\\""+E(s[f[0]])+"\\"></label>"});
h+="</div>";[["Fp","fp","Fingerprint"],["Cs","cs","cipherSuites"],["Fm","fm","finalmask (JSON)"]].forEach(function(x){
h+="<label class=c><input type=checkbox id=s_use"+x[0]+(s["use"+x[0]]=="1"?" checked":"")+"> اعمال "+x[2]+"</label>"+(x[1]=="fp"?"<input id=s_fp value=\\""+E(s.fp)+"\\">":"<textarea id=s_"+x[1]+">"+E(s[x[1]])+"</textarea>")});
h+="<button onclick=sv()>ذخیره تنظیمات</button></section><section><h2>ورکرها</h2>";
d.w.forEach(function(w){h+="<div class=r><b>"+E(w.name)+"</b><code>"+E(w.host)+"/"+E(w.route)+"</code><button class=d onclick=\\"del('worker?id="+w.id+"')\\">حذف</button></div>"});
h+="<div class=f><input id=wn placeholder=نام><input id=wh placeholder='آدرس ورکر (xxx.workers.dev)'><input id=wr placeholder='مسیر ساب (پیش‌فرض sync)'></div><button onclick=aw()>افزودن ورکر</button></section><section><h2>مشتریان</h2>";
d.c.forEach(function(c){var l=location.origin+"/s/"+c.token;h+="<div class=r><b>"+E(c.name)+"</b><code>"+E(l)+"</code><button onclick=\\"navigator.clipboard.writeText('"+l+"')\\">کپی</button><button class=d onclick=\\"del('customer?token="+c.token+"')\\">حذف</button></div>"});
h+="<div class=f><select id=cw>"+d.w.map(function(w){return"<option value="+w.id+">"+E(w.name)+"</option>"}).join("")+"</select><input id=cs_ placeholder='نام ساب در نهان (مثلاً test)'><input id=cn placeholder='نام نمایشی (اختیاری)'></div><button onclick=ac()>ساخت لینک</button></section>";
$("o").innerHTML=h})}
function sv(){var b={};F.forEach(function(f){b[f[0]]=$("s_"+f[0]).value});b.fp=$("s_fp").value;b.cs=$("s_cs").value;b.fm=$("s_fm").value;["Fp","Cs","Fm"].forEach(function(x){b["use"+x]=$("s_use"+x).checked?"1":"0"});a("POST","settings",b).then(function(r){alert(r.e||"ذخیره شد")})}
function aw(){a("POST","worker",{name:$("wn").value,host:$("wh").value,route:$("wr").value}).then(load)}
function ac(){a("POST","customer",{worker_id:$("cw").value,sub:$("cs_").value,name:$("cn").value}).then(function(r){if(r.e)return alert(r.e);prompt("لینک مشتری:",r.link);load()})}
function del(p){if(confirm("حذف شود؟"))a("DELETE",p).then(load)}
load()
</script></body></html>`;

export default {
  async fetch(req, env) {
    try {
      if (!env.DB) return txt("Bind a D1 database as DB", 500);
      await init(env.DB);
      const u = new URL(req.url), p = u.pathname;
      if (p.startsWith("/s/")) return await sub(req, env, u, p.slice(3));
      if (p === "/admin") return html(ADMIN);
      if (p.startsWith("/api/")) return await api(req, env, u, p);
      return txt("Not found", 404);
    } catch (e) { return txt("Error", 500); }
  },
};
