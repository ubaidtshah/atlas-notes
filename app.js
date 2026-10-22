if (window.top !== window.self) { document.documentElement.replaceChildren(); throw new Error("framed"); }

"use strict";
const VAULT = {salt:"jbwFFWPYe5zjs4vJsK29mQ==", iter:600000, manifest:"a4e3bbb523d1f3f8897f0162.bin"};
const IDLE_MS = 15 * 60 * 1000;
let KEY = null, M = null, current = null, downloads = null, idleTimer = null, failures = 0, lockedUntil = 0;
const urls = new Set();
const $ = id => document.getElementById(id);
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

async function deriveKey(pw){
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt:b64(VAULT.salt), iterations:VAULT.iter, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, false, ["decrypt"]);
}
async function fetchDec(name){
  if (!/^[0-9a-f]{24}\.bin$/.test(name)) throw new Error("bad name");
  const r = await fetch("enc/" + name.replace(/\.bin$/, ".txt"), {cache:"no-store"}); if (!r.ok) throw new Error("missing");
  const buf = b64((await r.text()).trim());
  return crypto.subtle.decrypt({name:"AES-GCM", iv:buf.slice(0,12)}, KEY, buf.slice(12));
}
async function imgURL(name){ const u = URL.createObjectURL(new Blob([await fetchDec(name)], {type:"image/jpeg"})); urls.add(u); return u; }

/* ---------- unlock ---------- */
$("lockform").addEventListener("submit", async e => {
  e.preventDefault();
  const now = Date.now();
  if (now < lockedUntil){ $("err").textContent = `Too many attempts. Try again in ${Math.ceil((lockedUntil-now)/1000)} seconds.`; return; }
  const pw = $("pw").value.trim(); if (!pw) return;
  $("unlock").disabled = true; $("unlock").textContent = "Unlocking…"; $("err").textContent = "";
  try {
    KEY = await deriveKey(pw);
    M = JSON.parse(new TextDecoder().decode(await fetchDec(VAULT.manifest)));
    $("pw").value = ""; failures = 0;
    renderVault(); armIdle();
  } catch(err) {
    KEY = null; failures++;
    if (failures >= 5){ lockedUntil = Date.now() + 30000 * Math.pow(2, failures - 5); }
    $("err").textContent = "That password didn't open the vault. Check for a missing character or an extra space.";
  } finally { $("unlock").disabled = false; $("unlock").textContent = "Unlock"; }
});

function armIdle(){ clearTimeout(idleTimer); if (KEY) idleTimer = setTimeout(() => { lockVault(); $("err").textContent = "Locked after 15 minutes without activity."; }, IDLE_MS); }
["pointerdown","keydown","scroll","touchstart"].forEach(ev => addEventListener(ev, armIdle, {passive:true, capture:true}));
document.addEventListener("visibilitychange", () => { if (document.hidden && KEY) { clearTimeout(idleTimer); idleTimer = setTimeout(lockVault, 5 * 60 * 1000); } });

function lockVault(){
  closeDoc(); KEY = null; M = null; calY = null; clearTimeout(idleTimer);
  for (const u of urls) URL.revokeObjectURL(u); urls.clear();
  ["reg","shelf","comp","feed","stats","typechips","cal-grid","agenda","unsched"].forEach(id => $(id).replaceChildren());
  $("area").replaceChildren(); $("q").value = "";
  $("vault").hidden = true; $("lock").hidden = false; $("pw").focus();
}
$("relock").addEventListener("click", lockVault);

/* ---------- tabs ---------- */
function showTab(which){
  for (const k of ["logs","cal","docs"]){ $("view-" + k).hidden = k !== which; $("tab-" + k).setAttribute("aria-selected", k === which); }
  if (which === "cal") renderCal();
}
$("tab-logs").addEventListener("click", () => showTab("logs"));
$("tab-cal").addEventListener("click", () => showTab("cal"));
$("tab-docs").addEventListener("click", () => showTab("docs"));

/* ---------- render ---------- */
const TYPES = ["All","Approval","Decision","Security","Issued","Research","System"];
let fType = "All";
function renderVault(){
  $("lock").hidden = true; $("vault").hidden = false; showTab("logs");
  const L = M.log || [];
  const n = t => L.filter(e => e.type === t).length;
  const stats = [[L.length,"events"],[n("Decision"),"decisions"],[n("Security"),"security events"],[M.docs.length,"documents"]];
  $("stats").replaceChildren(...stats.map(([v,l]) => { const d = el("div","stat"); d.append(el("b",null,String(v)), el("span",null,l)); return d; }));
  $("typechips").replaceChildren(...TYPES.map(t => {
    const b = el("button","chip t-" + t.toLowerCase(), t); b.type = "button"; b.setAttribute("aria-pressed", t === fType);
    b.addEventListener("click", () => { fType = t; [...$("typechips").children].forEach(c => c.setAttribute("aria-pressed", c.textContent === t)); renderFeed(); });
    return b;
  }));
  const areas = ["All areas", ...[...new Set(L.map(e => e.area))].sort()];
  $("area").replaceChildren(...areas.map(a => { const o = el("option", null, a); o.value = a; return o; }));
  renderFeed(); renderDocs();
}
$("q").addEventListener("input", () => renderFeed());
$("area").addEventListener("change", () => renderFeed());

function hl(parent, text, terms){
  if (!terms.length){ parent.append(text); return; }
  const re = new RegExp("(" + terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")", "gi");
  let last = 0; text.replace(re, (m, _g, i) => { parent.append(text.slice(last, i), el("mark", null, m)); last = i + m.length; return m; });
  parent.append(text.slice(last));
}

function renderFeed(){
  const L = (M && M.log) || [];
  const terms = $("q").value.trim().toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
  const area = $("area").value || "All areas";
  const hits = L.filter(e => {
    if (fType !== "All" && e.type !== fType) return false;
    if (area !== "All areas" && e.area !== area) return false;
    if (!terms.length) return true;
    const hay = [e.title,e.summary,e.what,e.why,e.tech,e.area,e.type,(e.tags||[]).join(" ")].join(" ").toLowerCase();
    return terms.every(t => hay.includes(t));
  }).slice().reverse();
  $("count").textContent = hits.length === L.length ? `${L.length} events, newest first` : `${hits.length} of ${L.length} events`;
  const feed = $("feed"); feed.replaceChildren();
  if (!hits.length){ const p = el("div","empty","Nothing matches. Try fewer words, or clear the filters."); feed.append(p); return; }
  let day = null;
  for (const e of hits){
    if (e.d !== day){ day = e.d; feed.append(el("div","dayhead", new Date(e.d + "T12:00:00").toLocaleDateString("en-US",{weekday:"long",month:"long",day:"numeric",year:"numeric"}))); }
    const card = el("details","ev");
    if (terms.length) card.open = true;
    const sm = el("summary");
    const top = el("div","evtop");
    top.append(el("span","tm", e.t), el("span","pill t-" + e.type.toLowerCase(), e.type), el("span","ar", e.area));
    const ttl = el("div","evtitle"); hl(ttl, e.title, terms);
    const sub = el("div","evsum"); hl(sub, e.summary, terms);
    sm.append(top, ttl, sub); card.append(sm);
    const body = el("div","evbody");
    for (const [label, key, cls] of [["What happened","what",""],["Why it matters","why",""],["Under the hood","tech","code"]]){
      const blk = el("div","blk " + cls); blk.append(el("h4",null,label)); const p = el("p"); hl(p, e[key], terms); blk.append(p); body.append(blk);
    }
    const foot = el("div","evfoot");
    for (const t of (e.tags || [])){ const c = el("button","tag", "#" + t); c.type = "button"; c.addEventListener("click", ev => { ev.preventDefault(); $("q").value = t; renderFeed(); $("q").scrollIntoView({block:"center"}); }); foot.append(c); }
    if (e.doc){ const d = M.docs.find(x => x.id === e.doc); if (d){ const b = el("button","btn small", "Open " + d.title); b.type = "button"; b.addEventListener("click", () => openDoc(d)); foot.append(b); } }
    body.append(foot); card.append(body); feed.append(card);
  }
}

function renderDocs(){
  const reg = $("reg"), shelf = $("shelf"), comp = $("comp");
  reg.replaceChildren(); shelf.replaceChildren(); comp.replaceChildren();
  for (const d of M.docs){
    const tr = el("tr");
    const c1 = el("td","no", d.no);
    const c2 = el("td"); c2.append(el("div","dname", d.title), el("div","dsub", d.sub));
    const pill = el("span","pill " + (d.status[1] === "p-master" ? "p-master" : "p-action"), d.status[0]);
    const c6 = el("td"); c6.append(pill);
    const ob = el("button","openbtn","Open"); ob.type = "button"; const c7 = el("td"); c7.append(ob);
    tr.append(c1, c2, el("td",null,"v" + d.ver), el("td",null,d.date), el("td",null,String(d.pages.length)), c6, c7);
    tr.addEventListener("click", () => openDoc(d)); reg.append(tr);
    const b = el("button","book"); b.type = "button";
    const img = el("img"); img.alt = "Cover of " + d.title;
    const bt = el("div","bt"); bt.append(el("b",null,d.title), el("span",null,`${d.no} · v${d.ver} · ${d.pages.length} pages`));
    b.append(img, bt); b.addEventListener("click", () => openDoc(d)); shelf.append(b);
    imgURL(d.pages[0]).then(u => img.src = u).catch(() => {});
  }
  for (const c of (M.companions || [])){
    if (!/^https:\/\/claude\.ai\//.test(c.u)) continue;
    const a = el("a","ccard"); a.href = c.u; a.target = "_blank"; a.rel = "noopener noreferrer";
    a.append(el("b",null,c.t), el("span",null,c.s)); comp.append(a);
  }
}


/* ---------- calendar ---------- */
const pad = n => String(n).padStart(2,"0");
const iso = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
let calY = null, calM = null, calSel = null;
function dayItems(ds){
  const L = (M && M.log) || [], S = (M && M.schedule) || [];
  return { approvals: L.filter(e => e.d === ds && e.type === "Approval"), events: L.filter(e => e.d === ds && e.type !== "Approval"), plans: S.filter(x => x.d === ds || (typeof x.weekly === "number" && ds >= (x.start || "") && new Date(ds + "T12:00:00").getDay() === x.weekly)) };
}
function renderCal(){
  if (!M) return;
  const now = new Date();
  if (calY === null){ calY = now.getFullYear(); calM = now.getMonth(); calSel = iso(now); }
  $("cal-month").textContent = new Date(calY, calM, 1).toLocaleDateString("en-US", {month:"long", year:"numeric"});
  const grid = $("cal-grid"); grid.replaceChildren();
  for (const w of ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]) grid.append(el("div","dow", w));
  const first = new Date(calY, calM, 1), start = first.getDay(), days = new Date(calY, calM + 1, 0).getDate();
  for (let i = 0; i < start; i++) grid.append(el("div","cell blank"));
  const today = iso(now);
  for (let day = 1; day <= days; day++){
    const ds = `${calY}-${pad(calM+1)}-${pad(day)}`, it = dayItems(ds);
    const c = el("button","cell"); c.type = "button"; c.setAttribute("role","gridcell");
    if (ds === today) c.classList.add("today"); if (ds === calSel) c.classList.add("sel");
    c.append(el("span","num", String(day)));
    const dots = el("div","dots");
    const add = (n, cls, label) => { if (!n) return; const x = el("span","pip " + cls); x.append(el("i","dot " + cls.replace("p-","d-")), el("b",null,String(n))); x.title = `${n} ${label}`; dots.append(x); };
    add(it.approvals.length, "p-approval", "approvals"); add(it.events.length, "p-event", "events"); add(it.plans.length, "p-plan", "scheduled");
    c.append(dots);
    const total = it.approvals.length + it.events.length + it.plans.length;
    c.setAttribute("aria-label", `${ds}: ${total} items`);
    c.addEventListener("click", () => { calSel = ds; renderCal(); $("agenda").scrollIntoView({block:"start", behavior:"smooth"}); });
    grid.append(c);
  }
  renderAgenda(); renderUnsched();
}
function renderAgenda(){
  const ag = $("agenda"); ag.replaceChildren();
  const it = dayItems(calSel);
  ag.append(el("div","dayhead", new Date(calSel + "T12:00:00").toLocaleDateString("en-US",{weekday:"long",month:"long",day:"numeric",year:"numeric"})));
  const sec = (title, list, render) => { if (!list.length) return; ag.append(el("h3","agh", `${title} · ${list.length}`)); list.forEach(x => ag.append(render(x))); };
  const row = (time, pillCls, pillText, title, sub) => { const r = el("div","agrow"); const t = el("div","agtop"); if (time) t.append(el("span","tm",time)); t.append(el("span","pill " + pillCls, pillText)); r.append(t, el("div","evtitle",title), el("div","evsum",sub)); return r; };
  sec("Scheduled", it.plans, x => row(null, "t-plan", x.status, x.title, x.detail));
  sec("Approvals", it.approvals, e => row(e.t, "t-approval", "Approval", e.title, e.summary));
  sec("Events", it.events, e => row(e.t, "t-" + e.type.toLowerCase(), e.type, e.title, e.summary));
  if (!it.plans.length && !it.approvals.length && !it.events.length) ag.append(el("div","empty","Nothing recorded or scheduled for this day."));
}
function renderUnsched(){
  const u = $("unsched"); u.replaceChildren();
  const list = ((M && M.schedule) || []).filter(x => !x.d && typeof x.weekly !== "number");
  if (!list.length){ u.append(el("div","empty","Everything has a date.")); return; }
  for (const x of list){ const r = el("div","agrow"); const t = el("div","agtop"); t.append(el("span","pill t-plan", x.status), el("span","ar", x.area)); r.append(t, el("div","evtitle", x.title), el("div","evsum", x.detail)); u.append(r); }
}
$("cal-prev").addEventListener("click", () => { calM--; if (calM < 0){ calM = 11; calY--; } renderCal(); });
$("cal-next").addEventListener("click", () => { calM++; if (calM > 11){ calM = 0; calY++; } renderCal(); });
$("cal-today").addEventListener("click", () => { calY = null; renderCal(); });

/* ---------- reader ---------- */
async function openDoc(d){
  current = d;
  $("r-title").textContent = d.title;
  $("r-sub").textContent = `${d.no} · v${d.ver} · ${d.pages.length} PAGES · ${d.date.toUpperCase()}`;
  const pages = $("pages"); pages.replaceChildren(); pages.scrollTop = 0;
  $("reader").hidden = false; document.body.style.overflow = "hidden";
  const imgs = d.pages.map((n, i) => { const im = el("img"); im.alt = `${d.title}, page ${i+1}`; pages.append(im); return im; });
  const io = new IntersectionObserver(ents => {
    for (const e of ents) if (e.isIntersecting) {
      const i = imgs.indexOf(e.target); io.unobserve(e.target);
      imgURL(d.pages[i]).then(u => { if (current === d) e.target.src = u; }).catch(() => {});
    }
  }, {root: pages, rootMargin: "800px 0px"});
  imgs.forEach(im => io.observe(im));
}
function closeDoc(){ $("reader").hidden = true; current = null; document.body.style.overflow = ""; }
$("back").addEventListener("click", closeDoc);
document.addEventListener("keydown", e => { if (e.key === "Escape" && !$("reader").hidden) closeDoc(); });

function toast(msg){ const t = $("toast"); t.textContent = msg; t.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => t.hidden = true, 3200); }

$("save").addEventListener("click", async () => {
  if (!current || !KEY) return;
  const d = current, btn = $("save");
  btn.disabled = true; btn.textContent = "Preparing…";
  try {
    const data = new Blob([await fetchDec(d.pdf)], {type:"application/pdf"});
    if (downloads) { const r = await downloads.save({filename: d.file, data}); if (r && r.status === "saved") toast("Saved " + d.file); }
    else { const u = URL.createObjectURL(data), a = el("a"); a.href = u; a.download = d.file; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 10000); }
  } catch (err) { if (!(err && err.code === "declined")) toast("Couldn't prepare the PDF. Try again in a moment."); }
  finally { btn.disabled = false; btn.textContent = "Save PDF"; }
});
(async () => { try { downloads = window.claude && window.claude.use ? await window.claude.use("downloads") : null; } catch(e) { downloads = null; } })();
