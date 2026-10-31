/* One renderer for live sessions and recorded runs. No build step. */
"use strict";

const $ = (id) => document.getElementById(id);
const I18N = {
  en: { chat: "Conversation", map: "Control map", send: "Send", assessed: "Observed from outside",
    assessedSub: "no violation seen, of the testable controls", documented: "Documented by answers", documentedSub: "evidence or declarations, never merged",
    touches: "Owner actions", time: "Time", calls: "AI decisions", egress: "Outside connections", timeline: "Agent activity",
    ai: "AI decisions", aiHint: "What the model saw, the allowed menu, its choice, and the code verdict.",
    live: "Live session", placeholder: "Type your reply…", chapters: "Chapters", start: "Start replay",
    startHint: "Space starts the replay · 1 2 4 9 changes speed · A opens AI decisions · C opens chapters", owner: "Owner", iris: "Iris", lab: "Later change",
    contradiction: "Claim contradicted", handover: "Handed to a person", irisSteps: "Iris steps", ownerSteps: "Owner steps" },
  ar: { chat: "المحادثة", map: "خريطة الضوابط", send: "إرسال", assessed: "المرصود من الخارج",
    assessedSub: "لم تُرصد مخالفة، من الضوابط القابلة للفحص", documented: "الموثّق بالإجابات", documentedSub: "بأدلة أو إقرارات، لا يُدمج مع الأول",
    touches: "إجراءات المالك", time: "الوقت", calls: "قرارات الذكاء الاصطناعي", egress: "اتصالات خارجية", timeline: "ما يفعله الوكيل",
    ai: "قرارات الذكاء الاصطناعي", aiHint: "ما رآه النموذج والقائمة المسموحة واختياره وحكم الكود.", live: "جلسة مباشرة",
    placeholder: "اكتب ردّك…", chapters: "الفصول", start: "ابدأ الإعادة", startHint: "مسافة للبدء · 1 2 4 9 للسرعة · A لقرارات الذكاء الاصطناعي · C للفصول",
    owner: "المالك", iris: "آيريس", lab: "تغيير لاحق", contradiction: "ادعاء متناقض", handover: "أُحيل إلى مختص", irisSteps: "خطوات آيريس", ownerSteps: "خطوات المالك" },
};
const PHASES = [["scope", "النطاق", "Scope"], ["ownership", "الملكية", "Ownership"], ["scan", "الفحص", "Scan"],
  ["interview", "المقابلة", "Interview"], ["reconcile", "المطابقة", "Reconcile"], ["fix", "المعالجة", "Fix"], ["report", "التقرير", "Report"],
  ["monitor", "المراقبة", "Monitor"]];
const controlsAr = (n) => n === 1 ? "ضابط واحد" : n === 2 ? "ضابطان" : `${n} ${n % 100 >= 3 && n % 100 <= 10 ? "ضوابط" : "ضابطاً"}`;
const LEGEND = [["violation", "مخالفة مرصودة", "Violation observed"], ["clean", "لم تُرصد مخالفة", "No violation observed"],
  ["contradicted", "ادعاء يناقضه الفحص", "Claim contradicted"], ["not_observable", "تعذّرت رؤيته", "Not observable"],
  ["declared_evidence", "مُقرّ بدليل", "Declared with evidence"], ["declared", "مُقرّ", "Declared"], ["self_gap", "فجوة أقرّ بها المالك", "Owner-reported gap"],
  ["needs_answer", "يحتاج إجابة", "Needs an answer"], ["unknown", "غير معروف بعد", "Not known yet"]];
const TILE_NAMES = Object.fromEntries(LEGEND.map(([k, ar, en]) => [k, { ar, en }]));
const PHASE_IDX = Object.fromEntries(PHASES.map(([k], i) => [k, i]));
const SUB_EN = { "1-1": "Strategy", "1-2": "Management", "1-3": "Policies and procedures", "1-4": "Roles and responsibilities", "1-5": "Risk management",
  "1-6": "IT projects", "1-7": "Compliance with laws", "1-8": "Review and audit", "1-9": "Human resources", "1-10": "Awareness and training",
  "2-1": "Asset management", "2-2": "Identity and access", "2-3": "Systems protection", "2-4": "Email protection", "2-5": "Network security",
  "2-6": "Mobile devices", "2-7": "Data protection", "2-8": "Cryptography", "2-9": "Backup and recovery", "2-10": "Vulnerability management",
  "2-11": "Penetration testing", "2-12": "Logs and monitoring", "2-13": "Incidents and threats", "2-14": "Physical security", "2-15": "Web applications",
  "": "Small-entity controls", "3-1": "Business continuity", "4-1": "Third parties", "4-2": "Cloud and hosting" };
const GROUPS = { dns: ["البريد وDNS", "email and DNS"], web: ["الموقع", "website"], tls: ["الشهادات", "certificates"], ports: ["الخدمات المكشوفة", "exposed services"] };

let lang = "en";
let tax = null;
let brand = null;
let chapters = [];
let translations = { owner_replies: {}, tickets: {}, calendar: [] };
let presenter = false;
const S = { tiles: {}, scope: {}, defaultScope: {}, touches: 0, calls: 0, t: 0, ai: 0, session: null, pending: null, replay: null, reported: new Set(), final: null, metrics: null, monitor: null,
  pendingSeq: -1, reportHref: "", calendarHref: "", file: "", phase: null, source: null, eventSteps: 0, ownerSteps: 0 };

function t(key) { return (I18N[lang] || I18N.en)[key] || key; }
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function pick(ar, en) { return lang === "ar" ? ar : en; }

function setPresenterCaption(title, explanation, visible = true) {
  const caption = $("presenterCaption");
  $("presenterCaptionTitle").textContent = title || "";
  $("presenterCaptionExplanation").textContent = explanation || "";
  caption.hidden = !presenter || !visible;
}

async function boot() {
  [tax, brand, chapters, translations] = await Promise.all([
    fetch("taxonomy.json").then((r) => r.json()),
    fetch("brand.json").then((r) => r.json()).catch(() => null),
    fetch("chapters.json").then((r) => r.json()).catch(() => []),
    fetch("translations_en.json").then((r) => r.json()).catch(() => ({ owner_replies: {}, tickets: {}, calendar: [] })),
  ]);
  for (const r of tax.rows) if (r.b) S.defaultScope[r.id] = r.b;
  const params = new URLSearchParams(location.search);
  if (params.get("lang") === "ar") lang = "ar";
  presenter = params.get("present") === "1";
  document.body.classList.toggle("presenter-mode", presenter);
  setPresenterCaption("", "", false);
  if (brand) {
    document.title = brand.name_en;
    $("introSub").textContent = presenter ? brand.challenge : `${brand.company_en} · ${brand.challenge}`;
  }
  buildPhases(); buildMap(); buildLegend(); buildChapters(); applyLang();
  $("langBtn").onclick = () => toggleLang();
  const aiDot = $("aiToggle").querySelector(".dot");
  if (aiDot) aiDot.outerHTML = irisIcon("brain", "ai");
  $("aiDrawer").querySelector("h2")?.insertAdjacentHTML("afterbegin", irisIcon("brain", "ai"));
  $("aiToggle").onclick = () => toggleAi();
  $("aiClose").onclick = () => { $("aiDrawer").hidden = true; };
  $("playBtn").onclick = () => togglePlay();
  $("chaptersBtn").onclick = () => { $("chapters").hidden = !$("chapters").hidden; };
  $("helpBtn").onclick = () => { $("helpWrap").hidden = false; };
  $("helpClose").onclick = () => { $("helpWrap").hidden = true; };
  $("helpWrap").onclick = (e) => { if (e.target.id === "helpWrap") $("helpWrap").hidden = true; };
  if (brand && brand.repo_url) $("repoLink").href = brand.repo_url;
  $("videoLink").hidden = !(brand && brand.video_url);
  if (brand && brand.video_url) $("videoLink").href = brand.video_url;
  $("composer").onsubmit = (e) => { e.preventDefault(); sendText(); };
  if (presenter) { $("runPicker").hidden = true; $("helpBtn").hidden = true; }
  document.addEventListener("keydown", onKey);
  const runs = await fetch("runs/index.json").then((r) => r.json()).catch(() => []);
  for (const r of runs) { const o = document.createElement("option"); o.value = r; o.textContent = r; $("runPicker").append(o); }
  $("runPicker").onchange = () => startReplay($("runPicker").value);
  const live = await fetch("api/ping").then((r) => r.json()).then((data) => data.ok === true).catch(() => false);
  if (live) { $("liveBtn").hidden = false; $("liveBtn").onclick = () => startLive(); }
  const initial = params.get("run") || runs.find((r) => r.includes("demo")) || runs[0];
  if (params.get("live")) { startLive(params.get("owner") || "ui"); return; }
  if (!initial) return;
  $("runPicker").value = initial;
  const at = params.get("at");
  const intro = params.get("intro") !== "0" && !at && params.get("autoplay") !== "0";
  await startReplay(initial, false);
  if (at === "end") { while (S.replay.i < S.replay.events.length) handle(S.replay.events[S.replay.i++]); }
  else if (at) { const n = Number(at); while (S.replay.i < Math.min(n, S.replay.events.length)) handle(S.replay.events[S.replay.i++]); }
  if (params.get("ai") === "1") $("aiDrawer").hidden = false;
  if (params.get("chapters") === "1") $("chapters").hidden = false;
  if (intro) {
    $("introWrap").hidden = false;
    $("startBtn").onclick = startDemo;
  } else if (!at && params.get("autoplay") !== "0") togglePlay(true);
  else if (at && params.get("play") === "1") togglePlay(true);
}

function startDemo() {
  const w = $("introWrap"); w.style.transition = "opacity .6s ease"; w.style.opacity = "0";
  setTimeout(() => { w.hidden = true; w.style.opacity = ""; if (!presenter) togglePlay(true); }, 600);
}

function onKey(e) {
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
  if (!$("introWrap").hidden && (e.key === " " || e.key === "Enter")) { e.preventDefault(); startDemo(); return; }
  if (e.key === "Escape") { $("aiDrawer").hidden = true; $("helpWrap").hidden = true; $("chapters").hidden = true; return; }
  if (e.key === " ") { e.preventDefault(); togglePlay(); return; }
  if (e.key === "ArrowRight") { e.preventDefault(); stepOnce(); return; }
  const speeds = { 1: "1", 2: "2", 4: "4", 9: "9" };
  if (speeds[e.key]) { $("speed").value = speeds[e.key]; return; }
  if (e.key === "a" || e.key === "A") toggleAi();
  if (e.key === "l" || e.key === "L") toggleLang();
  if (e.key === "c" || e.key === "C") $("chapters").hidden = !$("chapters").hidden;
}

function toggleAi() { $("aiDrawer").hidden = !$("aiDrawer").hidden; }
function toggleLang() { lang = lang === "ar" ? "en" : "ar"; applyLang(); }

function applyLang() {
  document.documentElement.lang = lang; document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  $("langBtn").textContent = lang === "ar" ? "EN" : "ع";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $("composerInput").placeholder = t("placeholder");
  if (brand) {
    $("brandName").textContent = brand.name_en.toUpperCase();
    $("brandTag").textContent = pick(brand.tagline_ar, brand.tagline_en);
    $("introTag").textContent = pick(brand.tagline_ar, brand.tagline_en);
    $("introSub").textContent = presenter ? brand.challenge : pick(`${brand.company_ar} · ${brand.challenge}`, `${brand.company_en} · ${brand.challenge}`);
  }
  document.querySelectorAll("[data-ar]").forEach((el) => {
    const v = lang === "ar" ? el.dataset.ar : el.dataset.en;
    if (el.dataset.html === "1") el.innerHTML = v; else el.textContent = v;
  });
  document.querySelectorAll(".msg.owner").forEach((el) => { el.dataset.who = t("owner"); });
  document.querySelectorAll(".msg.contra").forEach((el) => { el.dataset.kind = t("contradiction"); });
  document.querySelectorAll(".msg.warn").forEach((el) => { el.dataset.kind = t("handover"); });
  document.querySelectorAll(".msg.note").forEach((el) => { el.dataset.kind = t("lab"); });
  buildPhases(S.phase); buildLegend(); buildChapters(); relabelMap();
  if (S.final) renderFinal();
}

function buildPhases(current) {
  const ol = $("phases"); ol.innerHTML = "";
  const idx = current ? PHASE_IDX[current] ?? 99 : -1;
  PHASES.forEach(([, ar, en], i) => {
    const li = document.createElement("li"); li.textContent = pick(ar, en);
    if (i < idx || current === "done") li.className = "done"; else if (i === idx) li.className = "now";
    ol.append(li);
  });
}

function buildChapters() {
  const nav = $("chapters"); nav.innerHTML = "";
  for (const c of chapters) {
    const b = document.createElement("button"); b.type = "button";
    b.innerHTML = `${esc(pick(c.ar, c.en))}<b>${c.at}</b>`;
    b.onclick = () => jumpTo(c.at);
    nav.append(b);
  }
}

function buildMap() {
  const map = $("map"); map.innerHTML = "";
  for (const d of ["1", "2", "3", "4"]) {
    const box = document.createElement("div"); box.className = "domain"; box.dataset.domain = d;
    const h = document.createElement("h4"); h.dataset.domain = d; box.append(h);
    const subs = Object.keys(tax.subdomains[d] || {}).sort(natural);
    for (const s of subs) {
      const row = document.createElement("div"); row.className = "sub";
      const name = document.createElement("div"); name.className = "sname"; name.dataset.sub = s; row.append(name);
      const tiles = document.createElement("div"); tiles.className = "tiles";
      for (const r of tax.rows.filter((x) => x.d === d && x.s === s).sort((a, b) => natural(a.id, b.id))) {
        const el = document.createElement("div");
        el.className = "tile t-unknown" + (r.k === "main" ? " main" : "") + (S.defaultScope[r.id] ? "" : " oos");
        el.id = "tile-" + r.id; el.dataset.id = r.id;
        tiles.append(el);
      }
      row.append(tiles); box.append(row);
    }
    map.append(box);
  }
  relabelMap();
}

function relabelMap() {
  if (!tax) return;
  document.querySelectorAll(".domain h4").forEach((h) => {
    const d = h.dataset.domain; const rows = tax.rows.filter((r) => r.d === d);
    h.innerHTML = `<span>${esc(tax.domains[d][lang] || tax.domains[d].ar)}</span><span>${rows.length}</span>`;
  });
  document.querySelectorAll(".sname").forEach((n) => {
    const s = n.dataset.sub; const d = n.closest(".domain").dataset.domain;
    const nm = tax.subdomains[d][s]; n.textContent = (s ? s + " · " : "") + (lang === "ar" ? nm.ar : (SUB_EN[s] || nm.ar));
    n.title = n.textContent;
  });
  const scopeOf = Object.keys(S.scope).length ? S.scope : S.defaultScope;
  document.querySelectorAll(".tile").forEach((el) => {
    const r = tax.rows.find((x) => x.id === el.dataset.id); const st = S.tiles[el.dataset.id] || "unknown";
    const scope = scopeOf[el.dataset.id];
    el.title = `${r.id} · ${pick("الفئة", "Tier")} ${r.t} · ${scope ? (scope === "M" ? pick("إلزامي", "mandatory") : pick("موصى به", "recommended")) : pick("خارج النطاق", "out of scope")} · ${TILE_NAMES[st][lang]}`;
  });
}

function buildLegend() {
  $("legend").innerHTML = LEGEND.map(([k, ar, en]) => `<span><i class="t-${k}"></i>${pick(ar, en)}</span>`).join("");
}

function natural(a, b) {
  const pa = String(a).split("-").map(Number), pb = String(b).split("-").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] ?? -1) - (pb[i] ?? -1); if (d) return d; }
  return 0;
}

function reset() {
  $("messages").innerHTML = ""; $("timeline").innerHTML = ""; $("aiList").innerHTML = "";
  delete document.body.dataset.phase;
  delete document.body.dataset.replayEvent;
  delete document.body.dataset.replayKind;
  setPresenterCaption("", "", false);
  Object.assign(S, { tiles: {}, scope: {}, touches: 0, calls: 0, ai: 0, phase: null, pending: null, reported: new Set(), final: null, metrics: null, monitor: null, eventSteps: 0, ownerSteps: 0 });
  setCounter("cTouches", 0); setCounter("cCalls", 0); setCounter("cEgress", 0); setCounter("cIrisSteps", 0); setCounter("cOwnerSteps", 0); $("aiCount").textContent = "0"; $("cTime").textContent = "0:00";
  setRing("Assessed", null); setRing("Documented", null); $("scopeChip").textContent = ""; $("company").textContent = "";
  document.querySelectorAll(".tile").forEach((el) => { el.className = "tile t-unknown" + (el.classList.contains("main") ? " main" : "") + (S.defaultScope[el.dataset.id] ? "" : " oos"); });
  buildPhases();
}

/* Events */

function handle(ev) {
  const d = ev.data || {};
  S.eventSteps++;
  if (ev.type === "owner_reply") S.ownerSteps++;
  setCounter("cOwnerSteps", S.ownerSteps);
  setCounter("cIrisSteps", S.eventSteps - S.ownerSteps);
  document.body.dataset.replayEvent = ev.type;
  document.body.dataset.replayKind = d.kind || "";
  S.t = ev.t || S.t; $("cTime").textContent = fmtTime(S.t);
  switch (ev.type) {
    case "session_started":
      if (document.body.classList.contains("presenter-mode")) setText($("company"), "منشأة صغيرة", "Sample small business");
      else setText($("company"), d.company_ar, d.company);
      tl(["بدأت الجلسة", "Session started"], [d.model || "", d.model || ""], "mark"); break;
    case "phase": S.phase = d.phase; document.body.dataset.phase = d.phase; buildPhases(d.phase); break;
    case "scope":
      setText($("scopeChip"), `${scopeLabel(d.scope, "ar")} · ${controlsAr(d.rows)}`, `${scopeLabel(d.scope, "en")} · ${d.rows} controls`);
      if (d.changed) tl(["تغيّر النطاق وأُعيد ترتيب الأسئلة", "Scope changed; questions re-prioritised"], [scopeLabel(d.scope, "ar"), scopeLabel(d.scope, "en")], "warn");
      break;
    case "owner_request":
      S.touches = d.human_touches; setCounter("cTouches", S.touches); S.pendingSeq = ev.seq;
      bubble("agent", d.text_ar, d.text_en, d.payload && d.payload.records ? recordsHtml(d.payload.records) : "");
      if (S.session && !S.replay) askOwner(d); break;
    case "owner_reply": {
      const picks = (d.choices || []);
      if (!d.text && picks.length) bubble("owner", pillsHtml(picks, "ar"), pillsHtml(picks, "en"), "", true);
      else {
        const translated = translations.owner_replies?.[String(ev.seq)] || d.text;
        const english = `${esc(translated)}<details class="original-reply"><summary>AR</summary><span lang="ar" dir="rtl">${esc(d.text)}</span></details>`;
        bubble("owner", esc(d.text), english, "", true);
      }
      break;
    }
    case "agent_message": bubble(d.topic === "contradiction" ? "agent contra" : "agent", d.text_ar, d.text_en); break;
    case "model_call": aiCall(d); break;
    case "ownership_challenge": tl(["طُلب إثبات ملكية النطاق", "Ownership proof requested"], [`${d.records.length} TXT`, `${d.records.length} TXT`]); break;
    case "ownership_verified": tl(["ثبتت الملكية، يُسمح بالفحص", "Ownership verified. Scanning unlocked"], ["", ""], "mark"); break;
    case "tool_call": tl(toolLabel(d), d.attempt ? [`#${d.attempt}`, `#${d.attempt}`] : ["", ""]); break;
    case "tool_result": {
      const g = GROUPS[d.group] || [d.group, d.group];
      tl([`نتيجة فحص ${g[0]}`, `Scan result: ${g[1]}`], [`${d.findings.length} مرصود · ${d.unread.length} لم يُقرأ · ${d.duration_ms} ms`, `${d.findings.length} found · ${d.unread.length} unread · ${d.duration_ms} ms`], d.findings.length ? "bad" : "ok"); break;
    }
    case "assessment": paint(d); break;
    case "answer":
      tl([`${d.qid} ← ${answerLabel(d.answer, "ar")}`, `${d.qid} → ${answerLabel(d.answer, "en")}`],
        [`${controlsAr(d.controls)} · ${d.source === "model" ? "النموذج" : d.source}${d.evidence ? " · بدليل" : ""}`, `${d.controls} controls · ${d.source}${d.evidence ? " · evidence" : ""}`]); break;
    case "contradiction":
      tl([`تناقض في ${d.qid}`, `Contradiction on ${d.qid}`], [(d.observed || []).join(", "), (d.observed || []).join(", ")], "warn");
      if (d.qid === "Q01") bubble(
        "agent contra",
        "قال المالك: «إيه، الإيميل محمي، مزود البريد مسوي كل شي». وجد الفحص أن SPF وDMARC غير موجودين، فحسم الفحص النتيجة.",
        "Owner said: “Yes, the email is protected.” The scan found SPF and DMARC missing, so the scan wins."
      );
      break;
    case "plan": bubble("agent", planHtml(d.fixes, "ar"), planHtml(d.fixes, "en"), "", true); break;
    case "fix_result":
      if (d.reason === "nothing_to_change") { tl([`لا حاجة: ${d.fix_id}`, `Not needed: ${d.fix_id}`], ["لا شيء لتغييره", "nothing to change"]); break; }
      tl([`تحقق بفحص جديد: ${d.fix_id}`, `Re-scan check: ${d.fix_id}`], d.verified ? ["✓ ثبت", "✓ verified"] : (d.verified === false ? ["✗ لم يثبت", "✗ not verified"] : ["—", "—"]), d.verified ? "ok" : "bad"); break;
    case "fix_drafted": tl([`مسودة تعديل: ${d.fix_id}`, `Drafted change: ${d.fix_id}`], ["", ""]); break;
    case "escalation": bubble("agent warn", d.text_ar, d.text_en); tl(["إحالة إلى مختص", "Handed to a person"], [d.reason, d.reason], "warn"); break;
    case "metrics": setCounter("cEgress", d.egress_blocked ?? 0); S.metrics = d; renderFinal(); break;
    case "report_ready": {
      if (S.reported.has(d.file)) break;
      S.reported.add(d.file);
      const base = (S.file || "").split("/").slice(0, -1).join("/");
      S.reportHref = "runs/" + (base ? base + "/" : "") + d.file; renderFinal(); break;
    }
    case "document_drafted": tl([`مسودة جاهزة: ${d.title_ar}`, `Draft ready: ${d.title_en}`], [d.qid, d.qid], "ok"); break;
    case "action_plan": tl(["خطة عمل ٩٠ يوماً", "90-day action plan"], [`${d.items} بنداً · ${d.within_30} خلال ٣٠ يوماً`, `${d.items} items · ${d.within_30} within 30 days`], "ok"); break;
    case "ticket_drafted": tl([`تذكرة للدعم التقني: ${d.title_ar}`, `IT ticket: ${d.check}`], d.urgent ? ["عاجل", "urgent"] : ["", ""], d.urgent ? "warn" : ""); break;
    case "calendar_ready": {
      const base = (S.file || "").split("/").slice(0, -1).join("/");
      S.calendarHref = "runs/" + (base ? base + "/" : "") + d.file;
      tl(["تقويم المهام الدورية", "Recurring-task calendar"], [d.file, d.file], "ok"); break;
    }
    case "lab_note":
      if (document.body.classList.contains("presenter-mode")) {
        bubble("agent note", "أعاد تغيير لاحق فتح منفذ وأضاف خدمة.", "A later change re-opened a port and added a service.");
        tl(["تغيير لاحق", "Later change"], [d.estate, d.estate], "warn");
      } else {
        bubble("agent note", d.text_ar, d.text_en);
        tl(["تغيّر في الاختبار", "Test change"], [d.estate, d.estate], "warn");
      }
      break;
    case "monitor_round":
      if (d.stage === "start") tl([`جولة مراقبة ${d.round}`, `Monitoring round ${d.round}`], ["", ""], "mark");
      else if (d.stage === "end") tl([`نهاية الجولة ${d.round}`, `Round ${d.round} done`], [`${d.new.length} جديد · ${d.verified.length} ✓`, `${d.new.length} new · ${d.verified.length} verified`], d.new.length ? "warn" : "ok");
      break;
    case "monitor_summary": S.monitor = d; renderFinal(); break;
    case "error": tl(["خطأ", "error"], [d.kind, d.kind], "bad"); break;
  }
}

function paint(d) {
  S.scope = d.scope || S.scope;
  const scopeOf = Object.keys(S.scope).length ? S.scope : S.defaultScope;
  for (const [id, st] of Object.entries(d.tiles || {})) {
    const el = $("tile-" + id); if (!el) continue;
    const changed = S.tiles[id] !== st;
    S.tiles[id] = st;
    el.className = "tile t-" + st + (el.classList.contains("main") ? " main" : "") + (scopeOf[id] ? "" : " oos");
    if (changed && st !== "unknown" && st !== "needs_answer") { void el.offsetWidth; el.classList.add("flash"); }
  }
  setRing("Assessed", d.assessed); setRing("Documented", d.documented); relabelMap();
}

function setRing(which, v) {
  const ring = $("ring" + which), val = $("val" + which);
  if (v == null) { ring.style.setProperty("--p", 0); val.textContent = "–"; return; }
  ring.style.setProperty("--p", (v * 100).toFixed(1)); val.textContent = Math.round(v * 100) + "%";
}

function setCounter(id, v) { $(id).textContent = String(v); }
function setText(el, ar, en) { el.dataset.ar = ar; el.dataset.en = en; el.textContent = pick(ar, en); }
function fmtTime(s) { const m = Math.floor(s / 60), r = Math.floor(s % 60); return `${m}:${String(r).padStart(2, "0")}`; }
function scopeLabel(s, l) { return { class_b: l === "ar" ? "الفئة (ب) · NCNICC" : "NCNICC Class B", class_a: l === "ar" ? "الفئة (أ) · NCNICC" : "NCNICC Class A", ecc: "ECC-2:2024", out: l === "ar" ? "خارج النطاق" : "Out of scope" }[s] || s; }
function answerLabel(a, l) { return ({ yes: ["نعم", "yes"], no: ["لا", "no"], partial: ["جزئياً", "partly"], unknown: ["لا يعرف", "doesn't know"] }[a] || [a, a])[l === "ar" ? 0 : 1]; }
function toolLabel(d) {
  if (d.tool === "scan") { const g = GROUPS[d.group] || [d.group, d.group]; return [`فحص: ${g[0]}`, `Scanning ${g[1]}`]; }
  if (d.tool === "fix") return [`تطبيق تعديل: ${d.fix_id}`, `Applying fix: ${d.fix_id}`];
  return [d.tool, d.tool];
}

function bubble(cls, ar, en, extra = "", html = false) {
  const div = document.createElement("div"); div.className = "msg " + cls;
  const body = document.createElement("div");
  body.dataset.ar = html ? ar : esc(ar); body.dataset.en = html ? en : esc(en); body.dataset.html = "1";
  body.innerHTML = pick(body.dataset.ar, body.dataset.en);
  div.append(body);
  if (extra) div.insertAdjacentHTML("beforeend", extra);
  if (cls.includes("owner")) div.dataset.who = t("owner");
  if (cls.includes("contra")) div.dataset.kind = t("contradiction");
  else if (cls.includes("warn")) div.dataset.kind = t("handover");
  else if (cls.includes("note")) div.dataset.kind = t("lab");
  $("messages").append(div); $("messages").scrollTop = $("messages").scrollHeight;
  return div;
}

function pillsHtml(picks, l) { return `<div class="choices">${picks.map((p) => `<span class="pick on">${esc(["yes", "no", "partial", "unknown"].includes(p) ? answerLabel(p, l) : p)}</span>`).join("")}</div>`; }
function recordNameForDisplay(name) {
  const parts = String(name || "").split(".");
  if (!document.body.classList.contains("presenter-mode") || parts.at(-1) !== "test") return name;
  const marker = parts[0]?.startsWith("_") ? `${parts.shift()}.` : "";
  const web = parts[0] === "www" ? `${parts.shift()}.` : "";
  return `${marker}${web}business.example`;
}
function recordsHtml(records) { return `<div class="records">${records.map((r) => `${esc(recordNameForDisplay(r.name))}  TXT  "${esc(r.value || "…")}"`).join("<br>")}</div>`; }
function planHtml(fixes, l) {
  const head = l === "ar" ? "<b>خطة المعالجة</b>" : "<b>Fix plan</b>";
  return head + "<ol>" + fixes.map((f) => `<li>${esc(l === "ar" ? f.title_ar : f.title_en)}<br><small>${esc(l === "ar" ? f.steps_ar : f.steps_en)}</small></li>`).join("") + "</ol>";
}

function tl(title, sub, cls = "") {
  const li = document.createElement("li"); li.className = cls;
  const [tAr, tEn] = title, [sAr, sEn] = sub;
  const auto = `<span class="auto-marker">AUTO</span>`;
  li.dataset.ar = `${auto}${esc(tAr)}${sAr ? `<small>${esc(sAr)}</small>` : ""}`;
  li.dataset.en = `${auto}${esc(tEn)}${sEn ? `<small>${esc(sEn)}</small>` : ""}`;
  li.dataset.html = "1"; li.innerHTML = pick(li.dataset.ar, li.dataset.en);
  $("timeline").prepend(li);
}

function aiCall(d) {
  if (isAiDecision(d)) {
    S.ai++; $("aiCount").textContent = String(S.ai);
    S.calls++; setCounter("cCalls", S.calls);
  }
  const verdict = d.verdict || "";
  const cls = verdict === "accepted" ? "ok" : verdict.startsWith("illegal") ? "bad" : verdict === "only_option" ? "" : "fb";
  const roles = { parse: ["فهم الإجابة", "Read the reply"], choose: ["اختيار الخطوة", "Choose next step"], explain: ["شرح للمالك", "Explain to owner"] };
  const verdicts = { accepted: ["مقبول", "Accepted"], template: ["قالب", "Template"], only_option: ["الخيار الوحيد", "Only option"] };
  const role = roles[d.role] || [d.role, d.role];
  const v = verdicts[verdict] || (verdict.startsWith("illegal") ? ["مرفوض", "Refused"] : [verdict, verdict]);
  const menu = d.menu ? `<div class="menu">${d.menu.map((m) => `<span class="${m === d.picked ? "picked" : ""}">${esc(m)}</span>`).join("")}</div>` : "";
  const out = d.output ? `<pre class="out">${esc(prettyJson(d.output))}</pre>` : "";
  const prompt = d.prompt ? `<pre>${esc(d.prompt)}</pre>` : "";
  const typedReply = d.role === "parse" && d.prompt ? d.prompt.match(/Owner's reply:\s*([^\n]+)/)?.[1] : "";
  const received = typedReply ? `<div class="typed-reply"><b>reply as typed</b><span lang="ar" dir="rtl">${esc(typedReply)}</span></div>` : "";
  const header = (l) => `<header><span class="badge role">${esc(role[l])}</span><span class="badge">${esc(d.model || (l ? "no model" : "بلا نموذج"))}</span>`
    + `<span class="badge ${cls}">${esc(v[l])}</span>${d.ms != null ? `<span class="badge ms">${d.ms} ms</span>` : ""}</header>`;
  const card = document.createElement("div"); card.className = "call";
  card.dataset.ar = header(0) + menu + received + prompt + out; card.dataset.en = header(1) + menu + received + prompt + out; card.dataset.html = "1";
  card.innerHTML = pick(card.dataset.ar, card.dataset.en);
  $("aiList").prepend(card);
}
function prettyJson(s) { try { return JSON.stringify(JSON.parse(s), null, 1); } catch { return s; } }

function renderFinal() {
  const m = S.metrics; if (!m) return;
  const pc = (v) => v != null ? Math.round(v * 100) + "%" : "—";
  const docs = (S.replay ? S.replay.events.slice(0, S.replay.i) : []).filter((e) => e.type === "document_drafted").length;
  const tickets = (S.replay ? S.replay.events.slice(0, S.replay.i) : []).filter((e) => e.type === "ticket_drafted").length;
  const plan = (S.replay ? S.replay.events.slice(0, S.replay.i) : []).find((e) => e.type === "action_plan");
  const mo = S.monitor;
  const rows = (l) => {
    const a = l === "ar";
    const r = [
      [a ? "أسئلة" : "Questions", m.questions_asked], [a ? "إجراءات المالك" : "Owner actions", m.human_touches],
      [a ? "قرارات الذكاء الاصطناعي، خارج القائمة" : "AI decisions · outside the menu", `${m.model_calls} · ${m.illegal_choices ?? 0}`],
      [a ? "مرصود من الخارج قبل → بعد" : "Observed from outside, before → after", `${pc(m.assessed_before)} → ${pc(m.assessed_after)}`],
      [a ? "تعديلات ثبتت بفحص جديد" : "Fixes verified by re-scan", (m.fixes_verified || []).length],
      [a ? "أُحيل إلى مختص" : "Handed to a person", (m.escalations || []).length],
      [a ? "مستندات مُسوَّدة" : "Documents drafted", docs], [a ? "تذاكر للدعم التقني" : "IT tickets", tickets],
    ];
    if (plan) r.push([a ? "بنود خطة ٩٠ يوماً" : "90-day plan items", plan.data.items]);
    if (mo) r.push([a ? "المراقبة: جولات · جديد · أُعيد إصلاحه · استُؤذن" : "Monitoring: rounds · new · re-fixed · asked first",
      `${mo.rounds} · ${(mo.new || []).length} · ${(mo.reapplied || []).length} · ${(mo.approved || []).length + (mo.declined || []).length}`]);
    r.push([a ? "ثوانٍ" : "Seconds", m.seconds]);
    return r;
  };
  const table = (l) => `<table>${rows(l).map(([k, v]) => `<tr><td>${k}</td><td>${v ?? "—"}</td></tr>`).join("")}</table>`;
  const links = (l) => {
    const reportHref = l === "en" ? S.reportHref.replace(/\.report\.html$/, ".report.en.html") : S.reportHref;
    return `<div class="links">${S.reportHref ? `<a class="pick" href="${esc(reportHref)}" target="_blank" rel="noopener">${l === "ar" ? "فتح التقرير" : "Open the report"}</a>` : ""}`
    + `${S.calendarHref ? `<a class="pick" href="${esc(S.calendarHref)}" target="_blank" rel="noopener">${l === "ar" ? "التقويم" : "Calendar file"}</a>` : ""}</div>`;
  };
  const head = (l) => `<b>${mo ? (l === "ar" ? "اكتملت المراقبة" : "Monitoring complete") : (l === "ar" ? "اكتمل التقييم" : "Assessment complete")}</b>`;
  if (!S.final) S.final = bubble("agent final", "", "", "", true);
  const body = S.final.firstElementChild;
  body.dataset.ar = head("ar") + table("ar") + links("ar"); body.dataset.en = head("en") + table("en") + links("en");
  body.innerHTML = pick(body.dataset.ar, body.dataset.en);
  $("messages").scrollTop = $("messages").scrollHeight;
}

/* Replay */

async function startReplay(file, autoplay = true) {
  stopAll(); reset();
  S.file = file;
  const text = await fetch("runs/" + file).then((r) => r.text());
  const events = text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  S.replay = { events, i: 0, playing: false, timer: null };
  setText($("foot"), `إعادة تشغيل تسجيل حقيقي · ${file} · ${events.length} حدثاً · ${events.at(-1)?.hash?.slice(0, 12) || ""}`,
    `Replaying a recorded run · ${file} · ${events.length} events · audit head ${events.at(-1)?.hash?.slice(0, 12) || ""}`);
  if (autoplay) togglePlay(true);
}

function togglePlay(force) {
  const R = S.replay; if (!R) return;
  R.playing = force ?? !R.playing; $("playBtn").textContent = R.playing ? "❚❚" : "▶";
  if (R.playing) step();
  else clearTimeout(R.timer);
}

function stepOnce() {
  const R = S.replay; if (!R) return;
  if (R.playing) togglePlay(false);
  if (R.i < R.events.length) handle(R.events[R.i++]);
}

function step() {
  const R = S.replay; if (!R || !R.playing) return;
  if (R.i >= R.events.length) { R.playing = false; $("playBtn").textContent = "▶"; return; }
  const ev = R.events[R.i++]; handle(ev);
  const next = R.events[R.i];
  const speed = Number($("speed").value) || 4;
  const gap = next ? Math.min(2500, Math.max(60, ((next.t - ev.t) * 1000) / speed)) : 0;
  const pace = ["owner_request", "agent_message", "escalation", "plan", "metrics", "lab_note"].includes(ev.type) ? 900 / Math.sqrt(speed) : 0;
  R.timer = setTimeout(step, Math.max(gap, pace));
}

function jumpTo(n) {
  const R = S.replay; if (!R) return;
  const wasPlaying = R.playing;
  clearTimeout(R.timer); R.playing = false;
  const events = R.events; reset();
  S.replay = { events, i: 0, playing: false, timer: null };
  while (S.replay.i < Math.min(n, events.length)) handle(events[S.replay.i++]);
  $("chapters").hidden = true;
  if (wasPlaying) togglePlay(true); else $("playBtn").textContent = "▶";
}

function stopAll() {
  if (S.replay) { clearTimeout(S.replay.timer); S.replay = null; }
  if (S.source) { S.source.close(); S.source = null; }
}

/* Live */

async function startLive(owner = "ui") {
  stopAll(); reset(); $("introWrap").hidden = true;
  const res = await fetch("api/session", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "lab", owner }) }).then((r) => r.json());
  S.session = res.session; S.file = res.file;
  setText($("foot"), `جلسة مباشرة على المختبر · ${res.file}`, `Live lab session · ${res.file}`);
  S.source = new EventSource(`api/session/${S.session}/events`);
  S.source.onmessage = (m) => handle(JSON.parse(m.data));
}

function askOwner(d) {
  S.pending = d; const box = $("composer");
  if (d.kind === "buttons" || d.kind === "approve_fixes" || d.kind === "publish_txt" || d.kind === "staff_band") {
    box.hidden = true;
    const wrap = document.createElement("div"); wrap.className = "choices";
    const opts = d.kind === "publish_txt" ? ["done"] : d.options;
    const picked = new Set(d.kind === "approve_fixes" ? opts : []);
    for (const o of opts) {
      const b = document.createElement("button"); b.type = "button"; b.textContent = o === "done" ? pick("أضفت السجل", "I added the record") : o;
      if (picked.has(o)) b.classList.add("on");
      b.onclick = () => {
        if (d.kind === "approve_fixes") { b.classList.toggle("on"); picked.has(o) ? picked.delete(o) : picked.add(o); return; }
        reply({ text: o === "done" ? "تم" : "", choices: o === "done" ? [] : [o] }); wrap.remove();
      };
      wrap.append(b);
    }
    if (d.kind === "approve_fixes") {
      const ok = document.createElement("button"); ok.type = "button"; ok.className = "on"; ok.textContent = pick("اعتماد", "Approve");
      ok.onclick = () => { reply({ choices: [...picked] }); wrap.remove(); }; wrap.append(ok);
    }
    $("messages").lastElementChild.append(wrap);
  } else { box.hidden = false; $("composerInput").focus(); }
}

function sendText() {
  const v = $("composerInput").value.trim(); if (!v || !S.pending) return;
  $("composerInput").value = ""; $("composer").hidden = true; reply({ text: v });
}

async function reply(body) {
  S.pending = null;
  await fetch(`api/session/${S.session}/reply`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...body, seq: S.pendingSeq }) });
}

boot();
