import { FEATURED_FACTS as F, PLAN_ITEMS, STORY_CASE as C, STORY_SCREENS } from "./story_data.js";

const params = new URLSearchParams(location.search);
if (params.get("present") !== "1") {
  // The module is intentionally inert for the standard replay and live interface.
} else {
  const state = { index: Math.max(0, Math.min(8, Number(params.get("story") || 1) - 1)), events: [], translations: {}, results: {} };
  const q = (selector) => document.querySelector(selector);
  const lang = () => document.documentElement.lang === "ar" ? "ar" : "en";
  const tx = (en, ar) => lang() === "ar" ? ar : en;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const ic = (name, tone = "iris") => irisIcon(name, tone);

  document.body.classList.add("story-mode");
  document.body.insertAdjacentHTML("beforeend", `
    <div class="story-progress" id="storyProgress" aria-label="Story progress"></div>
    <section class="story-overlay" id="storyOverlay" aria-live="polite">
      <article class="story-panel" id="storyPanel"></article>
    </section>
    <aside class="live-story-hud" id="liveStoryHud" hidden>
      <span>${tx("LIVE RUN", "تشغيل حي")}</span><b id="liveStoryTitle"></b>
      <div><strong id="hudIris">0</strong> ${tx("Iris steps", "خطوات آيريس")} <i></i><strong id="hudOwner">0</strong> ${tx("Owner steps", "خطوات المالك")}</div>
    </aside>`);

  function panelHead(index) {
    const screen = STORY_SCREENS[index];
    return `<header class="story-head"><span>${String(index + 1).padStart(2, "0")}</span><div><p>${screen.group === "none" ? "IRIS" : screen.group.toUpperCase()}</p><h1>${esc(screen.title[lang()])}</h1></div><small>${index + 1} / 9</small></header>`;
  }

  function problem() {
    return `${panelHead(0)}<div class="problem-grid">
      <div class="hero-stat danger">${ic("building-2", "problem")}<b data-count="1300000">1.3M</b><span>${tx("SMEs in the Kingdom", "منشأة صغيرة ومتوسطة في المملكة")}</span><small>${tx("Monsha'at SME Monitor, end of 2023", "مرصد منشآت، نهاية 2023")}</small></div>
      <div class="problem-stack">
        <div>${ic("shield-check", "problem")}<b>~22,000</b><span>${tx("cybersecurity specialists", "متخصص أمن سيبراني")}</span><small>NCA, Key Economic Indicators 2026</small></div>
        <div>${ic("scan-search", "problem")}<b>500+</b><span>${tx("SMEs targeted by NCA's initiative", "منشأة تستهدفها مبادرة الهيئة")}</span><em class="reach-note">${tx("Fewer than 1 in 2,500 SMEs.", "أقل من منشأة من كل 2,500.")}</em><small>${tx("NCA, November 2025", "الهيئة الوطنية للأمن السيبراني، نوفمبر 2025")}</small></div>
      </div>
      <div class="risk-row"><div>${ic("circle-alert", "problem")}<b>82%</b><span>${tx("hit by a cyber incident", "تعرضت لحادث سيبراني")}</span><small>Kaspersky, Sep 2026</small></div><div>${ic("cpu", "problem")}<b>SAR 27M</b><span>${tx("average breach cost", "متوسط تكلفة الاختراق")}</span><small>IBM 2026, Saudi findings</small></div><div>${ic("timer", "problem")}<b>226</b><span>${tx("days to find a breach", "يوماً لاكتشاف الاختراق")}</span><small>IBM 2026, Saudi findings</small></div></div>
    </div>`;
  }

  function loop() {
    const nodes = [
      ["01", "SCAN", "يفحص", "scan-search"], ["02", "ASK", "يسأل", "message-square-text"], ["03", "CHECK", "يطابق", "scale"],
      ["04", "FIX", "يصلح", "wrench"], ["05", "RE-SCAN", "يعيد الفحص", "shield-check"], ["06", "DELIVER", "يسلّم", "file-text"],
    ];
    return `${panelHead(1)}<div class="loop-layout"><div class="loop-diagram">${nodes.map(([n,en,ar,icon]) => `<div class="loop-node">${ic(icon)}<span>${n}</span><b>${tx(en, ar)}</b></div>`).join("")}<div class="loop-branch"><b>${tx("Safe change", "تغيير آمن")}</b><span>${tx("fix it and prove it", "يصلحه ويثبت النتيجة")}</span><i></i><b>${tx("Risky change", "تغيير خطر")}</b><span>${tx("ready-to-run IT ticket", "تذكرة جاهزة للتنفيذ")}</span></div></div><aside class="owner-touch"><p>${ic("message-square-text")}${tx("THE OWNER", "المالك")}</p><div><span>01</span>${tx("Proves the domain", "يثبت ملكية النطاق")}</div><div><span>02</span>${tx("Answers what a scan cannot see", "يجيب عما لا يراه الفحص")}</div><div><span>03</span>${tx("Approves changes", "يعتمد التغييرات")}</div><strong>${tx("Iris runs the assessment end to end.", "آيريس ينفذ التقييم من البداية إلى النهاية.")}</strong></aside></div>`;
  }

  function automation() {
    return `${panelHead(2)}<div class="automation-layout"><div class="split-ring" style="--iris:${F.irisSteps};--owner:${F.ownerSteps}"><div>${ic("workflow")}<b>${F.irisSteps}</b><span>${tx("Iris steps", "خطوات آيريس")}</span><small>${F.irisSteps} / ${F.events}</small></div></div><div class="automation-evidence"><p class="story-claim">${tx("The owner answers and approves. Iris does the rest.", "المالك يجيب ويعتمد. آيريس يتولى الباقي.")}</p><div class="evidence-grid"><span>${ic("scan-search")}<b>${F.scans}</b>${tx("scans", "فحصاً")}</span><span>${ic("scale", "ai")}<b>${F.contradictions}</b>${tx("contradictions caught", "تناقضات اكتشفها")}</span><span>${ic("shield-check", "proof")}<b>${F.assessmentFixes}</b>${tx("assessment fixes proven", "إصلاحات تقييم مثبتة")}</span><span>${ic("ticket")}<b>${F.tickets}</b>${tx("IT tickets", "تذاكر تقنية")}</span><span>${ic("file-text")}<b>${F.documents}</b>${tx("documents", "مستندات")}</span><span>${ic("calendar-check")}<b>${F.calendarEvents}</b>${tx("calendar events", "مواعيد تقويم")}</span></div><div class="monitor-strip">${ic("eye", "proof")}<b>31 / 31</b><span>${tx("approved fixes re-applied and proven", "إصلاحاً معتمداً أُعيد تطبيقه وإثباته")}</span></div></div></div>`;
  }

  function ai() {
    return `${panelHead(3)}<div class="ai-layout"><p class="ai-principle">${ic("cpu", "ai")}<strong>${tx("AI only where it adds value.", "الذكاء الاصطناعي حيث يضيف قيمة فقط.")}</strong> ${tx("A scanner and a rules engine do the checking and fixing.", "الماسح ومحرك القواعد يتوليان الفحص والإصلاح.")}</p><div class="arch-line"><div><span>${ic("brain", "ai")}${tx("OWNER'S MACHINE", "جهاز المالك")}</span><b>${tx("Local AI model", "نموذج ذكاء اصطناعي محلي")}</b><b>${tx("Reads owner replies", "يفهم ردود المالك")}</b><b>${tx("Chooses the next step", "يختار الخطوة التالية")}</b></div><i><em>${ic("lock", "ai")}${tx("Verified facts only", "حقائق متحقق منها فقط")}</em></i><div><span>${ic("scan-search")}${tx("IRIS SCANNER", "ماسح آيريس")}</span><b>${tx("Ownership check", "إثبات الملكية")}</b><b>${tx("32 checks", "32 فحصاً")}</b><b>${tx("Approved fixes", "الإصلاحات المعتمدة")}</b></div><i></i><div><span>${ic("building-2")}${tx("THE BUSINESS", "المنشأة")}</span><b>${tx("Email and DNS", "البريد وDNS")}</b><b>${tx("Website", "الموقع")}</b><b>${tx("Exposed services", "الخدمات المكشوفة")}</b></div></div><div class="trace-case"><p>${tx("ONE ANSWER, TRACED", "تتبّع إجابة واحدة")}</p><div>${ic("message-square-text", "ai")}<b>${tx("Owner says", "يقول المالك")}</b><span lang="ar" dir="rtl">«${esc(C.replyAr)}»</span><small>${C.replyEn}</small></div><div>${ic("brain", "ai")}<b>${tx("AI reads it", "يفهمها الذكاء")}</b><code>answer: ${C.answer}</code></div><div>${ic("scale", "problem")}<b>${tx("Scan wins", "الفحص يحسم")}</b><span>${tx(C.findings, "SPF وDMARC غير موجودين")}</span></div><div>${ic("shield-check", "proof")}<b>${tx("Fix proven", "إصلاح مثبت")}</b><span>${tx(C.result, "أُصلحا وأثبتتهما إعادة الفحص")}</span></div></div></div>`;
  }

  function outputs() {
    return `${panelHead(5)}<div class="output-shell"><nav class="output-tabs" id="outputTabs"></nav><div class="output-body" id="outputBody"></div></div>`;
  }

  function results() {
    const held = state.results["e1-held_out-ollama_qwen3_8b"]?.all || {};
    const live = state.results["e6-held_out-ollama_qwen3_8b"] || {};
    const injection = state.results.e4?.models || {};
    const raw = Object.values(injection).map((m) => m.naive_raw_text?.choose_attack_success || 0);
    const rawAvg = raw.length ? Math.round(raw.reduce((a,b) => a+b, 0) / raw.length * 100) : 68;
    return `${panelHead(6)}<div class="results-layout"><div class="result-heroes"><span>${ic("scan-search", "proof")}<b>${live.planted_found || "23/23"}</b>${tx("planted vulnerabilities found", "ثغرة مزروعة اكتُشفت")}</span><span>${ic("shield-check", "proof")}<b>${live.fixable_defects_removed || "20/20"}</b>${tx("fixed and proven", "عولجت وأُثبتت")}</span><span>${ic("eye", "proof")}<b>58/58</b>${tx("later changes caught", "تغيراً لاحقاً اكتُشف")}</span><span>${ic("scale")}<b>${Number(held.violation_detection?.precision || .962).toFixed(2)}</b>${tx("precision", "الدقة")}</span><span>${ic("scale")}<b>${Number(held.violation_detection?.recall || .974).toFixed(2)}</b>${tx("recall", "الاستدعاء")}</span></div><div class="result-charts"><section><h2>${ic("lock", "ai")}${tx("Hidden website instructions", "تعليمات مخفية في المواقع")}</h2><div class="bar-row"><span>${tx("Raw text", "النص الخام")}</span><i style="--v:${rawAvg}"></i><b>${rawAvg}%</b></div><div class="bar-row safe"><span>${tx("Typed boundary", "الحد الفاصل")}</span><i style="--v:0"></i><b>0/30 × 4</b></div></section><section><h2>${ic("workflow")}${tx("Take a part away", "عند إزالة جزء")}</h2><div class="ablation"><span>${tx("Full Iris", "آيريس كامل")}</span><i style="--v:104"></i><b>104 / 120</b></div><div class="ablation"><span>${tx("No interview", "دون مقابلة")}</span><i style="--v:10"></i><b>10 / 120</b></div><div class="ablation danger"><span>${tx("No action gate", "دون بوابة إجراءات")}</span><i style="--v:14"></i><b>14 ${tx("illegal", "مخالفاً")}</b></div><div class="ablation danger"><span>${tx("No re-scan", "دون إعادة فحص")}</span><i style="--v:5"></i><b>5 ${tx("false fixes", "إصلاحات زائفة")}</b></div></section></div></div>`;
  }

  function value() {
    return `${panelHead(7)}<div class="value-pairs"><section><div class="before">${ic("timer", "problem")}<b>226</b><span>${tx("days to find a breach", "يوماً لاكتشاف الاختراق")}</span></div><i>→</i><div class="after">${ic("eye", "proof")}<b>${tx("EVERY WEEK", "كل أسبوع")}</b><span>${tx("58/58 changes caught", "اكتشف 58/58 تغيراً")}</span></div></section><section><div class="before">${ic("building-2", "problem")}<b>1.3M</b><span>${tx("firms · ~22,000 specialists", "منشأة · نحو 22,000 متخصص")}</span></div><i>→</i><div class="after">${ic("timer", "proof")}<b>~3 MIN</b><span>${tx("one complete assessment", "تقييم كامل واحد")}</span></div></section><p><strong>${ic("cpu", "ai")}${tx("AI only where it adds value: low cost, data stays local.", "الذكاء الاصطناعي حيث يضيف قيمة فقط: تكلفة منخفضة، والبيانات تبقى محلية.")}</strong><small>${tx("Capacity grows by adding independent scanners.", "تزداد السعة بإضافة ماسحات مستقلة.")}</small></p></div>`;
  }

  function close() {
    return `<div class="close-screen"><img src="iris.svg?v=2" alt=""><h1>IRIS</h1><p>${tx("Sees it. Fixes it. Proves it.", "يرى. يُصلح. يُثبت.")}</p><div><figure><img src="img/qr-code.png" alt="${tx("Source code QR code", "رمز المصدر")}"><figcaption>GITHUB</figcaption></figure><p>${tx("Demo video: on the project page", "فيديو العرض: في صفحة المشروع")}</p></div></div>`;
  }

  const renderers = [problem, loop, automation, ai, () => "", outputs, results, value, close];

  function renderProgress() {
    const groups = [["input", "Input", "المدخلات"], ["ai", "AI in action", "الذكاء يعمل"], ["output", "Output", "المخرجات"], ["value", "Value", "القيمة"]];
    q("#storyProgress").innerHTML = groups.map(([id,en,ar]) => {
      const indices = STORY_SCREENS.map((s,i) => s.group === id ? i : -1).filter((i) => i >= 0);
      const done = !state.app && state.index > Math.max(...indices), active = !state.app && indices.includes(state.index);
      return `<button type="button" data-screen="${indices[0]}" class="${active ? "active" : done ? "done" : ""}"><i></i><span>${tx(en, ar)}</span></button>`;
    }).join("");
    q("#storyProgress").querySelectorAll("button").forEach((button) => button.onclick = () => show(Number(button.dataset.screen)));
  }

  function showApp() {
    state.app = true;
    document.body.classList.add("story-live", "story-app");
    q("#storyOverlay").hidden = true;
    q("#liveStoryHud").hidden = true;
    window.setPresenterCaption?.("", "", false);
    renderProgress();
  }

  function show(index) {
    state.app = false;
    document.body.classList.remove("story-app");
    state.index = Math.max(0, Math.min(8, index));
    const live = state.index === 4;
    document.body.classList.toggle("story-live", live);
    q("#storyOverlay").hidden = live;
    q("#liveStoryHud").hidden = !live;
    if (live) {
      q("#liveStoryTitle").textContent = STORY_SCREENS[4].title[lang()];
      window.setPresenterCaption?.(STORY_SCREENS[4].title[lang()], tx("Watch the contradiction, verified fixes, escalation and ready tickets.", "راقب التناقضات والإصلاحات المثبتة والإحالة والتذاكر الجاهزة."), true);
      window.togglePlay?.(true);
    } else {
      window.setPresenterCaption?.("", "", false);
      q("#storyPanel").innerHTML = renderers[state.index]();
      if (state.index === 5) renderOutputTabs("overview");
    }
    renderProgress();
    
  }

  function renderOutputTabs(active) {
    const tabs = [["overview","Outputs","المخرجات","sparkles"],["report","Report","التقرير","file-text"],["tickets","7 tickets","7 تذاكر","ticket"],["documents","4 policies","4 سياسات","clipboard-check"],["plan","90-day plan","خطة 90 يوماً","workflow"],["calendar","Calendar","التقويم","calendar-check"]];
    q("#outputTabs").innerHTML = tabs.map(([id,en,ar,icon]) => `<button type="button" data-tab="${id}" class="${id === active ? "active" : ""}">${ic(icon)}${tx(en, ar)}</button>`).join("");
    q("#outputTabs").querySelectorAll("button").forEach((button) => button.onclick = () => renderOutputTabs(button.dataset.tab));
    const events = state.events;
    if (active === "overview") {
      const outputs = [["file-text", "Report", "تقرير", "204", "control rows", "صفوف ضوابط"], ["ticket", "IT tickets", "تذاكر تقنية", "7", "ready to hand over", "جاهزة للتسليم"], ["clipboard-check", "Policies", "سياسات", "4", "ready for approval", "جاهزة للاعتماد"], ["workflow", "Action plan", "خطة عمل", "90", "days prioritised", "يوماً مرتبة"], ["calendar-check", "Calendar", "التقويم", "6", "recurring checks", "فحوص دورية"]];
      q("#outputBody").innerHTML = `<div class="output-overview">${outputs.map(([icon,en,ar,value,detailEn,detailAr]) => `<article>${ic(icon)}<span>${tx(en, ar)}</span><b>${value}</b><small>${tx(detailEn, detailAr)}</small></article>`).join("")}</div>`;
    } else if (active === "report") {
      q("#outputBody").innerHTML = `<iframe title="${tx("Iris assessment report", "تقرير تقييم آيريس")}" src="runs/featured/demo-qwen3.report${lang() === "en" ? ".en" : ""}.html"></iframe>`;
    } else if (active === "calendar") {
      const items = state.translations.calendar || [];
      q("#outputBody").innerHTML = `<div class="calendar-line">${items.map((item) => `<article>${ic("calendar-check")}<time>${esc(item.start)}</time><b>${esc(lang() === "en" ? item.title : calendarAr(item.title))}</b><span>${esc(lang() === "en" ? item.detail : calendarDetailAr(item.title))}</span><em>${esc(lang() === "en" ? item.repeat : repeatAr(item.repeat))}</em></article>`).join("")}</div>`;
    } else if (active === "tickets") {
      const tickets = events.filter((e) => e.type === "ticket_drafted").sort((a,b) => Number(b.data.urgent) - Number(a.data.urgent));
      q("#outputBody").innerHTML = `<div class="ticket-grid">${tickets.map((e) => `<article class="${e.data.urgent ? "urgent" : ""}">${ic("ticket", e.data.urgent ? "problem" : "iris")}<span>${e.data.urgent ? tx("URGENT", "عاجل") : "IT"}</span><b>${esc(lang() === "en" ? state.translations.tickets?.[e.data.check] || e.data.check : e.data.title_ar)}</b><small>${e.data.steps} ${tx("ready-to-run steps", "خطوات جاهزة للتنفيذ")}</small></article>`).join("")}</div>`;
    } else if (active === "documents") {
      const docs = events.filter((e) => e.type === "document_drafted");
      q("#outputBody").innerHTML = `<div class="document-grid">${docs.map((e, i) => `<article>${ic("file-text")}<span>0${i + 1}</span><b>${esc(lang() === "en" ? e.data.title_en : e.data.title_ar)}</b><small>${e.data.sections} ${tx("sections ready for approval", "أقسام جاهزة للاعتماد")}</small></article>`).join("")}</div>`;
    } else {
      q("#outputBody").innerHTML = `<div class="plan-line">${[30,60,90].map((days) => `<section>${ic("calendar-check")}<b>${days}</b><span>${tx("DAYS", "يوماً")}</span>${PLAN_ITEMS.filter((item) => item.days === days).map((item) => `<p class="${item.kind}">${esc(item[lang()])}</p>`).join("")}</section>`).join("")}</div>`;
    }
  }

  function repeatAr(value) { return ({ Weekly:"أسبوعياً", "Every 3 months":"كل 3 أشهر", "Every 6 months":"كل 6 أشهر", Yearly:"سنوياً" })[value] || value; }
  function calendarAr(title) { return ({ "Security monitoring round":"جولة مراقبة أمنية", "Backup restore test":"اختبار استعادة النسخ الاحتياطية", "Accounts and permissions review":"مراجعة الحسابات والصلاحيات", "Phishing reminder for staff":"تذكير الموظفين بالتصيد", "Cybersecurity policy review":"مراجعة سياسة الأمن السيبراني", "Ransomware tabletop exercise":"تمرين مكتبي لبرامج الفدية" })[title] || title; }
  function calendarDetailAr(title) { return ({ "Security monitoring round":"يعيد الوكيل الفحص ويصلح ما عاد.", "Backup restore test":"استعد ملفاً وقاعدة بيانات وسجل النتيجة.", "Accounts and permissions review":"أزل ما لم يعد مستخدماً وتحقق من الدخول الثنائي.", "Phishing reminder for staff":"أرسل رسالة التوعية للموظفين.", "Cybersecurity policy review":"راجع السياسة واعتمد التغييرات.", "Ransomware tabletop exercise":"شغّل خطة الاستجابة على سيناريو." })[title] || ""; }

  function onKey(event) {
    if (["INPUT","SELECT","TEXTAREA"].includes(event.target.tagName)) return;
    if (!q("#introWrap")?.hidden) return;
    if (["ArrowRight","PageDown"].includes(event.key)) { event.preventDefault(); event.stopImmediatePropagation(); show(state.app ? state.index : state.index + 1); }
    else if (["ArrowLeft","PageUp"].includes(event.key)) { event.preventDefault(); event.stopImmediatePropagation(); show(state.app ? state.index : state.index - 1); }
    else if (event.key === "Escape" && !state.app && state.index !== 4) { showApp(); }
    else if (event.key.toLowerCase() === "s") { event.preventDefault(); event.stopImmediatePropagation(); state.app ? show(state.index) : showApp(); }
    else if (event.key.toLowerCase() === "o") { event.preventDefault(); event.stopImmediatePropagation(); show(5); }
  }

  function syncHud() {
    q("#hudIris").textContent = q("#cIrisSteps")?.textContent || "0";
    q("#hudOwner").textContent = q("#cOwnerSteps")?.textContent || "0";
  }

  document.addEventListener("keydown", onKey, true);
  new MutationObserver(() => { if (!state.app && state.index !== 4) show(state.index); }).observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
  new MutationObserver(syncHud).observe(q("#cIrisSteps"), { childList: true, characterData: true, subtree: true });
  Promise.all([
    fetch("runs/featured/demo-qwen3.jsonl").then((r) => r.text()).then((text) => text.split("\n").filter(Boolean).map(JSON.parse)),
    fetch("translations_en.json").then((r) => r.json()),
    fetch("results.json").then((r) => r.json()),
  ]).then(([events, translations, results]) => { state.events = events; state.translations = translations; state.results = results; if (!state.app) show(state.index); }).catch(() => { if (!state.app) show(state.index); });
  state.index = 0;
  history.replaceState(null, "", `${location.pathname}?present=1`);
  showApp();
}
