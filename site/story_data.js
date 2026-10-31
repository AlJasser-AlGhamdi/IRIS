export const FEATURED_FACTS = Object.freeze({
  events: 274,
  irisSteps: 247,
  ownerSteps: 27,
  questions: 14,
  modelDecisions: 46,
  nextStepChoices: 27,
  repliesRead: 19,
  illegalChoices: 0,
  scans: 27,
  contradictions: 3,
  assessmentFixes: 5,
  fixesVerified: 8,
  escalations: 1,
  tickets: 7,
  urgentTickets: 1,
  documents: 4,
  planItems: 13,
  mandatoryGaps: 5,
  calendarEvents: 6,
});

export const STORY_CASE = Object.freeze({
  replyAr: "إيه، الإيميل محمي، مزود البريد مسوي كل شي",
  replyEn: "Yes, the email is protected.",
  answer: "yes",
  findings: "SPF and DMARC missing",
  result: "Both fixed and proven by re-scan",
});

export const STORY_SCREENS = Object.freeze([
  { id: "problem", group: "input", title: { en: "The gap is already here", ar: "الفجوة موجودة اليوم" } },
  { id: "loop", group: "input", title: { en: "One loop does the whole job", ar: "حلقة واحدة تنجز المهمة كاملة" } },
  { id: "automation", group: "ai", title: { en: "What runs on its own", ar: "ما يعمل من تلقاء نفسه" } },
  { id: "ai", group: "ai", title: { en: "Where the AI works", ar: "أين يعمل الذكاء الاصطناعي" } },
  { id: "live", group: "ai", title: { en: "A real run, event by event", ar: "تشغيل حقيقي، حدثاً بعد حدث" } },
  { id: "outputs", group: "output", title: { en: "What the owner receives", ar: "ما يستلمه المالك" } },
  { id: "results", group: "value", title: { en: "Tested on companies it had never seen", ar: "اختُبر على منشآت لم يرها من قبل" } },
  { id: "value", group: "value", title: { en: "From months of exposure to weekly proof", ar: "من شهور الانكشاف إلى إثبات أسبوعي" } },
  { id: "close", group: "none", title: { en: "Sees it. Fixes it. Proves it.", ar: "يرى. يُصلح. يُثبت." } },
]);

export const PLAN_ITEMS = Object.freeze([
  { days: 30, kind: "ticket", en: "Secure remote management", ar: "تأمين الدخول عن بُعد" },
  { days: 60, kind: "gap", en: "Vulnerability management", ar: "إدارة الثغرات" },
  { days: 60, kind: "gap", en: "Accounts and access", ar: "الحسابات والصلاحيات" },
  { days: 60, kind: "gap", en: "Incident response", ar: "الاستجابة للحوادث" },
  { days: 60, kind: "gap", en: "Log review", ar: "مراجعة السجلات" },
  { days: 60, kind: "gap", en: "Asset register", ar: "سجل الأصول" },
  { days: 90, kind: "ticket", en: "Enable DKIM signing", ar: "تفعيل توقيع DKIM" },
  { days: 90, kind: "ticket", en: "Enable DNSSEC", ar: "تفعيل DNSSEC" },
  { days: 90, kind: "ticket", en: "Add website security headers", ar: "إضافة ترويسات أمان الموقع" },
  { days: 90, kind: "ticket", en: "Publish MTA-STS", ar: "نشر MTA-STS" },
  { days: 90, kind: "ticket", en: "Add DDoS protection", ar: "إضافة حماية من حجب الخدمة" },
  { days: 90, kind: "ticket", en: "Add a WAF", ar: "إضافة WAF" },
  { days: 90, kind: "gap", en: "Approve the cybersecurity policy", ar: "اعتماد سياسة الأمن السيبراني" },
]);
