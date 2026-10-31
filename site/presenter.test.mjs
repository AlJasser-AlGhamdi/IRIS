import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

test("presenter story has the nine approved screens and exact evidence", async () => {
  const moduleUrl = `${pathToFileURL(path.join(HERE, "story_data.js")).href}?t=${Date.now()}`;
  const { FEATURED_FACTS, STORY_CASE, STORY_SCREENS } = await import(moduleUrl);
  assert.deepEqual(STORY_SCREENS.map((screen) => screen.id), [
    "problem", "loop", "automation", "ai", "live", "outputs", "results", "value", "close",
  ]);
  assert.deepEqual(STORY_SCREENS.map((screen) => screen.group), [
    "input", "input", "ai", "ai", "ai", "output", "value", "value", "none",
  ]);
  assert.deepEqual(FEATURED_FACTS, {
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
  assert.deepEqual(STORY_CASE, {
    replyAr: "إيه، الإيميل محمي، مزود البريد مسوي كل شي",
    replyEn: "Yes, the email is protected.",
    answer: "yes",
    findings: "SPF and DMARC missing",
    result: "Both fixed and proven by re-scan",
  });
});

test("presenter mode is wired without changing the standard replay", async () => {
  const [html, presenter, css, app, chapters] = await Promise.all([
    fs.readFile(path.join(HERE, "index.html"), "utf8"),
    fs.readFile(path.join(HERE, "presenter.js"), "utf8"),
    fs.readFile(path.join(HERE, "presenter.css"), "utf8"),
    fs.readFile(path.join(HERE, "app.js"), "utf8"),
    fs.readFile(path.join(HERE, "chapters.json"), "utf8").then(JSON.parse),
  ]);
  assert.match(html, /href="presenter\.css\?v=\d+"/);
  assert.match(html, /type="module" src="presenter\.js\?v=\d+"/);
  assert.match(presenter, /params\.get\("present"\)\s*!==\s*"1"/);
  assert.match(presenter, /ArrowRight|PageDown/);
  assert.match(presenter, /ArrowLeft|PageUp/);
  assert.match(presenter, /key\.toLowerCase\(\)\s*===\s*"o"/);
  assert.match(css, /\.story-overlay/);
  assert.match(css, /body\.story-live/);
  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(app, /fetch\("translations_en\.json"\)/);
  assert.match(app, /owner_replies/);
  assert.match(app, /class="original-reply"/);
  assert.match(app, /reply as typed/i);
  assert.match(html, /option value="9">9×/);
  assert.match(app, /9:\s*"9"/);
  assert.match(app, /SPF and DMARC missing, so the scan wins/);
  assert.deepEqual(Object.fromEntries(chapters.map((chapter) => [chapter.key, chapter.at])), {
    scope: 1, ownership: 5, scan: 10, interview: 30, contradiction: 163,
    fix: 181, documents: 202, monitor: 257, results: 269,
  });
});

test("public build copies both report languages and exact evaluation keys", async () => {
  const build = await fs.readFile(path.join(ROOT, "scripts", "build_site.py"), "utf8");
  for (const key of [
    "e1-held_out-ollama_qwen3_8b",
    "e6-held_out-ollama_qwen3_8b",
    "e4",
    "e7-ollama_qwen3_8b",
    "ablations-ollama_qwen3_8b",
  ]) assert.match(build, new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(build, /\.report\.en\.html/);
  assert.match(build, /results\.json/);
});

test("static replay probes live mode without a console 404", async () => {
  const [ping, app] = await Promise.all([
    fs.readFile(path.join(HERE, "api", "ping"), "utf8"),
    fs.readFile(path.join(HERE, "app.js"), "utf8"),
  ]);
  assert.deepEqual(JSON.parse(ping), { ok: false });
  assert.match(app, /\.json\(\).*\.ok/);
});
