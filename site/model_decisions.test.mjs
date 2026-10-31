import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

test("the public counters include only parse and choose decisions", async () => {
  delete globalThis.isAiDecision;
  await import(`${pathToFileURL(path.join(HERE, "model_decisions.js")).href}?t=${Date.now()}`);

  assert.equal(globalThis.isAiDecision({ role: "parse", model: "qwen3:8b" }), true);
  assert.equal(globalThis.isAiDecision({ role: "choose", model: "qwen3:8b" }), true);
  assert.equal(globalThis.isAiDecision({ role: "explain", model: "qwen3:8b" }), false);
  assert.equal(globalThis.isAiDecision({ role: "choose" }), true);
  assert.equal(globalThis.isAiDecision({ role: "explain" }), false);
});
