import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

test("the pinned Lucide helper returns inline SVGs with the approved stroke", async () => {
  delete globalThis.irisIcon;
  await import(`${pathToFileURL(path.join(HERE, "icons.js")).href}?t=${Date.now()}`);

  const svg = globalThis.irisIcon("shield-check", "proof");
  assert.match(svg, /^<svg/);
  assert.match(svg, /stroke-width="1\.75"/);
  assert.match(svg, /class="iris-icon proof"/);
  assert.doesNotMatch(svg, /<img|https?:\/\//);
});

test("unknown icon names fail loudly", async () => {
  if (!globalThis.irisIcon) await import(`${pathToFileURL(path.join(HERE, "icons.js")).href}?t=${Date.now()}`);
  assert.throws(() => globalThis.irisIcon("not-an-icon"), /Unknown Iris icon/);
});
