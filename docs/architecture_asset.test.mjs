import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("the shared Iris architecture asset stays public, simple, and judge-readable", async () => {
  const [readme, html, svg] = await Promise.all([
    fs.readFile(new URL("../README.md", import.meta.url), "utf8"),
    fs.readFile(new URL("./img/iris-architecture.html", import.meta.url), "utf8"),
    fs.readFile(new URL("./img/iris-architecture.svg", import.meta.url), "utf8"),
  ]);

  assert.match(readme, /docs\/img\/iris-architecture\.svg/);
  for (const copy of [html, svg]) {
    assert.match(copy, /Business owner/);
    assert.match(copy, /Iris agent/);
    assert.match(copy, /Iris scanner/);
    assert.match(copy, /The business's[\s\S]*systems/);
    assert.match(copy, /answers, approvals/);
    assert.match(copy, /verified facts only/);
    assert.match(copy, /scan, fix, re-scan/);
    assert.match(copy, /Action gate/);
    assert.match(copy, /Typed boundary/);
    assert.match(copy, /Audit log/);
    assert.match(copy, /Qwen3 8B/);
    assert.match(copy, /ALLaM · Gemma · GPT-OSS/);
    assert.doesNotMatch(copy, /Oracle|Jeddah|SSH|Docker bridge|CoreDNS|decoy|lab domain|published ports|Vercel/i);
  }
});
