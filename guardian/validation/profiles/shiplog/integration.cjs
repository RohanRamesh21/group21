// Guardian integration check for ShipLog: start the real server and exercise its HTTP API.
// Prints one JSON line {"ok": bool, "steps": [...]} and exits 0 only if every step succeeded.
const { spawn } = require("child_process");

const PORT = 3311;
const BASE = `http://127.0.0.1:${PORT}`;
const steps = [];
const record = (step, ok, detail) => steps.push({ step, ok, detail: String(detail ?? "").slice(0, 300) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const server = spawn(process.execPath, ["src/server.js"], { env: { ...process.env, PORT: String(PORT), LOG_LEVEL: "warn" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  server.stdout.on("data", (d) => { log += d; });
  server.stderr.on("data", (d) => { log += d; });
  try {
    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
      try { up = (await fetch(`${BASE}/health`)).ok; } catch { await sleep(250); }
    }
    record("server starts", up, up ? "health ok" : log.slice(-200));
    if (!up) throw new Error("server did not start");
    const health = await (await fetch(`${BASE}/health`)).json();
    record("health", health.status === "ok" && health.pipelines > 0, JSON.stringify(health));
    const list = await (await fetch(`${BASE}/api/pipelines`)).json();
    record("list pipelines", Array.isArray(list.items) && list.count === list.items.length, `${list.count} pipelines`);
    const created = await fetch(`${BASE}/api/pipelines/web/runs`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "passed", durationSec: 200, commit: "abc1234", triggeredBy: "guardian" }) });
    record("record a run", created.status === 201, `HTTP ${created.status}`);
    const bad = await fetch(`${BASE}/api/pipelines/web/runs`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{\"status\":\"nope\"}" });
    record("reject invalid input", bad.status === 400, `HTTP ${bad.status}`);
  } catch (e) {
    record("error", false, e.message);
  } finally {
    server.kill("SIGTERM");
  }
  const ok = steps.every((s) => s.ok);
  console.log(JSON.stringify({ ok, steps }));
  process.exit(ok ? 0 : 1);
})();
