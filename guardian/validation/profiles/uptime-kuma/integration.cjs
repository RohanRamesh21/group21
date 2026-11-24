// Guardian integration check for Uptime Kuma: real application operations over the app's own socket.io API.
// Prints one JSON line {"ok": bool, "steps": [...]} and exits 0 only if every step succeeded.
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { io } = require(path.join(process.cwd(), "node_modules", "socket.io-client"));

const PORT = 3301;
const URL = `http://127.0.0.1:${PORT}`;
const steps = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const record = (step, ok, detail) => steps.push({ step, ok, detail: String(detail ?? "").slice(0, 300) });

function emit(socket, event, ...args) {
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`${event}: no answer in 20s`)), 20000);
        socket.emit(event, ...args, (res) => { clearTimeout(t); resolve(res); });
    });
}

(async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-data-"));
    const server = spawn(process.execPath, ["server/server.js", `--data-dir=${dataDir}`, `--port=${PORT}`, "--host=127.0.0.1"],
        { env: { ...process.env, UPTIME_KUMA_DB_TYPE: "sqlite" }, stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    server.stdout.on("data", (d) => { log += d; });
    server.stderr.on("data", (d) => { log += d; });
    let socket;
    try {
        let up = false;
        for (let i = 0; i < 90 && !up; i++) {
            try { const r = await fetch(`${URL}/api/entry-page`); up = r.ok; if (up) record("server_started", true, `entry-page ${r.status} ${JSON.stringify(await r.json())}`); } catch { /* not yet */ }
            if (!up) await sleep(1000);
        }
        if (!up) throw new Error("server did not answer /api/entry-page within 90s");

        socket = io(URL, { transports: ["websocket"], reconnection: false });
        await new Promise((res, rej) => { socket.once("connect", res); socket.once("connect_error", rej); });
        const user = "guardian-check";
        const pass = "Gk-" + Math.random().toString(36).slice(2) + "-Z9q";
        let r = await emit(socket, "setup", user, pass);
        record("setup_admin_user", !!r.ok, r.msg);
        if (!r.ok) throw new Error(`setup failed: ${r.msg}`);
        r = await emit(socket, "login", { username: user, password: pass, token: "" });
        record("login", !!r.ok, r.msg);
        if (!r.ok) throw new Error(`login failed: ${r.msg}`);

        const heartbeat = new Promise((res, rej) => {
            const t = setTimeout(() => rej(new Error("no heartbeat within 90s")), 90000);
            socket.on("heartbeat", (hb) => { clearTimeout(t); res(hb); });
        });
        r = await emit(socket, "add", {
            type: "http", name: "guardian-self-check", url: `${URL}/api/entry-page`, method: "GET", interval: 20,
            retryInterval: 20, resendInterval: 0, maxretries: 0, timeout: 16, accepted_statuscodes: ["200-299"],
            notificationIDList: {}, ignoreTls: false, upsideDown: false, maxredirects: 10, expiryNotification: false,
            kafkaProducerBrokers: [], kafkaProducerSaslOptions: { mechanism: "None" }, kafkaProducerSsl: false,
            kafkaProducerAllowAutoTopicCreation: false, conditions: [], rabbitmqNodes: [], httpBodyEncoding: "json",
        });
        record("add_monitor", !!r.ok, r.msg || `monitorID ${r.monitorID}`);
        if (!r.ok) throw new Error(`add monitor failed: ${r.msg}`);
        const hb = await heartbeat;
        const ok = hb.status === 1;
        record("heartbeat_stored", ok, `monitor ${hb.monitorID} status ${hb.status} ${hb.msg || ""}`);
        if (!ok) throw new Error(`monitor reported status ${hb.status}`);
        console.log(JSON.stringify({ ok: true, steps }));
    } catch (e) {
        record("error", false, e.message);
        console.log(JSON.stringify({ ok: false, steps, server_log_tail: log.slice(-1500) }));
        process.exitCode = 1;
    } finally {
        if (socket) socket.close();
        server.kill("SIGTERM");
        await sleep(500);
        fs.rmSync(dataDir, { recursive: true, force: true });
    }
})();
