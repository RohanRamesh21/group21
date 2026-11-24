"use strict";
/* Guardian Buddy: main process.
 * Owns the connection to the Guardian server (snapshot → ordered server-sent events → resume with Last-Event-ID),
 * turns events into one Buddy state, and controls the windows. Buddy has no approval buttons; its only action on
 * Guardian is "Stop session" (stops a running scan, agent run or validation, never approves or fakes a result).
 * The renderer (pet.html) only draws the state it is given.
 */
const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, nativeImage, screen, shell } = require("electron");
const path = require("node:path");

const SERVER = process.env.GUARDIAN_URL || "http://127.0.0.1:8765";
const SIZES = { compact: { width: 150, height: 170 }, expanded: { width: 430, height: 280 } };
const MARGIN = 18;

let pet, dash, tray;
let state = { kind: "connecting", text: "Connecting to Guardian…" };
let lastSeq = 0;
let snoozeUntil = 0;
let lastEventAt = 0;
const currentByPr = new Map();   // "repo#pr" → newest run project (older runs of the same PR are ignored)
const notified = new Set();      // one notification per run verdict

// ------------------------------------------------------------------ windows
function anchor(size) {
  const wa = screen.getPrimaryDisplay().workArea;
  return { x: wa.x + wa.width - size.width - MARGIN, y: wa.y + wa.height - size.height - MARGIN, ...size };
}

function createPet() {
  pet = new BrowserWindow({
    ...anchor(SIZES.compact), frame: false, transparent: true, resizable: false, hasShadow: false, alwaysOnTop: true,
    skipTaskbar: true, fullscreenable: false, show: false, backgroundColor: "#00000000",
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  pet.setAlwaysOnTop(true, "floating");
  pet.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  // Diagnostics (written to the launchd log): load result, renderer crashes, console errors, and a self-snapshot.
  const wc = pet.webContents;
  wc.on("did-finish-load", () => console.log(`[buddy] pet page loaded; window ${JSON.stringify(pet.getBounds())}`));
  wc.on("did-fail-load", (_e, code, desc) => console.log(`[buddy] pet page FAILED to load: ${code} ${desc}`));
  wc.on("render-process-gone", (_e, d) => console.log(`[buddy] renderer gone: ${d.reason}`));
  wc.on("console-message", (e) => { const m = e.message ?? e; if ((e.level ?? 0) >= 2 || /error/i.test(String(m))) console.log(`[buddy] page console: ${m}`); });
  pet.loadFile(path.join(__dirname, "pet.html"));
  pet.once("ready-to-show", () => {
    pet.showInactive(); push();
    setTimeout(() => wc.executeJavaScript(`(() => { const r = document.getElementById("robot"), w = document.querySelector(".wrap"); const cs = getComputedStyle(r);
      return JSON.stringify({ kind: document.body.dataset.kind, win: [innerWidth, innerHeight], robot: r.getBoundingClientRect(), wrap: w.getBoundingClientRect(),
        display: cs.display, opacity: cs.opacity, visibility: cs.visibility, cols: getComputedStyle(w).gridTemplateColumns, sheets: document.styleSheets.length }); })()`)
      .then((d) => console.log(`[buddy] layout ${d}`)).catch((e) => console.log(`[buddy] layout check failed: ${e.message}`)), 2500);
    setTimeout(() => wc.capturePage().then((img) => {
      const out = path.join(app.getPath("home"), "Library", "Logs", "guardian", "buddy-snapshot.png");
      require("node:fs").writeFileSync(out, img.toPNG());
      console.log(`[buddy] self-snapshot ${img.getSize().width}x${img.getSize().height} -> ${out}; state ${state.kind}`);
    }).catch((err) => console.log(`[buddy] snapshot failed: ${err.message}`)), 3000);
  });
}

function setSize(name) {
  if (!pet || pet.isDestroyed()) return;
  const b = anchor(SIZES[name]);
  const cur = pet.getBounds();
  // keep the robot where the user dragged it: grow up/left from its current bottom-right corner
  const right = cur.x + cur.width, bottom = cur.y + cur.height;
  pet.setBounds({ x: right - b.width, y: bottom - b.height, width: b.width, height: b.height }, true);
}

function openDashboard(project, view = "summary", tour = true) {
  // Clicking the pet starts the guided flow from the beginning (Summary), with the tour bar for the presenter.
  const q = [project ? `run=${encodeURIComponent(project)}` : "", tour ? "tour=1" : ""].filter(Boolean).join("&");
  const url = `${SERVER}/${q ? `?${q}` : ""}#${tour ? "summary" : view}`;
  const wa = screen.getPrimaryDisplay().workArea;
  const target = { width: Math.min(1440, wa.width - 80), height: Math.min(920, wa.height - 60) };
  target.x = wa.x + Math.round((wa.width - target.width) / 2);
  target.y = wa.y + Math.round((wa.height - target.height) / 2);
  if (dash && !dash.isDestroyed()) {
    dash.loadURL(url);
    dash.show(); dash.focus();
    return;
  }
  const from = pet.getBounds();  // "enlarge the pet": the dashboard grows out of Buddy's position
  dash = new BrowserWindow({
    x: from.x, y: from.y, width: from.width, height: from.height, show: false, title: "Guardian",
    backgroundColor: "#0a0b0e", webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  dash.webContents.setWindowOpenHandler(({ url: u }) => { shell.openExternal(u); return { action: "deny" }; });
  dash.webContents.on("will-navigate", (e, u) => { if (!u.startsWith(SERVER)) { e.preventDefault(); shell.openExternal(u); } });
  dash.loadURL(url);
  dash.once("ready-to-show", () => { dash.show(); dash.setBounds(target, true); dash.focus(); });
  dash.on("closed", () => { dash = null; });
}

// ------------------------------------------------------------------ state
function push() {
  if (pet && !pet.isDestroyed()) pet.webContents.send("state", { ...state, snoozed: Date.now() < snoozeUntil });
  updateTray();
}

const LOUD = new Set(["scanning", "block", "review", "approval", "verified", "not_verified", "nightly"]);

function setState(next) {
  if (next.kind !== state.kind) console.log(`[buddy] state ${state.kind} -> ${next.kind}${next.pr ? ` (PR #${next.pr})` : ""}`);
  state = { ...next, at: Date.now() };
  const quiet = Date.now() < snoozeUntil && next.kind !== "block";  // snoozed: only red interrupts
  if (!quiet && LOUD.has(next.kind) || next.kind === "block") {
    setSize("expanded");
    if (pet && !pet.isVisible()) pet.showInactive();
  }
  if (["idle", "offline", "connecting"].includes(next.kind)) setSize("compact");
  push();
  if (next.kind === "block" && next.project && !notified.has(next.project) && Notification.isSupported()) {
    notified.add(next.project);
    const n = new Notification({ title: `Guardian blocked PR #${next.pr}`, body: (next.reasons && next.reasons[0]) || "A critical supply-chain risk was introduced." });
    n.on("click", () => openDashboard(next.project));
    n.show();
  }
}

function isCurrent(d) {
  if (!d || !d.repo || d.pr == null) return true;
  const key = `${d.repo}#${d.pr}`;
  return !currentByPr.has(key) || currentByPr.get(key) === d.project;
}

const AGENT_TEXT = {
  lead: "Lead is planning the cases", investigator: "Investigators are examining the evidence",
  verifier: "Verifier is challenging the claims", gatekeeper: "Gatekeeper is checking every AI sentence",
  fixer: "Fixer is explaining the computed fix", human: "Waiting for your decision",
};

function onEvent(kind, d) {
  lastEventAt = Date.now();
  const base = { pr: d.pr, title: d.title || state.title, project: d.project || state.project, repo: d.repo };
  switch (kind) {
    case "run_queued":
      if (d.repo && d.pr != null) currentByPr.set(`${d.repo}#${d.pr}`, d.project);
      return setState({ ...base, kind: "scanning", text: `PR #${d.pr} opened · scanning` });
    case "scan_finished": {
      if (!isCurrent(d)) return;
      const v = d.complete === false ? "incomplete" : d.verdict;
      const text = { block: "BLOCK · critical supply-chain risk", review: "REVIEW · needs a human look", allow: "Scan passed · safe to merge", incomplete: "Scan incomplete · not a clean result" }[v] || "Scan finished";
      return setState({ ...base, kind: v === "allow" ? "allow" : v || "incomplete", text, reasons: d.reasons || [] });
    }
    case "agents_started":
      if (!isCurrent(d)) return;
      return setState({ ...base, kind: "agents", agent: "lead", text: "4 agents are investigating", verdict: d.verdict });
    case "agent":
      if (!isCurrent(d) || state.kind !== "agents") return;
      return setState({ ...state, agent: d.agent, text: AGENT_TEXT[d.agent] || "Agents are working" });
    case "approval_needed":
      if (!isCurrent(d)) return;
      return setState({ ...base, kind: "approval", text: "Review the proposed fix", view: "fix" });
    case "decision_recorded":
      return setState({ ...base, kind: d.decision === "approve" ? "approved" : "rejected", text: d.decision === "approve" ? `Approved by ${d.approver} · validate next` : `Rejected by ${d.approver}`, view: "validate" });
    case "validation_started":
      return setState({ ...base, kind: "validating", text: "Validating the fix in an isolated container", view: "validate" });
    case "session_stopped":
      return setState({ ...base, kind: "stopped", text: `Session stopped (${(d.stopped || []).join(", ") || "nothing was running"})`, view: state.view });
    case "agents_finished":
      if (d.status === "cancelled" && isCurrent(d)) return setState({ ...base, kind: "stopped", text: "Agents stopped · no approval requested" });
      return;
    case "validation_finished":
      if (d.state === "cancelled") return setState({ ...base, kind: "stopped", text: "Validation stopped · no PR status posted", view: "validate" });
      return setState({ ...base, kind: d.state === "success" ? "verified" : d.state === "failure" ? "not_verified" : "incomplete", text: d.description || "Validation finished", view: "validate" });
    case "nightly_finished":
      if (d.newly_disclosed > 0) return setState({ ...base, kind: "nightly", text: `Nightly: ${d.newly_disclosed} newly disclosed advisories on main` });
      return;
    case "github_post":
      if (String(d.result).startsWith("post failed")) return setState({ ...state, warning: `GitHub ${d.what} not posted (check token permissions)` });
      return;
    default:
  }
}

// ------------------------------------------------------------------ connection: snapshot → SSE with resume
async function connect() {
  setState({ kind: "connecting", text: "Connecting to Guardian…" });
  for (;;) {
    try {
      if (!lastSeq) {
        const cur = await (await fetch(`${SERVER}/api/trigger/current`)).json();
        lastSeq = cur.last_seq || 0;
        const running = (cur.runs || []).filter((r) => r.status === "running" || r.status === "queued").pop();
        for (const r of cur.runs || []) currentByPr.set(`${r.repo}#${r.pr}`, `gh-${r.id}`);
        if (running) setState({ kind: "scanning", pr: running.pr, title: running.title, project: `gh-${running.id}`, repo: running.repo, text: `PR #${running.pr} · scanning` });
        else setState({ kind: "idle", text: "Watching pull requests" });
      } else if (["offline", "connecting"].includes(state.kind)) {
        setState({ kind: "idle", text: "Reconnected · watching pull requests" });
      }
      const res = await fetch(`${SERVER}/api/trigger/stream?since=${lastSeq}`, { headers: { "Last-Event-ID": String(lastSeq), Accept: "text/event-stream" } });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      lastEventAt = Date.now();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) throw new Error("stream ended");
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i); buf = buf.slice(i + 2);
          lastEventAt = Date.now();  // keep-alives count as liveness
          let id = null, ev = "message", data = "";
          for (const line of block.split("\n")) {
            if (line.startsWith("id:")) id = line.slice(3).trim();
            else if (line.startsWith("event:")) ev = line.slice(6).trim();
            else if (line.startsWith("data:")) data += line.slice(5).trim();
          }
          if (!data) continue;
          if (id && Number(id) <= lastSeq) continue;   // never replay an older event
          if (id) lastSeq = Number(id);
          try { onEvent(ev, JSON.parse(data).data || {}); } catch { /* malformed event: ignored */ }
        }
      }
    } catch {
      if (state.kind !== "offline") setState({ kind: "offline", text: "Guardian offline · last state may be stale" });
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}

// staleness watchdog: no data or keep-alive for 20 s → grey, never the old green
setInterval(() => { if (lastEventAt && Date.now() - lastEventAt > 20000 && state.kind !== "offline") setState({ kind: "offline", text: "No signal from Guardian · stale" }); }, 5000);

// ------------------------------------------------------------------ tray
function updateTray() {
  if (!tray) return;
  tray.setToolTip(`Guardian Buddy · ${state.text || state.kind}`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: state.text || state.kind, enabled: false },
    { type: "separator" },
    { label: "Open dashboard", click: () => openDashboard(state.project, state.view) },
    { label: "Stop current session", enabled: RUNNING.has(state.kind), click: () => stopSession() },
    { label: pet && pet.isVisible() ? "Hide Buddy" : "Show Buddy", click: () => { if (pet.isVisible()) pet.hide(); else pet.showInactive(); updateTray(); } },
    { label: Date.now() < snoozeUntil ? "Unsnooze" : "Snooze 1 hour (only red interrupts)", click: () => { snoozeUntil = Date.now() < snoozeUntil ? 0 : Date.now() + 3600e3; push(); } },
    { type: "separator" },
    { label: "Quit Buddy", role: "quit" },
  ]));
}

// ------------------------------------------------------------------ stop session
const RUNNING = new Set(["scanning", "agents", "validating"]);
async function stopSession() {
  if (!state.project) return setState({ ...state, kind: "idle", text: "Watching pull requests", warning: null });
  try {
    const res = await fetch(`${SERVER}/api/session/stop`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project: state.project }) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    console.log(`[buddy] stop session ${state.project}: ${(body.stopped || []).join(", ") || "nothing running"}`);
    setState({ ...state, kind: "stopped", text: body.stopped && body.stopped.length ? `Session stopped (${body.stopped.join(", ")})` : "Nothing was running · session closed", warning: null });
  } catch (e) {
    setState({ ...state, warning: `Could not stop: ${String(e.message || e).slice(0, 80)}` });
  }
}

// ------------------------------------------------------------------ IPC from the renderer
ipcMain.on("open-dashboard", () => openDashboard(state.project, state.view));
ipcMain.on("dismiss", () => setState({ ...state, kind: "idle", text: "Watching pull requests", warning: null }));
ipcMain.on("stop-session", () => { stopSession(); });
ipcMain.on("toggle-size", () => { const b = pet.getBounds(); setSize(b.width > SIZES.compact.width ? "compact" : "expanded"); });

app.whenReady().then(() => {
  if (process.platform === "darwin") app.dock.hide();
  tray = new Tray(nativeImage.createEmpty());
  tray.setTitle("🛡 Guardian");
  createPet();
  updateTray();
  connect();
});
app.on("window-all-closed", (e) => e.preventDefault());
