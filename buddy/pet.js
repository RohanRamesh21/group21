"use strict";
const $ = (id) => document.getElementById(id);
let last = null;

window.buddy.onState((s) => {
  const changed = !last || last.kind !== s.kind || last.project !== s.project;
  document.body.dataset.kind = s.kind;
  document.body.dataset.agent = s.agent || "";
  document.body.classList.toggle("snoozed", !!s.snoozed);
  $("pr").textContent = s.pr ? `PR #${s.pr}` : "Guardian";
  $("title").textContent = s.title ? ` · ${s.title}` : "";        // untrusted text: textContent only
  $("text").textContent = s.text || "";
  $("agent").textContent = s.kind === "agents" && s.agent ? `● ${s.agent}` : "";
  $("warning").textContent = s.warning || "";
  const ul = $("reasons");
  ul.replaceChildren(...(s.kind === "block" || s.kind === "review" ? (s.reasons || []).slice(0, 2) : []).map((r) => {
    const li = document.createElement("li"); li.textContent = r; return li;
  }));
  $("open").hidden = !s.project && !["idle"].includes(s.kind);
  $("stop").hidden = !["scanning", "agents", "validating"].includes(s.kind);
  if ($("stop").hidden) resetStop();
  if (changed) {  // a new situation pops: replay the entrance animation
    document.body.classList.remove("pop"); void document.body.offsetWidth; document.body.classList.add("pop");
  }
  last = s;
});

$("open").addEventListener("click", () => window.buddy.openDashboard());
// Stop needs two clicks (the first only arms it for 3 s), so a stray click never stops a live scan.
let armed = null;
function resetStop() { clearTimeout(armed); armed = null; $("stop").textContent = "Stop session"; $("stop").classList.remove("armed"); }
$("stop").addEventListener("click", () => {
  if (!armed) { $("stop").textContent = "Click again to stop"; $("stop").classList.add("armed"); armed = setTimeout(resetStop, 3000); return; }
  resetStop(); $("stop").hidden = true; window.buddy.stopSession();
});
$("dismiss").addEventListener("click", () => window.buddy.dismiss());
$("robot").addEventListener("dblclick", () => window.buddy.toggleSize());
$("robot").addEventListener("click", () => { if (document.body.dataset.kind !== "offline") window.buddy.openDashboard(); });
