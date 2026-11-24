"use strict";
// The only bridge between the pet page and the main process: receive state, ask for display actions. Nothing else.
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("buddy", {
  onState: (fn) => ipcRenderer.on("state", (_e, s) => fn(s)),
  openDashboard: () => ipcRenderer.send("open-dashboard"),
  dismiss: () => ipcRenderer.send("dismiss"),
  stopSession: () => ipcRenderer.send("stop-session"),
  toggleSize: () => ipcRenderer.send("toggle-size"),
});
