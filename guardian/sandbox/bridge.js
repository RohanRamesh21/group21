// Runs INSIDE a sandbox container that has no network (--network=none).
// Exposes the host's egress allow-list proxy (a Unix socket mounted at $GSBX_SOCK) as 127.0.0.1:3128,
// then runs the real command with that address as its HTTPS proxy and exits with the command's code.
// Usage: node /gsbx/bridge.js <command> [args...]
"use strict";
const net = require("net");
const { spawn } = require("child_process");

const server = net.createServer((client) => {
  const upstream = net.connect(process.env.GSBX_SOCK);
  client.pipe(upstream);
  upstream.pipe(client);
  client.on("error", () => upstream.destroy());
  upstream.on("error", () => client.destroy());
});

server.listen(3128, "127.0.0.1", () => {
  const [cmd, ...args] = process.argv.slice(2);
  const child = spawn(cmd, args, { stdio: "inherit" });
  child.on("exit", (code, signal) => process.exit(code ?? (signal ? 128 : 1)));
  child.on("error", (e) => { console.error(`bridge: ${e.message}`); process.exit(127); });
});
