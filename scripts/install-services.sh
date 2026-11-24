#!/bin/bash
# Install Guardian's always-on services and scheduled jobs as macOS LaunchAgents (current user, no sudo):
#   com.guardian.server         Guardian API + dashboard on 127.0.0.1:8765 (kept alive; the runner and Buddy talk to it)
#   com.guardian.buddy          Guardian Buddy desktop companion (kept alive)
#   com.guardian.intel-refresh  daily 02:00 advisory data refresh
#   com.guardian.watchdog       every 10 min: submit open PRs the runner missed
set -euo pipefail
G="$(cd "$(dirname "$0")/.." && pwd)"
REPOS="${GUARDIAN_DEMO_REPOS:-kirankishoreV-07/PIPELINE_CHECK kirankishoreV-07/uptime-kuma}"
LA="$HOME/Library/LaunchAgents"; LOG="$HOME/Library/Logs/guardian"; mkdir -p "$LA" "$LOG"

plist() {  # label, program args (xml), extra keys (xml)
  cat > "$LA/$1.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array>$2</array>
  <key>WorkingDirectory</key><string>$G</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string></dict>
  <key>StandardOutPath</key><string>$LOG/$1.log</string>
  <key>StandardErrorPath</key><string>$LOG/$1.log</string>
  $3
</dict></plist>
PL
  launchctl bootout "gui/$(id -u)/$1" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do launchctl print "gui/$(id -u)/$1" >/dev/null 2>&1 || break; sleep 0.5; done  # wait for unload
  launchctl bootstrap "gui/$(id -u)" "$LA/$1.plist"
  echo "installed $1"
}
s() { printf '<string>%s</string>' "$@"; }

plist com.guardian.server "$(s "$G/.venv/bin/uvicorn" guardian.server:app --host 127.0.0.1 --port 8765)" \
  "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>"
plist com.guardian.buddy "$(s "$G/buddy/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron" "$G/buddy")" \
  "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>LimitLoadToSessionType</key><string>Aqua</string>"
plist com.guardian.intel-refresh "$(s "$G/.venv/bin/python" -m guardian.scoring.intel_refresh)" \
  "<key>StartCalendarInterval</key><dict><key>Hour</key><integer>2</integer><key>Minute</key><integer>0</integer></dict>"
WD=(); for r in $REPOS; do WD+=(--repo "$r"); done
plist com.guardian.watchdog "$(s "$G/.venv/bin/python" -m guardian.trigger.watchdog "${WD[@]}")" \
  "<key>StartInterval</key><integer>600</integer>"
