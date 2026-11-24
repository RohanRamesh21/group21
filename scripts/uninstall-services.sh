#!/bin/bash
for l in com.guardian.server com.guardian.buddy com.guardian.intel-refresh com.guardian.watchdog; do
  launchctl bootout "gui/$(id -u)/$l" 2>/dev/null || true; rm -f "$HOME/Library/LaunchAgents/$l.plist"; echo "removed $l"
done
