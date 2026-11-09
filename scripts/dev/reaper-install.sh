#!/bin/bash
# Install (or remove with --uninstall) the orphan reaper so it runs every 10 minutes.
# macOS: a launchd user agent. Linux (incl. WSL2 with systemd): a systemd user timer.
# Idempotent: re-running replaces the installed copy and reloads the job.
set -euo pipefail

label=com.knt048.vedette.orphan-reaper
src="$(cd "$(dirname "$0")" && pwd)/orphan-reaper.sh"
mode=${1:-install}

case "$(uname)" in
Darwin)
	dir="$HOME/Library/Application Support/Vedette"
	plist="$HOME/Library/LaunchAgents/$label.plist"
	launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
	if [ "$mode" = "--uninstall" ]; then
		rm -f "$plist" "$dir/orphan-reaper.sh"
		echo "orphan reaper removed"
		exit 0
	fi
	mkdir -p "$dir" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
	install -m 0755 "$src" "$dir/orphan-reaper.sh"
	cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$label</string>
	<key>ProgramArguments</key>
	<array><string>/bin/bash</string><string>$dir/orphan-reaper.sh</string></array>
	<key>StartInterval</key><integer>600</integer>
	<key>RunAtLoad</key><true/>
	<key>LowPriorityIO</key><true/>
	<key>Nice</key><integer>10</integer>
	<key>StandardErrorPath</key><string>$HOME/Library/Logs/vedette-orphan-reaper.err</string>
</dict>
</plist>
EOF
	launchctl bootstrap "gui/$(id -u)" "$plist"
	launchctl print "gui/$(id -u)/$label" >/dev/null # effect check: the job is loaded
	echo "orphan reaper installed: every 10 min, log ~/Library/Logs/vedette-orphan-reaper.log"
	;;
Linux)
	unit="$HOME/.config/systemd/user"
	bin="$HOME/.local/bin/vedette-orphan-reaper"
	if ! systemctl --user show-environment >/dev/null 2>&1; then
		echo "orphan reaper: systemd user session not available (WSL2: enable systemd in /etc/wsl.conf); not installed" >&2
		exit 1
	fi
	systemctl --user disable --now vedette-orphan-reaper.timer 2>/dev/null || true
	if [ "$mode" = "--uninstall" ]; then
		rm -f "$unit/vedette-orphan-reaper.service" "$unit/vedette-orphan-reaper.timer" "$bin"
		systemctl --user daemon-reload
		echo "orphan reaper removed"
		exit 0
	fi
	mkdir -p "$unit" "$(dirname "$bin")"
	install -m 0755 "$src" "$bin"
	printf '[Unit]\nDescription=Vedette orphan reaper\n\n[Service]\nType=oneshot\nNice=10\nExecStart=%s\n' "$bin" >"$unit/vedette-orphan-reaper.service"
	printf '[Unit]\nDescription=Run the Vedette orphan reaper every 10 minutes\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=10min\n\n[Install]\nWantedBy=timers.target\n' >"$unit/vedette-orphan-reaper.timer"
	systemctl --user daemon-reload
	systemctl --user enable --now vedette-orphan-reaper.timer
	systemctl --user is-active --quiet vedette-orphan-reaper.timer # effect check
	echo "orphan reaper installed: every 10 min, log ~/.local/state/vedette-orphan-reaper.log"
	;;
*)
	echo "orphan reaper: only macOS and Linux are supported" >&2
	exit 1
	;;
esac
