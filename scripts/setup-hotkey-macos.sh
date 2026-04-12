#!/usr/bin/env bash
# setup-hotkey-macos.sh — Set up a keyboard shortcut for `picrypt panic` on macOS.
#
# Creates an Automator Quick Action (workflow) at ~/Library/Services/ that runs
# `picrypt panic`. The user then assigns a keyboard shortcut to it via System
# Settings.
#
# Does NOT require sudo. Safe to run multiple times (idempotent).

set -euo pipefail

readonly SERVICE_NAME="PicryptPanicLock"
readonly WORKFLOW_DIR="${HOME}/Library/Services/${SERVICE_NAME}.workflow"
readonly CONTENTS_DIR="${WORKFLOW_DIR}/Contents"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

log_info()  { printf "[INFO]  %s\n" "$*"; }
log_warn()  { printf "[WARN]  %s\n" "$*" >&2; }
log_error() { printf "[ERROR] %s\n" "$*" >&2; }
log_ok()    { printf "[OK]    %s\n" "$*"; }

die() {
    log_error "$@"
    exit 1
}

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #

if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This script is for macOS only. Detected: $(uname -s)"
fi

# --------------------------------------------------------------------------- #
# 1. Locate the picrypt binary
# --------------------------------------------------------------------------- #

log_info "Locating picrypt binary..."

PICRYPT_BIN=""

# Check common locations in priority order.
if command -v picrypt &>/dev/null; then
    PICRYPT_BIN="$(command -v picrypt)"
elif [[ -x "${HOME}/.cargo/bin/picrypt" ]]; then
    PICRYPT_BIN="${HOME}/.cargo/bin/picrypt"
elif [[ -x "/usr/local/bin/picrypt" ]]; then
    PICRYPT_BIN="/usr/local/bin/picrypt"
elif [[ -x "/opt/homebrew/bin/picrypt" ]]; then
    PICRYPT_BIN="/opt/homebrew/bin/picrypt"
fi

if [[ -z "${PICRYPT_BIN}" ]]; then
    log_warn "picrypt binary not found in PATH or common locations."
    log_warn "The workflow will use 'picrypt' and rely on PATH resolution at runtime."
    log_warn "If picrypt is installed later, re-run this script or edit the workflow."
    PICRYPT_BIN="picrypt"
else
    # Resolve symlinks to get the canonical path.
    PICRYPT_BIN="$(readlink -f "${PICRYPT_BIN}" 2>/dev/null || echo "${PICRYPT_BIN}")"
    log_ok "Found picrypt at: ${PICRYPT_BIN}"
fi

# --------------------------------------------------------------------------- #
# 2. Create the Automator Quick Action workflow
# --------------------------------------------------------------------------- #

log_info "Creating Automator Quick Action at ${WORKFLOW_DIR}..."

# Remove existing workflow if present (idempotent).
if [[ -d "${WORKFLOW_DIR}" ]]; then
    log_info "Removing existing workflow..."
    rm -rf "${WORKFLOW_DIR}"
fi

mkdir -p "${CONTENTS_DIR}"

# The workflow document.wflow is a plist that defines the Automator actions.
# This Quick Action receives "no input" in "any application" and runs a shell script.
cat > "${CONTENTS_DIR}/document.wflow" << 'PLIST_HEADER'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>523</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMLargeIconFile</key>
				<string>Execute_Shellscript</string>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
PLIST_HEADER

# Insert the actual command with the resolved binary path.
# We need to set up PATH since Automator runs with a minimal environment.
cat >> "${CONTENTS_DIR}/document.wflow" << PLIST_COMMAND
					<string>export PATH="/usr/local/bin:/opt/homebrew/bin:\$HOME/.cargo/bin:\$PATH"
${PICRYPT_BIN} panic 2&gt;&amp;1 || /usr/bin/osascript -e 'display notification "picrypt panic FAILED" with title "Picrypt"'
/usr/bin/osascript -e 'display notification "Panic lock sent to all devices" with title "Picrypt"'</string>
PLIST_COMMAND

cat >> "${CONTENTS_DIR}/document.wflow" << 'PLIST_FOOTER'
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>0</integer>
					<key>shell</key>
					<string>/bin/bash</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>00000000-0000-0000-0000-000000000000</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
					<string>Command</string>
					<string>Run</string>
				</array>
				<key>OutputUUID</key>
				<string>00000000-0000-0000-0000-000000000001</string>
				<key>UUID</key>
				<string>00000000-0000-0000-0000-000000000002</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>conversionLabel</key>
				<integer>0</integer>
				<key>is498</key>
				<true/>
				<key>is498b</key>
				<true/>
				<key>noter</key>
				<integer>0</integer>
				<key>now498</key>
				<true/>
			</dict>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
PLIST_FOOTER

log_ok "Workflow created at ${WORKFLOW_DIR}"

# --------------------------------------------------------------------------- #
# 3. Create the Info.plist (marks this as a Quick Action / Service)
# --------------------------------------------------------------------------- #

cat > "${CONTENTS_DIR}/Info.plist" << 'INFO_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>PicryptPanicLock</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
		</dict>
	</array>
</dict>
</plist>
INFO_PLIST

log_ok "Info.plist created."

# --------------------------------------------------------------------------- #
# 4. Print shortcut assignment instructions
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Keyboard Shortcut Assignment ==="
echo ""
echo "The Quick Action '${SERVICE_NAME}' has been installed."
echo "To assign a keyboard shortcut (recommended: Ctrl+Shift+L):"
echo ""
echo "  macOS Ventura and later (System Settings):"
echo "    1. Open System Settings"
echo "    2. Go to Keyboard > Keyboard Shortcuts > Services (or 'App Shortcuts')"
echo "    3. Scroll down to 'General' in the Services list"
echo "    4. Find '${SERVICE_NAME}' and click 'Add Shortcut'"
echo "    5. Press Control + Shift + L"
echo ""
echo "  macOS Monterey and earlier (System Preferences):"
echo "    1. Open System Preferences > Keyboard > Shortcuts"
echo "    2. Select 'Services' in the left panel"
echo "    3. Find '${SERVICE_NAME}' under 'General'"
echo "    4. Click 'Add Shortcut' and press Control + Shift + L"
echo ""

# --------------------------------------------------------------------------- #
# 5. Attempt to set the shortcut programmatically via defaults
# --------------------------------------------------------------------------- #

# macOS stores service shortcuts in NSServicesStatus within the global domain.
# We can try to set it, but it may not take effect until logout/restart.

log_info "Attempting to set keyboard shortcut programmatically..."

# Try setting via defaults -- this sets the shortcut for the Quick Action.
# Service shortcut format: ^ = Control, $ = Shift. So "^$l" = Ctrl+Shift+L.
if defaults write pbs NSServicesStatus -dict-add \
    "\"(null) - ${SERVICE_NAME} - runWorkflowAsService\"" \
    '{ "key_equivalent" = "^$l"; "enabled" = 1; }' 2>/dev/null; then
    log_ok "Shortcut preference written. You may need to log out and back in for it to take effect."
else
    log_warn "Could not set shortcut programmatically. Please set it manually using the instructions above."
fi

# Refresh services (may or may not work depending on macOS version).
/System/Library/CoreServices/pbs -flush 2>/dev/null || true

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
log_info "=== macOS Hotkey Setup Summary ==="
log_info "  Quick Action: ~/Library/Services/${SERVICE_NAME}.workflow"
log_info "  Command:      ${PICRYPT_BIN} panic"
log_info "  Shortcut:     Ctrl+Shift+L (assign manually if not auto-configured)"
echo ""
log_info "Test the Quick Action:"
log_info "  1. Open any app"
log_info "  2. Go to the app's menu bar > Services > ${SERVICE_NAME}"
log_info "  3. Or press your assigned keyboard shortcut"
echo ""
log_info "To remove: rm -rf '${WORKFLOW_DIR}'"
