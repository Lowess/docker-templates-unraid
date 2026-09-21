#!/bin/sh

run_uid="${PUID:-99}"
run_gid="${PGID:-100}"
settings_file="/data/.livesync/settings.json"
bootstrap_pending="/data/.livesync/unraid-bootstrap-pending"
bootstrap_complete="/data/.livesync/unraid-bootstrap-v1"

run_as_user() {
	setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups "$@"
}

idle_forever() {
	exec setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups /bin/sh -c \
		'trap exit TERM INT; while :; do sleep 3600 & wait $!; done'
}

is_true() {
	case "${1:-}" in
		1 | true | TRUE | yes | YES | on | ON) return 0 ;;
		*) return 1 ;;
	esac
}

is_configured() {
	[ -s "$settings_file" ] && grep -Eq '"isConfigured"[[:space:]]*:[[:space:]]*true' "$settings_file"
}

normalise_settings() {
	run_as_user node -e '
const fs = require("fs");
const path = "/data/.livesync/settings.json";

try {
    const settings = JSON.parse(fs.readFileSync(path, "utf8"));
    let changed = false;
    const rawSuffix = process.env.LOCAL_DATABASE_SUFFIX || "unraid-cli";
    const suffix = rawSuffix.replace(/[^A-Za-z0-9._-]/g, "") || "unraid-cli";

    if (settings.additionalSuffixOfDatabaseName !== suffix) {
        settings.additionalSuffixOfDatabaseName = suffix;
        changed = true;
        console.log(`[Bootstrap] Local database suffix: ${suffix}`);
    }

    const enableLive = !/^(0|false|no|off)$/i.test(process.env.ENABLE_LIVE_SYNC || "true");
    if (enableLive && (settings.liveSync !== true || settings.syncOnStart !== true || settings.syncOnSave !== true)) {
        settings.liveSync = true;
        settings.syncOnStart = true;
        settings.syncOnSave = true;
        changed = true;
        console.log("[Bootstrap] Continuous and save-triggered replication enabled");
    }

    if (changed) {
        const temporaryPath = `${path}.tmp`;
        fs.writeFileSync(temporaryPath, JSON.stringify(settings, null, 2));
        fs.renameSync(temporaryPath, path);
    }
} catch (error) {
    console.error(`[Bootstrap] Could not prepare CLI settings: ${error.message}`);
    process.exit(1);
}
'
}

umask "${UMASK:-002}"
mkdir -p /data/.livesync
chown "$run_uid:$run_gid" /data /data/.livesync
if [ -f "$settings_file" ]; then
	chown "$run_uid:$run_gid" "$settings_file"
fi

if ! run_as_user test -w /vault; then
	echo "[Bootstrap] The vault at /vault is not writable by PUID $run_uid and PGID $run_gid."
	echo "[Bootstrap] Correct the host-directory permissions, then restart this container."
	idle_forever
fi

if ! is_configured; then
	if [ -z "${SETUP_URI:-}" ] || [ -z "${SETUP_PASSPHRASE:-}" ]; then
		echo "[Bootstrap] Waiting for first-time configuration."
		echo "[Bootstrap] Edit this container and fill in Setup URI and Setup URI Passphrase, then restart it."
		idle_forever
	fi

	echo "[Bootstrap] Importing the supplied Setup URI..."
	if ! printf '%s\n' "$SETUP_PASSPHRASE" | run_as_user /usr/local/bin/livesync-cli setup "$SETUP_URI"; then
		echo "[Bootstrap] Setup URI import failed. Check the URI and passphrase in the template."
		idle_forever
	fi
	run_as_user touch "$bootstrap_pending"
	echo "[Bootstrap] Setup URI imported successfully."
	echo "[Bootstrap] Clear the Setup URI and passphrase fields after this bootstrap completes."
fi

unset SETUP_URI SETUP_PASSPHRASE

if ! normalise_settings; then
	idle_forever
fi

if [ -f "$bootstrap_pending" ] && is_true "${AUTO_INITIAL_SYNC:-true}"; then
	if [ -f /vault/.livesync-snapshot.json ]; then
		echo "[Bootstrap] Ignoring LiveSync CLI snapshot metadata while checking the destination vault."
	fi
	first_vault_entry=$(find /vault -mindepth 1 -maxdepth 1 ! -name '.livesync-snapshot.json' -print -quit 2>/dev/null)
	if [ -n "$first_vault_entry" ]; then
		echo "[Bootstrap] Automatic initial sync stopped because /vault is not empty: $first_vault_entry"
		echo "[Bootstrap] Use an empty destination vault, or disable Automatic Initial Sync and manage the merge manually."
		idle_forever
	fi

	echo "[Bootstrap] Authorising this new CLI device on the existing remote..."
	if ! run_as_user /usr/local/bin/livesync-cli mark-resolved; then
		echo "[Bootstrap] The CLI device could not be authorised. Verify CouchDB connectivity and restart to retry."
		idle_forever
	fi

	echo "[Bootstrap] Pulling the existing remote database before the vault scanner starts..."
	if ! run_as_user /usr/local/bin/livesync-cli sync; then
		echo "[Bootstrap] Initial CouchDB pull failed. The bootstrap remains pending and will retry after restart."
		idle_forever
	fi

	run_as_user mv -f "$bootstrap_pending" "$bootstrap_complete"
	echo "[Bootstrap] Initial remote sync completed."
fi

set -- --vault /vault
case "${LOG_MODE:-normal}" in
	verbose) set -- "$@" --verbose ;;
	debug) set -- "$@" --debug ;;
esac
if [ -n "${SYNC_INTERVAL:-}" ]; then
	set -- "$@" --interval "$SYNC_INTERVAL"
fi

echo "[Bootstrap] Starting the LiveSync daemon."
stop_requested=0
child_pid=""
stop_daemon() {
	stop_requested=1
	if [ -n "$child_pid" ]; then
		kill -TERM "$child_pid" 2>/dev/null || true
	fi
}
trap stop_daemon TERM INT

run_as_user /usr/local/bin/livesync-cli "$@" daemon &
child_pid=$!
wait "$child_pid"
daemon_status=$?

if [ "$stop_requested" -eq 1 ]; then
	exit "$daemon_status"
fi

echo "[Recovery] LiveSync daemon exited with status $daemon_status."
echo "[Recovery] The container will remain running so its console and logs stay available."
idle_forever
