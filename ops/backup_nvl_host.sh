#!/usr/bin/env bash
# NVL emergency host snapshot: no service stop/restart and no network changes.
# Usage: sudo bash backup_nvl_host.sh core|edge
# WARNING: output includes database, account hashes, SSH/WG keys and tokens.
set -Eeuo pipefail
umask 077

ROLE="${1:-}"
if [[ "$ROLE" != "core" && "$ROLE" != "edge" ]]; then
  echo "Usage: sudo bash $0 core|edge" >&2; exit 2
fi
if (( EUID != 0 )); then echo "Must run as root" >&2; exit 2; fi
for cmd in tar sha256sum gzip df find sort mktemp date; do
  command -v "$cmd" >/dev/null || { echo "Missing: $cmd" >&2; exit 2; }
done
if [[ "$ROLE" == "core" ]]; then
  command -v sqlite3 >/dev/null || { echo "Missing: sqlite3" >&2; exit 2; }
  [[ -f /root/master_bot.db ]] || { echo "Missing /root/master_bot.db" >&2; exit 2; }
fi

FREE_KB="$(df -Pk /root | awk 'NR==2 {print $4}')"
if [[ ! "$FREE_KB" =~ ^[0-9]+$ ]] || (( FREE_KB < 1048576 )); then
  echo "STOP: less than 1 GiB available under /root" >&2; exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE=/root/nvl-emergency-backups
mkdir -p "$BASE"
chmod 700 "$BASE"
DEST="$(mktemp -d "$BASE/${ROLE}-${STAMP}-XXXXXX")"
chmod 700 "$DEST"
DETAILS="$DEST/diagnostics"
mkdir -m 700 "$DETAILS"

# Observability only. These commands never mutate running state.
{
  date -u -Is
  hostname -f 2>/dev/null || hostname
  uname -a
  printf '\n=== DISK ===\n'; df -hT
  printf '\n=== INTERFACES ===\n'; ip -br addr || true
  printf '\n=== IPv4 RULES ===\n'; ip -4 rule show || true
  printf '\n=== IPv4 ROUTES ===\n'; ip -4 route show table all || true
  printf '\n=== IPv6 RULES/ROUTES ===\n'; ip -6 rule show || true; ip -6 route show table all || true
  printf '\n=== WIREGUARD (NO PRIVATE KEYS) ===\n'; wg show all || true
  printf '\n=== IPTABLES ===\n'; iptables-save || true
  printf '\n=== NFTABLES ===\n'; nft list ruleset || true
  printf '\n=== SYSCTL ===\n'; sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv6.conf.all.disable_ipv6 || true
  printf '\n=== SYSTEMD UNITS ===\n'; systemctl list-unit-files --no-pager || true
  printf '\n=== SYSTEMD TIMERS ===\n'; systemctl list-timers --all --no-pager || true
  printf '\n=== LISTENERS ===\n'; ss -lntup || true
  printf '\n=== GIT VERSION ===\n'; git -C /root/nvl-release rev-parse HEAD 2>/dev/null || true
} > "$DETAILS/host-state.txt" 2>&1

if [[ "$ROLE" == "core" ]]; then
  echo "Backing up live SQLite database with SQLite's online backup API..."
  sqlite3 -bail /root/master_bot.db ".backup '$DEST/master_bot.sqlite3'"
  CHECK="$(sqlite3 -bail "$DEST/master_bot.sqlite3" 'PRAGMA integrity_check;')"
  if [[ "$CHECK" != "ok" ]]; then
    echo "STOP: backup database failed integrity_check: $CHECK" >&2
    exit 1
  fi
  sqlite3 -header -column "$DEST/master_bot.sqlite3" \
    'SELECT name FROM sqlite_master WHERE type="table" ORDER BY name;' \
    > "$DETAILS/db-tables.txt"
fi

# Curated paths only. Never tar /root wholesale, venv, caches, live SQLite or WAL.
INV="$DEST/archive-paths.nul"
: > "$INV"
add_path() { [[ ! -e "$1" && ! -L "$1" ]] || printf '%s\0' "${1#/}" >> "$INV"; }
for p in \
  /etc/wireguard /etc/ssh /etc/gost /etc/iptables /etc/nftables.conf \
  /etc/sysctl.conf /etc/sysctl.d /etc/systemd/system /etc/letsencrypt \
  /etc/ssl/cf /etc/ufw /etc/netplan /etc/network \
  /etc/passwd /etc/shadow /etc/group /etc/gshadow \
  /etc/security/limits.conf /etc/security/limits.d /etc/pam.d \
  /etc/nvl-egress /opt/nvl-egress \
  /etc/crontab /etc/cron.d /etc/cron.daily /var/spool/cron/crontabs \
  /root/.ssh /root/.env /root/.env.production \
  /root/nvl-egress-v1 /root/nvl-egress-staging /root/nvl-egress-keys \
  /root/nvl-release \
  /usr/local/bin/gost /usr/local/bin/badvpn-udpgw; do
    add_path "$p"
done
while IFS= read -r -d '' f; do add_path "$f"; done < <(
  find /root -maxdepth 1 -type f \
    \( -name '*.py' -o -name '*.sh' -o -name 'requirements*.txt' \
       -o -name '*.service' -o -name '*.env' -o -name '*.conf' \) -print0
)

sort -zu "$INV" -o "$INV"
# Record exactly which input roots are covered, without leaking secret bytes.
# No claim that this curated archive replaces a full provider disk snapshot.
tr '\\0' '\\n' < "$INV" > "$DETAILS/archived-roots.txt"
if [[ "$ROLE" == "core" ]]; then
  for required in etc/ssh etc/pam.d etc/passwd etc/shadow; do
    grep -Fxq "$required" "$DETAILS/archived-roots.txt" || {
      echo "STOP: mandatory Core host identity/config path omitted: $required" >&2
      exit 1
    }
  done
  for mandatory_k2 in /etc/nvl-egress /opt/nvl-egress; do
    if [[ -e "$mandatory_k2" || -L "$mandatory_k2" ]]; then
      grep -Fxq "${mandatory_k2#/}" "$DETAILS/archived-roots.txt" || {
        echo "STOP: existing K2 PAM/roster/guard directory not snapshotted" >&2
        exit 1
      }
    fi
  done
fi
# The config archive contains PRIVATE KEYS and PASSWORD HASHES. Never push to Git.
if [[ -s "$INV" ]]; then
  # Snapshot working tree, never caches, node_modules or virtualenvs.
  tar -C / --exclude="*/.git/*" --exclude="*/__pycache__/*" \
    --exclude="*/node_modules/*" --exclude="*/venv/*" \
    --exclude="*/.venv/*" --exclude="*/.cache/*" \
    --null -T "$INV" -czf "$DEST/system-configs.tar.gz"
else
  echo "STOP: no config paths found" >&2; exit 1
fi
gzip -t "$DEST/system-configs.tar.gz"
tar -tzf "$DEST/system-configs.tar.gz" >/dev/null
rm -f "$INV"

(
  cd "$DEST"
  sha256sum system-configs.tar.gz > SHA256SUMS
  sha256sum diagnostics/archived-roots.txt >> SHA256SUMS
  sha256sum diagnostics/host-state.txt >> SHA256SUMS
  if [[ "$ROLE" == "core" ]]; then
    sha256sum master_bot.sqlite3 >> SHA256SUMS
    sha256sum diagnostics/db-tables.txt >> SHA256SUMS
  fi
  sha256sum -c SHA256SUMS
)

cat > "$DEST/README-PRIVATE.txt" <<'MSG'
HIGHLY CONFIDENTIAL NVL emergency snapshot. Contains passwords/SSH keys/WireGuard
private keys and may contain Telegram/API credentials and user personal data.
Do not upload to GitHub or share in chat. Keep directory owned by root, mode 700.
Copy an encrypted copy off this VPS to independent storage; a same-VPS backup
will be lost if the VPS provider deletes/suspends the instance.
This is a CURATED logical snapshot, NOT a full disk/VM snapshot and NOT a
proof of restore. Take an independent provider full-volume snapshot of BOTH
Core and candidate Edge, export encrypted backups, and perform a disposable
clone/restore drill with working independent console rescue.
The K2 root roster/guard/PAM and pinned dedicated transport files are included
when present. Never infer that a missing protected gate was backed up.
Restore only after inspecting host identity, OS versions, account UIDs and config.
Avoid blindly extracting /etc/passwd, /etc/shadow, network, firewall or SSH configs
on a live machine. Database and archive checksums are in SHA256SUMS.
MSG
find "$DEST" -type f -exec chmod 600 {} +
find "$DEST" -type d -exec chmod 700 {} +
printf '\nBACKUP_COMPLETE=%s\n' "$DEST"
printf 'VERIFY: (cd %q && sha256sum -c SHA256SUMS)\n' "$DEST"
printf 'WARNING: snapshot is stored only on this VPS until you export it securely.\n'