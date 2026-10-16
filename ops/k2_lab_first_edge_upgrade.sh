#!/usr/bin/env bash
# Owner-run from the original Core: GitHub source -> existing isolated lab.
set -Eeuo pipefail
umask 077
test "$(id -u)" = 0
test "$#" = 3
NVL_COMMIT=$1
NVL_BUNDLE=$2
NVL_PACKAGE=$3
[[ "$NVL_COMMIT" =~ ^[a-f0-9]{40}$ ]]
[[ "$NVL_BUNDLE" =~ ^[a-f0-9]{64}$ ]]
[[ "$NVL_PACKAGE" =~ ^[a-f0-9]{64}$ ]]
ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq 209.200.246.198
NVL_PID=$(systemctl show nvlbot -p MainPID --value)
test "$NVL_PID" -gt 0
NVL_REPO=/root/nvl-release
git -C "$NVL_REPO" fetch --quiet origin "$NVL_COMMIT"
test "$(git -C "$NVL_REPO" rev-parse FETCH_HEAD)" = "$NVL_COMMIT"
NVL_LOCAL=$(mktemp -d /root/nvl-lab-update-XXXXXXXX)
git -C "$NVL_REPO" show "$NVL_COMMIT:ops/k2_release_bundle.py" > "$NVL_LOCAL/bundle.py"
/root/venv/bin/python3 -B "$NVL_LOCAL/bundle.py" build --repo "$NVL_REPO" \
  --commit "$NVL_COMMIT" --output "$NVL_LOCAL/source.tar"
printf '%s  %s\n' "$NVL_BUNDLE" "$NVL_LOCAL/source.tar" | sha256sum -c -
NVL_SSH=(ssh -o ControlMaster=auto -o ControlPersist=120 \
  -o "ControlPath=$NVL_LOCAL/ssh" -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=3 root@144.172.84.127)
trap '"${NVL_SSH[@]}" -O exit >/dev/null 2>&1 || true' EXIT
NVL_REMOTE=$("${NVL_SSH[@]}" 'umask 077; mktemp -d /root/nvl-lab-first-edge-XXXXXXXX')
[[ "$NVL_REMOTE" =~ ^/root/nvl-lab-first-edge-[a-zA-Z0-9]{8}$ ]]
printf 'LAB_STAGE=%s\n' "$NVL_REMOTE"
scp -o "ControlPath=$NVL_LOCAL/ssh" "$NVL_LOCAL/source.tar" \
  "root@144.172.84.127:$NVL_REMOTE/source.tar"
"${NVL_SSH[@]}" bash -s -- "$NVL_REMOTE" "$NVL_COMMIT" "$NVL_BUNDLE" "$NVL_PACKAGE" <<'REMOTE'
set -Eeuo pipefail
umask 077
NVL_STAGE=$1
NVL_COMMIT=$2
NVL_BUNDLE=$3
NVL_PACKAGE=$4
printf '%s  %s\n' "$NVL_BUNDLE" "$NVL_STAGE/source.tar" | sha256sum -c -
mkdir "$NVL_STAGE/source"
tar -xf "$NVL_STAGE/source.tar" -C "$NVL_STAGE/source"
cd "$NVL_STAGE/source"
/root/venv/bin/python3 -B -m ops.k2_release_bundle verify --directory . \
  --commit "$NVL_COMMIT" --package-sha256 "$NVL_PACKAGE"
/root/venv/bin/python3 -B -m unittest tests.test_edge_egress_k2_p1_worker \
  tests.test_edge_egress_k2_m4_root_worker tests.test_k2_lab_first_edge_publish -q
printf '%s\n' "$NVL_COMMIT" > "$NVL_STAGE/STAGING_OK"
nohup flock -n "$NVL_STAGE/publish.lock" /root/venv/bin/python3 -B \
  -m ops.k2_lab_first_edge_publish --stage "$NVL_STAGE" \
  --commit "$NVL_COMMIT" --package-sha256 "$NVL_PACKAGE" \
  > "$NVL_STAGE/deploy.log" 2>&1 < /dev/null &
NVL_JOB=$!
if wait "$NVL_JOB"; then
  cat "$NVL_STAGE/deploy.log"
else
  cat "$NVL_STAGE/deploy.log"
  exit 1
fi
REMOTE
test "$(systemctl show nvlbot -p MainPID --value)" = "$NVL_PID"
systemctl is-active --quiet nvlbot
echo PRODUCTION_SERVICE_UNCHANGED=YES
