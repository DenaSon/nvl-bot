# Fresh isolated Core — interactive owner-run setup (2026-10-17)

The owner deleted the former Lab Core (144.172.84.127) and its Edge
(144.172.84.112) to reduce costs. Their last success reports are historical,
not current infrastructure. Production remains the original Core; no fresh
customer acceptance or new Lab installation is claimed.

Run the pinned repository's module on the original Core with its existing
/root/venv/bin/python3:

    python3 -B -m ops.k2_lab_core_prepare --commit <exact-40-character-commit>

The CLI reads the new public IPv4 from /dev/tty, then the root SSH password
and separate TEST bot token using getpass. This also works inside a bash
heredoc. The TEST token may be the former Lab bot's token, provided that old
polling instance is gone and no webhook is configured. The production bot ID,
including a rotated token for that same bot, is refused.

Target: a fresh Ubuntu 24.04 amd64 VPS, Python 3.12, password SSH as root
(default port 22; --port selects an additional existing administrative port,
but port 22 must remain available for the independent recovery account).
No Edge address, domain, TLS certificate, GitHub login or customer copy is
required. Installed Python packages come from the original Core and support
the same minor Python/compiled extension ABI across Ubuntu patch releases.

The controller authenticates once, fetches exactly the supplied Git commit
through /root/nvl-release, builds the canonical source-only bundle and sends
source, installed site-packages, fresh Lab environment, worker and hash
metadata over SFTP. The worker installs only after matching host, OS, empty
Lab paths/accounts and payload hashes. Existing/partial installations are
held, never overwritten or resumed. Both the original fixed-address copier
and its old pinned invocation remain compatible.

The existing fresh-Lab installer creates:
- current application code and canonical empty application/egress schemas;
- three independent nvltest1/1636, nvltest2/1637, nvltest3/1638 accounts,
  initially Core-local, without any reference to the deleted Edge;
- independent bot login (labadmin), recovery SSH/sudo identity and passwords;
- new wg0/Core keys without any production peer/private key;
- customer SSH on 2252 and preserved administrative listeners;
- a root-private nvlbot systemd service with stable PID observation;
- 1 GiB persistent swap on a low-memory VPS when adequate swap is absent,
  with disk checks and refusal to replace an existing swap path.

The installer is detached. During the SSH listener restart the controller
reconnects and polls result.json only; it never relaunches the installer.
After success it performs a fresh nvlrescue SSH login and actual sudo id -u,
downloads the private Lab access file to the original Core's unique export
directory and verifies the original Production bot still has the same PID.

Root SSH password is never placed in argv, payload files or logs. The fresh
TEST environment is sent privately to the target and its origin temporary
copy is removed. Access credentials remain 0600 in the Lab and the unique
origin export directory. New SSH host keys are fingerprinted and remembered
in /root/.ssh/nvl-lab-known_hosts; a changed known key requires verification
instead of an automatic trust reset.

Completion is LAB_CORE_INSTALLED, LAB_RESCUE_SSH_AND_SUDO=PASS and
PRODUCTION_SERVICE_UNCHANGED=YES. LAB_ACCESS_FILE points to the downloaded
login details. This is fresh Core preparation: no Edge, transferred user,
field report, READY state or customer-runtime release is manufactured.
Next add a NEW Edge via this TEST bot's existing wizard. The former
ops/k2_lab_trial.py grant is pinned to deleted hosts and must not be used
to enable the replacement Core.
