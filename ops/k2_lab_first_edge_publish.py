"""Lab-only febcc code upgrade using the existing publisher and rollback.

No server bootstrap, network/profile/PAM/UID changes or production publish.
The owner passes the exact reviewed commit and package digest over SSH.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3

from ops import k2_core_code_publish_febcc as publisher
from ops.k2_lab_core_copy import LAB_IP, local_ipv4s

OLD_RELEASE_SHA = 'e7e1324646d60bd7a9d533b4a28313bc03c319c9e2a64c6accfd0052ba80c297'
OLD_BOT_SHA = '502504367bdc01ef34efca70b6949ff3c03a74d3997e24ccf1478b1b945ce09b'


def preflight():
    publisher.require(os.geteuid() == 0 and LAB_IP in local_ipv4s(), 'WRONG_LAB_HOST')
    path = Path('/root/master_bot.db')
    with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=5) as db:
        for key, value in (('brand', 'NVL-LAB'), ('core_wg_public_ip', LAB_IP)):
            publisher.require(db.execute('SELECT value FROM settings WHERE key=?',
                                         (key,)).fetchall() == [(value,)],
                              'LAB_IDENTITY_CHANGED')
    publisher.off()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    # Wrong-host refusal precedes publisher configuration and every mutation.
    preflight()
    publisher.require(re.fullmatch('[a-f0-9]{40}', args.commit) is not None
                      and re.fullmatch('[a-f0-9]{64}', args.package_sha256) is not None,
                      'EXACT_RELEASE_PINS_REQUIRED')
    stage = args.stage
    publisher.require(stage.parent == Path('/root')
                      and stage.name.startswith('nvl-lab-first-edge-')
                      and not stage.is_symlink(), 'INVALID_LAB_STAGE')
    publisher.parents(stage/'deployment-plan.json')
    publisher.require(Path(__file__).resolve().parents[1] == stage/'source',
                      'RUN_REVIEWED_STAGED_SOURCE')
    publisher.STAGE = stage
    publisher.SHA = args.commit
    publisher.PACKAGE_SHA = args.package_sha256
    publisher.OLD_RELEASE_SHA = OLD_RELEASE_SHA
    publisher.OLD_BOT_SHA = OLD_BOT_SHA
    publisher.EXPECTED_CHANGED = frozenset(('edge_egress_k2_p1_worker.py',))
    if args.rollback:
        plan = json.loads((stage/'deployment-plan.json').read_bytes())
        publisher.require(plan['git_sha'] == args.commit, 'ROLLBACK_RELEASE_CHANGED')
        publisher.restore(plan)
    else:
        publisher.deploy()


if __name__ == '__main__':
    main()
