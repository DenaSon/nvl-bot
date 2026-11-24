# Emergency fix — failed pre-publication stop

A stop can succeed at systemd level but fail the clean journal evidence
check. The previous publisher then held the release and could leave the
bot inactive. This is a confirmed code defect; the current production
incident cause has not been verified on the host.

The replacement branch never publishes candidate files or sends another
stop after an unproven stop. It verifies the manifest, unchanged code,
schema and operational state, then starts only a confirmed inactive/dead
baseline or checks an already-running baseline. Real readiness is
required before recording ROLLED_BACK. Ambiguous state remains HOLD.
Explicit recovery from STOP_UNPROVEN/STOPPING uses the same path.

This is a control-plane change under ops/, which the deployed planner
deliberately does not self-update. A master merge cannot repair a stopped
Core or a HOLD automatically. Install the trusted updated control-plane
file on Core after disabling the apply timer and verifying the actual
checkpoint. Do not restore live SQLite or touch network services.
