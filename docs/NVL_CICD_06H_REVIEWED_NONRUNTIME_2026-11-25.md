# CICD-06H — Review of non-runtime transitions

UI-02 master 74f6724a0e6fdec72e8beeb14f982dac3d33a105 was blocked on Core with
zero runtime drift and three approved runtime updates. The two manual paths
were the retired offline Cloudzy test matrix (deleted) and the DenaProbe
standalone staging helper (modified). Neither is enrolled in the reported
Core runtime inventory.

The planner admits only the exact reviewed old/new Git tree entries for
these two transitions. It neither copies nor deletes the tools on Core.
Unknown changes, any future edits/re-additions, mode changes, inventory
removals and unreviewed ops paths remain HOLD. Release Gate, exact CI proof,
runtime drift detection, lock, backup, health and rollback remain unchanged.

## Production acceptance

After reviewed merge and green master CI, install the exact trusted planner
blob from the new master in /opt/nvl-deploy using the controlled control-plane
installation procedure. Disable the apply timer during that installation,
ensure no apply service is running and preserve a rollback copy. Verify file
hash and syntax. Do not edit deployed checkpoint, runtime inventory or cooldown.
Re-enable the apply timer only after acceptance; the normal planner/publisher
must revalidate the candidate and apply the approved runtime updates.
The new planner is not self-deployed. The observer may continue.
