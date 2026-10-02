# Phase 6E — Filtering Classification

Status: implementation branch `feature/phase6e-filtering-classification`

## Goal

Phase 6E converts normalized regional node evidence into deterministic filtering
states while preserving the diagnostic/action separation established in Phase 6C
and the provider separation established in Phase 6D.

Phase 6E does **not** perform failover.

## Architecture

```text
Phase 6D provider
(Check-Host raw node evidence)
        |
        v
regional_filtering.py
(spatial quorum/diversity)
        |
        v
Regional round state
UNKNOWN / CLEAR / POSSIBLE / LIKELY
        |
        v
edge_observability.py
(temporal confirmation + local/external controls)
        |
        v
Final filter state
UNKNOWN / CLEAR / POSSIBLE / LIKELY
```

## Spatial evidence

The Phase 6E regional classifier is provider-neutral. It consumes node-like
evidence with:

- `ok = True / False / None`
- `pending`
- `asn`
- `city`

Pending/unknown nodes never count as failures.

### Minimum usable coverage

A round is `UNKNOWN` unless it has at least:

- 4 completed nodes;
- 4 distinct completed ASNs;
- 2 distinct completed cities.

This avoids classifying a partial provider response as regional filtering.

### CLEAR

A usable round is `CLEAR` when there is no meaningful diverse failure quorum.

Examples with the current 8 Iran nodes:

- 8/8 success -> CLEAR;
- 7/8 success -> CLEAR;
- two failed nodes that collapse to the same ASN -> CLEAR.

A limited failure is still preserved as reason `LIMITED_FAILURE`; it is not
silently discarded.

### POSSIBLE

A usable round becomes `POSSIBLE` when all of the following are true:

- at least 2 failed nodes;
- at least 2 failed ASNs;
- failed nodes are at least 25% of completed nodes.

This is an alert category, **not** a calibrated probability.

### LIKELY

A usable round becomes `LIKELY` only when all of the following are true:

- failures are at least 60% of completed nodes;
- at least 4 failed nodes;
- at least 4 failed ASNs;
- at least 2 failed cities.

With 8 completed Iranian nodes this normally means at least 5 failed nodes with
strong ASN/city diversity.

## Temporal confirmation

Spatial evidence alone does not produce a final high-confidence filtering state.

`edge_observability.py` now accepts the richer `regional_filter_state`.

Rules:

- a `POSSIBLE` round remains POSSIBLE even if repeated many times;
- a single `LIKELY` round is surfaced as POSSIBLE until the configured temporal
  confirmation threshold is reached;
- repeated `LIKELY` rounds + healthy external control -> final `LIKELY / HIGH`;
- repeated `LIKELY` rounds without external control -> final `POSSIBLE / MEDIUM`;
- if the external control also fails, filtering is not isolated and the final
  filter state is `UNKNOWN`;
- confirmed filtering remains sticky until the configured regional recovery
  success threshold is met.

The existing Phase 6C Boolean-only caller remains backwards compatible.

## Infrastructure failures

WireGuard/Core/service failures do not imply `CLEAR` filtering state. They leave
the filtering dimension `UNKNOWN`, because infrastructure failure prevents a
clean filtering inference.

## Safety boundary

Phase 6E must not:

- change DNS;
- change default host;
- enable/disable host membership;
- move customer accounts;
- activate Standby;
- promote/demote Core or Edge;
- perform failover.

## Tests

`tests/test_phase6e_filtering.py` covers:

- all-eight healthy baseline;
- single-node failure;
- diverse 2/8 failure -> POSSIBLE;
- 4/8 failure -> POSSIBLE, not LIKELY;
- diverse 5/8 failure -> LIKELY;
- pending results -> UNKNOWN when coverage is insufficient;
- ASN diversity protection;
- repeated POSSIBLE never becoming LIKELY;
- LIKELY temporal confirmation;
- external control gating;
- sticky recovery;
- backwards compatibility with the Phase 6C Boolean contract;
- static side-effect guard for the classifier.

## Staging validation

After fetching the branch into a detached worktree:

```bash
/root/venv/bin/python3 -m py_compile \
  regional_filtering.py \
  edge_observability.py \
  checkhost_probe.py

/root/venv/bin/python3 -m unittest \
  tests.test_phase6e_filtering \
  tests.test_phase6c_regressions \
  tests.test_phase6d_checkhost \
  -v

/root/venv/bin/python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Live read-only classification smoke test

This uses Phase 6D to collect evidence and Phase 6E to classify it without DB
writes or bot restart:

```bash
cd /root/nvl-phase6e-stage

/root/venv/bin/python3 - <<'PY'
from checkhost_probe import CheckHostClient
from regional_filtering import classify_regional_evidence

probe = CheckHostClient().probe_tcp("1.1.1.1", 443)
decision = classify_regional_evidence(probe.evidence)

print(decision.to_dict())
PY
```

Expected baseline state for a healthy target is `CLEAR`.

Then repeat with one real Edge customer-facing `service_port`.

## Runtime integration

Phase 6E intentionally stops before scheduled provider execution and admin
notifications. Phase 6F will wire regional rounds into the management/notification
surface while preserving the no-failover boundary.
