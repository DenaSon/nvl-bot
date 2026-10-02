# Phase 6D — Check-Host Regional Probe Layer

Status: implementation branch `feature/phase6d-checkhost`

## Goal

Phase 6D adds a read-only regional reachability provider for NVL.

It does **not** classify an Edge as filtered and does **not** perform any operational action.

Responsibilities:

- discover Check-Host nodes for a country (Iran by default);
- run TCP reachability checks against an Edge customer-facing `service_port`;
- poll the asynchronous Check-Host request;
- keep pending nodes distinct from failed nodes;
- normalize per-node TCP evidence;
- aggregate node / city / ASN evidence;
- expose stable JSON output for staging and production smoke tests.

## Explicit non-goals

Phase 6D must not:

- set `filter_suspected`;
- produce `POSSIBLE` / `LIKELY` filtering verdicts;
- change `host_pool.active`;
- change the default host;
- update Cloudflare DNS;
- move customer account host assignments;
- activate Standby;
- promote/demote Core or Edge roles.

Those decisions belong to later phases.

## API contract used

Check-Host uses an asynchronous request model:

1. discover nodes from `/nodes/hosts`;
2. submit `/check-tcp?host=<host>:<port>&node=<node>...`;
3. receive a `request_id`;
4. poll `/check-result/<request_id>`.

For TCP results:

- `null` = node is still performing the check;
- an object containing `address` / `time` = TCP success;
- an object containing `error` = completed TCP failure.

The provider also tolerates a `message` error field because observed Check-Host responses can contain similar error-message shapes in other check types.

## Primary signal

TCP against the actual Edge `service_port` is the primary Phase 6D signal.

Ping may be added later only as supporting evidence. It must not be treated as equivalent to service reachability.

Reason: a node can fail an ICMP/ping-style check while TCP to a service port still succeeds.

## Module

`checkhost_probe.py`

Key types:

- `CheckHostNode`
- `TcpNodeEvidence`
- `RegionalTcpProbe`
- `CheckHostClient`

The aggregate contains:

- total nodes;
- completed nodes;
- successful nodes;
- failed nodes;
- pending nodes;
- success ratio across completed nodes;
- successful/failed ASN sets;
- successful/failed city sets;
- raw normalized evidence per node.

No filtering threshold is applied in this layer.

## Unit tests

`tests/test_phase6d_checkhost.py`

Coverage includes:

- Iran node discovery and metadata;
- repeated `node=` query parameters;
- TCP success normalization;
- TCP failure normalization;
- `null` pending semantics;
- polling until completion;
- polling timeout without converting pending into failure;
- city/ASN aggregation;
- static guard against operational failover/DNS hooks.

## Local / staging test

Compile:

```bash
python3 -m py_compile checkhost_probe.py
python3 -m unittest tests.test_phase6d_checkhost -v
```

Run all regressions:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Live smoke test

This command is read-only from NVL's point of view. It only calls Check-Host.

Use a known target first:

```bash
python3 checkhost_probe.py 1.1.1.1 443
```

Then test one real Edge using its customer-facing service port:

```bash
python3 checkhost_probe.py <EDGE_IP> <SERVICE_PORT>
```

Expected JSON shape:

```json
{
  "ok": true,
  "request_id": "...",
  "target_host": "...",
  "target_port": 2252,
  "total_nodes": 8,
  "completed_nodes": 8,
  "successful_nodes": 8,
  "failed_nodes": 0,
  "pending_nodes": 0,
  "completed_success_ratio": 1.0,
  "failed_asns": [],
  "failed_cities": [],
  "evidence": []
}
```

A provider/API failure returns exit code 2 and JSON with `"ok": false`.

## Deployment scope for 6D validation

Because Phase 6D is not wired into the bot runtime yet, validation does not require replacing the main bot or restarting `nvlbot`.

Only stage/test `checkhost_probe.py` and the tests. After 6D is validated, Phase 6E can consume its aggregate evidence and persist the resulting regional signal through the existing Phase 6C observability contract.
