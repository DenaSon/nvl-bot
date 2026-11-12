# Marzban / Check-Host low-noise Telegram alerts

Scope: **Marzban Infrastructure Alert only**. Legacy Edge filtering alerts,
DenaProbe, regional scan frequency, classification, history, Marzban and Xray
operations are unchanged.

## Configuration on the Core

```dotenv
MARZBAN_ALERT_ENABLED=1
MARZBAN_ALERT_CHAT_ID=-1001234567890
MARZBAN_ALERT_CONFIRM_SCANS=3
MARZBAN_ALERT_COOLDOWN_MINUTES=60
```

Replace the example ID with the actual Telegram supergroup ID. Add the existing
NVL bot as an admin permitted to post. Configure these values in the running
Core systemd service environment (not Git); changing a file alone does not
guarantee that systemd loads it. Restart the service after updating ENV.

## Policy

- LIKELY/CRITICAL: first transition is immediate.
- POSSIBLE/WARNING: requires three distinct, fresh Check-Host evidence
  revisions. Re-reading cached results does not count.
- UNKNOWN or another state resets POSSIBLE evidence confirmations.
- Derived NODE warnings and incidents are still monitored and recorded, but
  do not duplicate the corresponding PUBLIC HOST Telegram alerts.
- Recovery is announced only for an earlier LIKELY incident or a POSSIBLE
  warning that was actually sent.
- Same-severity repeat alerts are suppressed for 60 minutes unless a delivered
  recovery separated the incidents. Critical first alerts are not delayed.
- A single existing HTML digest combines up to 12 eligible events per tick.
- Suppressed outbox rows have separate audit records, not fake notified_at.

## Safe rollout

1. Test with: python -m unittest tests.test_marzban_alerting -v
2. Run normal regression/compile, backup, and guarded Core deployment.
3. Configure the group ID on Core and restart NVL systemd service.
4. Confirm group receives a new incident with no admin private message.
5. Inspect marzban_alert_confirmations and marzban_alert_suppressed.
6. Missing group ID or send failures never fall back to private admin chats.
   Failed sends remain pending for retry at the next regional scan.

Repository merge is not Core deployment, and the actual chat ID is not stored
in the repository.