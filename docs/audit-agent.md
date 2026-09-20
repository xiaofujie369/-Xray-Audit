# Agent operation

From an extracted release, run `sudo bash install-audit-agent.sh`. Existing Xray must already be installed. Enter the HTTPS central URL, short-lived enrollment token, VPS name and region. The installer stores credentials in `/opt/xray-audit/config.json` with mode 0600, starts only `xboard-audit`, and leaves proxy configuration alone.

For automation:

```sh
sudo bash install-audit-agent.sh --server https://audit.example.com --enroll-token TOKEN --name US-LA-01 --region US-LA
```

Interactive token input is hidden and avoids shell history. Never share the resulting long-lived token. Keep config and spool when upgrading. A new enrollment normally creates a new VPS; to rotate credentials while retaining the VPS, create an enrollment token bound to that existing VPS ID through the admin API.

Settings are in `agent/config.example.json`. JSON names correspond to the specification's `AUDIT_*` names: `aggregation_seconds`, `max_bucket_keys`, `upload_interval`, `batch_max_events`, `batch_max_bytes`, `spool_max_mb`, `spool_retention_hours`. Set `public_ipv4` and/or `public_ipv6` explicitly. No per-minute public IP lookup is performed. Configure `single_node` only for a legacy single-node deployment. Ambiguous legacy records on multi-node hosts retain null node IDs.

`xbr` options 20–29 provide status, enable/disable, enrollment, editor, logs, spool, upload, connection test and diagnostics. CLI equivalents:

```sh
export PYTHONPATH=/opt/xray-audit/code
python3 -m agent.manage status
python3 -m agent.manage test
python3 -m agent.manage diagnostics
python3 -m agent.manage upload
```

Diagnostics never prints bearer tokens. A failed central request keeps the batch and applies retry delay. Invalid batches remain available for diagnosis and expire under the configured retention policy. Receipt acknowledgement is checked against the exact batch ID before removal. Disk reserve protects the host, and oldest data is evicted under capacity pressure; check `evicted_batches` rather than assuming unlimited offline retention.

The traffic inbox holds at most 120 files, each at most 4 MiB, with a 128 MiB filesystem reserve. It is best-effort: if it is unavailable or full, panel reporting takes priority. This is distinct from already committed durable spool batches.

Optional Xray generation controls in `/opt/xray-sync/.env`:

```dotenv
AUDIT_ENABLED=false
AUDIT_SNIFFING_ENABLED=true
AUDIT_SNIFF_HTTP=true
AUDIT_SNIFF_TLS=true
```

When explicitly set to enabled, supported inbound sniffing is limited to configured HTTP/TLS protocols; QUIC is not injected. Audit-disabled config generation preserves legacy defaults. Existing Xray sniffing/routing semantics remain in effect unless an operator changes those controls. Changing sniffing affects generated configuration and goes through the project's normal validation/rollback path; merely enabling the audit daemon does not change it.
