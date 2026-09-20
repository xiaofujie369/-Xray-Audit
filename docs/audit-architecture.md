# Audit architecture

Audit is an optional, separate service. Existing installations do not start it. Xray and XBoard have no network or service dependency on central, Redis, PostgreSQL, or the audit daemon. Disabling audit does not restart Xray.

The report process remains the sole owner of `statsquery --reset`. Its optional local handoff copies user/node interval totals into a bounded inbox. Copy errors do not stop panel reporting. The independent agent moves those files into its durable SQLite outbox. Connection metadata never receives invented domain byte counts.

The access reader has its own cursor inside `/opt/xray-audit/spool.db`. Each cursor update and its batches commit together. It never shares `report_state.json`. It checks inode, size, and a short pre-offset hash to detect rename and copytruncate. It attempts to drain a renamed file before reading the new file. Copytruncate itself has an unavoidable copy/truncate race; retention and the agent cannot recover bytes already removed by logrotate.

One bounded read aggregates by minute, node, user, source, destination, protocol, tags and decision. High-cardinality input flushes early. Separate uploader and reader threads prevent central request latency from blocking log ingestion. SQLite uses WAL and synchronous NORMAL. This protects process crashes; host power failure has the SQLite NORMAL durability tradeoff.

Uploads use gzip over verified HTTPS, bounded bodies, independent bearer credentials, sortable random batch IDs and retry backoff. PostgreSQL commits events and the unique `(agent_id,batch_id)` receipt in one transaction before acknowledgement. A different body using the same ID is a conflict. PostgreSQL failure returns 503; Redis failure does not prevent event ingest. Login/enrollment fail closed if their Redis rate limiter is unavailable.

Jobs originate in a PostgreSQL outbox; Redis/Celery coordinates processing but is not the source of truth. Workers lock jobs and targets, retry failures, perform correlation, send optional notifications, and enforce retention. Notifications contain incident/host metadata, not browsing histories.

Probes accept only authenticated central target configuration. Mainland classification uses independent network groups, consecutive evidence and control targets. A refusal or TLS/HTTP failure is recorded but does not by itself count as filtering. Classification changes retain snapshots of their evidence.

Correlation compares event windows with the same VPS's normal control windows. Scores are associations, not cause probabilities. `docs/audit-correlation.md` specifies the formula and limitations.

## Data coverage

Xray access records expose their recorded destination, not a guaranteed simultaneous SNI, original IP and resolved IP. A domain destination produces a domain with null destination IP; an IP destination produces an IP with null domain. No public DNS lookup is used to invent historical destination IPs. Encrypted ClientHello and protocol behavior may hide a domain. Sniffing does not guarantee the standard access logger will emit the sniffed hostname.

Pinned upstream references: [access message formatting](https://github.com/XTLS/Xray-core/blob/v26.5.9/common/log/access.go), [dispatcher](https://github.com/XTLS/Xray-core/blob/v26.5.9/app/dispatcher/default.go). Production logging remains `warning`, never debug. URLs are reduced to hostname; request paths, queries, credentials and packet payloads are not persisted by the audit agent.

## Capacity planning

Small central host: 2 vCPU, 4 GB RAM, 40 GB SSD. Recommended starting point: 4 vCPU, 8 GB RAM, 100+ GB SSD. Actual capacity depends on unique aggregate keys, retention and query workload. The 50 VPS / 500 nodes / 10,000 users / 100 batches per second figures are sizing targets; benchmark the intended environment before claiming them. Monitor database size, worker queue, spool eviction and query latency.
