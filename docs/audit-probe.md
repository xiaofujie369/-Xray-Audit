# Independent probes

Deploy outside the target VPS, with mainland reachability provided by a real mainland network. Create a `probes` enrollment token in central, mark mainland probes accurately, and assign an independence group. Two credentials on the same network should use the same group; they do not count twice toward consensus.

```sh
sudo bash probe/install-probe.sh --server https://audit.example.com --enroll-token TOKEN --name CN-01 --region CN
```

The service uses `/opt/xray-probe/config.json` and a separate spool. Default checks run every 300 seconds with a five-second socket timeout and at most eight concurrent checks. Central distributes only authenticated, admin-defined public IP targets. HTTP checks use HEAD; TLS validates certificates and configured SNI. A generic TLS handshake is not a Reality authentication check. Use TCP for raw Reality nodes unless a meaningful operator-defined TLS target exists.

Set `control_targets` to operator-selected public IP/port objects in system settings. If any configured control fails, that probe's VPS results do not contribute to classification. With no controls the platform cannot distinguish a failed probe network using controls; configure them for production.

Targets are cached for at most 24 hours during a central outage. Results remain in the local durable spool and retry later. A stale or uninitialized config stops new probes rather than accepting untrusted targets. API ingest does not accept arbitrary remote probe requests.

Default states: NORMAL after recent successful evidence; SUSPECTED after two consecutive qualifying failures; CONFIRMED only with at least two explicitly grouped mainland networks, matching current control revisions, an independent outside-mainland success quorum of one network, configured controls and a recent healthy Xray heartbeat; RECOVERED after two consecutive successes from the configured group quorum. Missing/stale probes are not counted as successful checks. Refused, DNS, HTTP and TLS failures are recorded separately; only timeout/network-unreachable evidence enters this classifier.

Classification establishes observed reachability, not filtering mechanism or causation. Events preserve first-bad, last-good, evidence snapshots and the investigation window. A single configured probe cannot reach the default quorum. V2 always requires at least two independent mainland groups for confirmation, even if the configured quorum is one. Upgrade existing probes using `bash probe/update-probe.sh` after upgrading central. Old probe results remain accepted but cannot satisfy the new control-revision requirement. See [V2 guide](audit-v2.md).
