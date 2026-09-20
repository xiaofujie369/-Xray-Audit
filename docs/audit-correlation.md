# Correlation interpretation

The event window ends at first known bad, not the later confirmation timestamp. Its start is the configured lookback (default 60 minutes). Manual incidents use the same pipeline and are visibly labeled manual. Connection metadata and user/node traffic intervals are separate.

For each user, source IP, domain, destination IP and node, compute connection counts, first/last appearance, distinct users/source addresses and the event connection share. The same-VPS baseline uses available same-hour windows over the previous seven days, excluding overlapping incidents. With fewer than two available windows, it falls back to the previous 24 hours excluding incident windows. If no baseline observations exist, the score is zero and marked insufficient baseline, not high-risk by assumption.

Baseline lift compares entity connection share in the event with smoothed share in the control data. Define:

* `P`: fraction of eligible incidents where the entity occurs.
* `L`: clamp(log2(max(1, lift))/4, 0, 1).
* `T`: clamp(1 − seconds before event/window duration, 0, 1).
* `V`: clamp((distinct VPS count − 1)/4, 0, 1).
* `S`: fraction of event-window connections for the entity.

Default score: `100 × (0.30P + 0.25L + 0.20T + 0.15V + 0.10S) × clamp((lift−1)/3, 0, 1)`.

The final multiplier suppresses universally popular entities. Weights, ignored domains, baseline method, counts and components are exposed in settings/details. Scores are bounded 0–100. Counts, data retention, shared networks/NAT, insufficient coverage, changing workload and multiple comparisons all affect interpretation. A score is not a probability that a user or destination caused filtering.

Cross-event analysis uses retained source event windows; expired detailed data limits later recalculation. Retained correlation snapshots preserve the prior computation. Configure event-detail retention to cover the investigation horizon you actually need.
