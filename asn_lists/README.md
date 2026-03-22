# ASN Lists

This folder contains ASN reputation datasets intended for threat hunting, enrichment, triage, and blocklist curation. This document explains what the files contain, when to use each one, and how to consume them from KQL.

## Published files

- `asn_reputation.csv`: full ASN reputation dataset.
- `asn_reputation_nonzero.csv`: same schema, filtered to rows where `maliciousness_score > 0`.

Both CSV files can be loaded directly with `externaldata()` in KQL without extra preprocessing.

## When to use each file

- Use `asn_reputation.csv` when you want the complete dataset, including benign or currently unscored ASNs.
- Use `asn_reputation_nonzero.csv` when you want a smaller and more actionable list for detections, enrichment, or watchlists.
- If you need a stricter subset, filter by `maliciousness_score`, `confidence_score`, or `category`.

## CSV fields

### Identity and classification

- `asn`: Autonomous System Number in `AS12345` format.
- `description`: Public description or operator name associated with the ASN.
- `category`: Main classification assigned to the ASN.
- `recommended_action`: Suggested operational handling for the ASN.
- `reasons`: Short textual explanation of the main reasons behind the classification.

### Core scoring

- `maliciousness_score`: Overall risk score from 0 to 100. Higher values indicate stronger evidence of malicious or abusive activity.
- `confidence_score`: Confidence level for the assessment from 0 to 100.
- `score_density`: Contribution related to how concentrated the malicious activity is within the ASN space.
- `score_volume`: Contribution related to the absolute volume of malicious observations.
- `score_diversity`: Contribution related to the number of distinct sources or signal families supporting the assessment.
- `score_severity`: Contribution related to the seriousness of the observed activity.
- `score_persistence`: Contribution related to how consistently the ASN appears over time.
- `score_routing`: Contribution related to routing or Internet infrastructure risk indicators.
- `score_context_adjustment`: Context-based adjustment applied to the overall score.
- `routing_risk_score`: Routing-specific risk subscore.
- `rpki_risk_score`: RPKI-specific risk subscore.

### Activity volume and prevalence

- `total_ipv4`: Estimated number of IPv4 addresses announced by the ASN.
- `observed_bad_ipv4_unique`: Number of unique IPv4 addresses from the ASN observed with malicious signals.
- `observed_bad_ipv4_weighted`: Weighted activity count across feeds. This can be higher than the unique count when the same ASN is seen repeatedly or in multiple sources.
- `abuse_ratio_unique_pct`: Percentage of the ASN IPv4 space covered by unique malicious observations.
- `abuse_ratio_weighted_pct`: Weighted version of the abuse ratio, taking repeated observations into account.

### Source coverage

- `distinct_feeds`: Number of distinct data feeds that contributed to the ASN assessment.
- `distinct_feed_families`: Number of distinct feed families represented in the ASN assessment.

### Operator context

- `operator_profile`: High-level operator profile used to interpret the ASN, such as access network, hosting, or bulletproof hosting.
- `operator_tags`: Additional operator tags that add context to the profile.

### Flags

- `spamhaus_asndrop_flag`: `1` if the ASN appears in Spamhaus ASN-DROP, otherwise `0`.
- `community_bad_asn_flag`: `1` if the ASN appears in a community-maintained bad ASN list, otherwise `0`.
- `known_scanner_flag`: `1` if the ASN is known for research or Internet-wide scanning activity, otherwise `0`.
- `ripe_rpki_partial_flag`: `1` if RIPEstat indicates partial RPKI coverage for the ASN, otherwise `0`.

### Feed-specific weighted signals

- `spamhaus_drop_ipv4_weighted`: Weighted IPv4 signal contribution coming from Spamhaus DROP-related data.
- `threatfox_ipport_recent_ipv4_weighted`: Weighted IPv4 signal contribution coming from recent ThreatFox IP:port observations.
- `urlhaus_recent_urls_ipv4_weighted`: Weighted IPv4 signal contribution coming from recent URLhaus URL observations.
- `openphish_feed_ipv4_weighted`: Weighted IPv4 signal contribution coming from OpenPhish feed observations.

### RIPE routing and visibility fields

- `ripe_first_seen_utc`: First time RIPEstat observed the ASN in routing data.
- `ripe_last_seen_utc`: Most recent time RIPEstat observed the ASN in routing data.
- `ripe_visibility_v4_pct`: IPv4 visibility percentage reported by RIPEstat.
- `ripe_announced_prefixes_v4`: Number of announced IPv4 prefixes seen for the ASN.
- `ripe_announced_ipv4`: Number of announced IPv4 addresses seen for the ASN.
- `ripe_observed_neighbours`: Number of observed neighbouring ASNs in routing data.

### RIPE RPKI fields

- `ripe_rpki_total_prefixes_v4`: Total IPv4 prefixes considered for RPKI analysis.
- `ripe_rpki_prefixes_checked_v4`: IPv4 prefixes actually checked for RPKI validation.
- `ripe_rpki_valid_prefixes_v4`: IPv4 prefixes with valid RPKI status.
- `ripe_rpki_invalid_asn_prefixes_v4`: IPv4 prefixes invalid because of ASN mismatch.
- `ripe_rpki_invalid_length_prefixes_v4`: IPv4 prefixes invalid because of prefix length mismatch.
- `ripe_rpki_invalid_prefixes_v4`: Total IPv4 prefixes with invalid RPKI status.
- `ripe_rpki_unknown_prefixes_v4`: IPv4 prefixes with unknown RPKI status.
- `ripe_rpki_coverage_pct_v4`: Percentage of IPv4 prefixes with RPKI coverage.

### Observation window

- `first_seen_utc`: First time the ASN was seen by this dataset within the recent observation window.
- `last_seen_utc`: Most recent time the ASN was seen by this dataset within the recent observation window.
- `runs_seen_30d`: Number of collection runs in the last 30 days where the ASN was present.
- `days_observed_30d`: Number of distinct days in the last 30 days where the ASN was observed.

## Example KQL usage

Replace `<ORG>`, `<REPO>`, and `<BRANCH>` with your repository values. This example loads only the columns used in the query, converts the ASN from `AS12345` to integer format, and joins it with a table that already contains a numeric ASN field.

```kusto
let watched_asns = materialize(
    externaldata(
        asn:string,
        description:string,
        maliciousness_score:int,
        confidence_score:int,
        category:string,
        recommended_action:string
    )
    [@"https://raw.githubusercontent.com/<ORG>/<REPO>/<BRANCH>/asn_lists/asn_reputation_nonzero.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | extend asn_number = toint(replace_string(asn, "AS", ""))
    | where maliciousness_score >= 60
    | project asn_number, asn, description, maliciousness_score, confidence_score, category, recommended_action
);

CommonSecurityLog
| where DestinationAsNumber in (watched_asns | project asn_number)
| join kind=leftouter watched_asns on $left.DestinationAsNumber == $right.asn_number
| project TimeGenerated, DeviceVendor, DeviceProduct, DestinationAsNumber, asn, description, maliciousness_score, confidence_score, category, recommended_action
```
