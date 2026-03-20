# ASN Lists

This folder contains the ASN reputation dataset. The top-level CSV files are published for GitHub consumption, while local-only implementation assets for the builder live under this same directory tree.

## Published files

- `asn_reputation.csv`: full dataset.
- `asn_reputation_nonzero.csv`: same schema, filtered to rows where `maliciousness_score > 0`.

The CSV files published in this folder do not include the comment lines from the native export, so they can be loaded with `externaldata()` in KQL without any extra preprocessing.

## How to interpret the results

- `asn`: ASN in `AS12345` format.
- `description`: operator name or public ASN description.
- `maliciousness_score`: operational score from 0 to 100. The higher it is, the stronger the signal of malicious activity or sustained abuse.
- `confidence_score`: confidence level for that assessment. It helps distinguish strong signals from weak or low-persistence observations.
- `category`: primary classification. The most actionable values are usually `hard_block`, `malicious_infrastructure`, `high_risk_abused_hosting`, and `high_risk_access_network_abuse`.
- `recommended_action`: suggested operational handling for that ASN.
- `observed_bad_ipv4_unique`: number of unique IPv4 addresses observed with malicious signals, deduplicated across feeds.
- `observed_bad_ipv4_weighted`: aggregated signal intensity across feeds. It can be higher than the `unique` metric.
- `abuse_ratio_unique_pct`: estimated percentage of the ASN IPv4 space with unique observed signal.
- `distinct_feeds` and `distinct_feed_families`: how many sources and source families support the classification.
- `operator_profile` and `operator_tags`: operator context to help interpret the result.
- `spamhaus_asndrop_flag`: the ASN appears in Spamhaus ASN-DROP.
- `community_bad_asn_flag`: the ASN appears in a community-maintained risk list.
- `known_scanner_flag`: ASN known for research scanning activity; it does not always imply malicious behavior.
- `ripe_*`: additional routing and RPKI context from RIPEstat.
- `first_seen_utc`, `last_seen_utc`, `runs_seen_30d`, and `days_observed_30d`: temporal persistence of the signal.
- `reasons`: short textual summary explaining why the ASN was classified that way.

## Quick usage guidance

- For broad investigations, use `asn_reputation.csv`.
- For detections, enrichment, or soft-block lists, `asn_reputation_nonzero.csv` is usually the better starting point.
- If you need a stricter list, filter on `maliciousness_score >= 60` or on specific categories.
- If your telemetry stores ASN as a number, convert `AS12345` to integer with `toint(replace_string(asn, "AS", ""))`.

## KQL: load the CSV from GitHub

Replace `<ORG>`, `<REPO>`, and the branch name if you do not use `main`.

```kusto
let asn_nonzero = externaldata(
    asn:string,
    description:string,
    total_ipv4:long,
    observed_bad_ipv4_unique:long,
    observed_bad_ipv4_weighted:long,
    abuse_ratio_unique_pct:real,
    abuse_ratio_weighted_pct:real,
    distinct_feeds:int,
    distinct_feed_families:int,
    maliciousness_score:int,
    confidence_score:int,
    category:string,
    operator_profile:string,
    operator_tags:string,
    recommended_action:string
)
[@"https://raw.githubusercontent.com/<ORG>/<REPO>/main/asn_lists/asn_reputation_nonzero.csv"]
with (format="csv", ignoreFirstRecord=true);

asn_nonzero
| extend asn_number = toint(replace_string(asn, "AS", ""))
| where maliciousness_score >= 60
| project asn, asn_number, maliciousness_score, confidence_score, category, recommended_action
| order by maliciousness_score desc
```

## KQL: use it as a list in a query

Generic example to join the list with a table that already contains a numeric ASN field. Replace `DestinationAsNumber` with the ASN field used in your table.

```kusto
let watched_asns = materialize(
    externaldata(
        asn:string,
        description:string,
        total_ipv4:long,
        observed_bad_ipv4_unique:long,
        observed_bad_ipv4_weighted:long,
        abuse_ratio_unique_pct:real,
        abuse_ratio_weighted_pct:real,
        distinct_feeds:int,
        distinct_feed_families:int,
        maliciousness_score:int,
        confidence_score:int,
        category:string,
        operator_profile:string,
        operator_tags:string,
        recommended_action:string
    )
    [@"https://raw.githubusercontent.com/<ORG>/<REPO>/main/asn_lists/asn_reputation_nonzero.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | extend asn_number = toint(replace_string(asn, "AS", ""))
    | where maliciousness_score >= 60
    | project asn_number, category, recommended_action
);

CommonSecurityLog
| where DestinationAsNumber in (watched_asns | project asn_number)
| join kind=leftouter watched_asns on $left.DestinationAsNumber == $right.asn_number
| project TimeGenerated, DeviceVendor, DeviceProduct, DestinationAsNumber, category, recommended_action
```

## Operational note

Local-only process artifacts (`output/`, cache, logs, tests, builder script) also live under this directory tree but are ignored by Git. The published files intended for GitHub and KQL consumption remain the top-level `README.md`, `asn_reputation.csv`, and `asn_reputation_nonzero.csv`.
