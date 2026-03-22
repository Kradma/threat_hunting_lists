# TLDs

This folder contains a published list of top-level domains (TLDs) associated with elevated phishing risk based on the latest Cybercrime Information Center (CCIC) TLD ranking.

This dataset is based on the work of [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists/tree/main/Lists/TLDs), with additional normalization and documentation to make the CSV easier to consume directly from GitHub and KQL.

## Published file

- `latest_ccic_tlds.csv`: latest CCIC TLD phishing dataset in a compact operational CSV format.

## What the list is used for

- Enrich DNS, proxy, email, and web telemetry with TLD risk context.
- Prioritize triage when a domain belongs to a TLD with a high phishing domain score.
- Build watchlists, detections, or soft-blocking logic around higher-risk TLDs.

## CSV fields

- `dest_nt_domain`: normalized TLD value in wildcard format, for example `*.xin` or `*.icu`.
- `metadata_rank`: position of the TLD in the current CCIC phishing domain score ranking. `1` is the highest-risk entry in the list.
- `metadata_domains_count`: number of delegated or managed domains reported for that TLD in the current CCIC period.
- `metadata_phishing_domains_count`: phishing-domain count aligned to the same report period and normalized for this CSV.
- `metadata_phishing_domain_score`: CCIC phishing domain score for the TLD. Higher values indicate a higher concentration of phishing relative to the size of the TLD. CCIC defines this score as phishing domains per 10,000 delegated domains.

## Example KQL usage

Replace `<ORG>`, `<REPO>`, and `<BRANCH>` with your repository values. This example loads the published CSV from GitHub, extracts the last label from the observed domain, converts it to the same wildcard format used by the CSV, and joins the event with the TLD list.

```kusto
let ccic_tlds = materialize(
    externaldata(
        dest_nt_domain:string,
        metadata_rank:int,
        metadata_domains_count:long,
        metadata_phishing_domains_count:long,
        metadata_phishing_domain_score:real
    )
    [@"https://raw.githubusercontent.com/<ORG>/<REPO>/<BRANCH>/TLDs/latest_ccic_tlds.csv"]
    with (format="csv", ignoreFirstRecord=true)
);

DnsEvents
| where isnotempty(Name)
| extend observed_tld = strcat("*.", tostring(split(tolower(Name), ".")[-1]))
| join kind=inner ccic_tlds on $left.observed_tld == $right.dest_nt_domain
| project TimeGenerated, Name, observed_tld, metadata_rank, metadata_domains_count, metadata_phishing_domains_count, metadata_phishing_domain_score
| order by metadata_phishing_domain_score desc
```
