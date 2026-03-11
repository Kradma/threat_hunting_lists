# Umbrella Top Domains for Threat Hunting

This repository provides automated datasets extracted from the [Cisco Umbrella Top 1M list](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip). 

To facilitate efficient ingestion and processing across different security platforms (such as Microsoft Defender and Microsoft Sentinel), the original dataset is segmented into multiple files based on strict size and line constraints. This ensures compatibility with external data operators and indicator limits without truncating individual domain records.

## Data Source
The datasets are programmatically derived from:
- [Cisco Umbrella Top 1M](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip)

## File Information

The following files are generated and updated automatically:

* **`top-1m.csv`**: The complete, uncompressed dataset containing the full 1 million top domains.
* **`top_10000_domains.csv`**: A strict cut of the top 10,000 domains. Ideal for environments with tight custom indicator limits (e.g., Microsoft Defender Custom Network Indicators).
* **`top-850kb.csv`**: A size-constrained version (~850 KB). Optimized for rapid querying and minimal memory footprint.
* **`top-1mb.csv`**: A size-constrained version (~1 MB).
* **`top-10mb.csv`**: A size-constrained version (~10 MB). Allows for broader hunting coverage while remaining well below the maximum payload limits of external data operators (such as KQL's `externaldata`).

**Data Format:**
All files are strictly formatted as CSV without headers. Each row consists of:
1.  `Rank`: The position of the domain based on DNS traffic volume.
2.  `Domain`: The fully qualified domain name (FQDN).

## Usage Contexts
These datasets are designed for:
* **Threat Hunting & KQL Queries**: Ingesting via the `externaldata` operator in Microsoft Defender Advanced Hunting or Microsoft Sentinel to filter out known-good or noisy baseline traffic.
* **SIEM Watchlists**: Populating static lookup tables for rapid log enrichment or allowlisting.
* **Cybersecurity Research**: Analyzing domain popularity trends and establishing baseline traffic metrics.

## License
This dataset is provided as-is and should be used in compliance with the original data provider's (Cisco Umbrella) terms of service.

## Contributions
Contributions and logic optimizations are welcome. Feel free to open an issue or submit a pull request if you have improvements or additional operational insights.
