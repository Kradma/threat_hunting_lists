# Top 10,000 Domains

This repository contains a dataset of the top 10,000 domains extracted from the [Umbrella Top 1M list](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip). The data is updated periodically and serves as a reference for domain analysis, security research, and general web insights.

Additionally, a **850KB version** of the dataset has been generated from the resource: [TOP1M Domains](https://github.com/mthcht/awesome-lists/tree/main/Lists/Domains/TOP1M). This reduced version allows for easier handling in **Microsoft Sentinel** and other security tools without performance issues.

## Data Source
The dataset is based on:
- [Umbrella Top 1M](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip)
- [TOP1M Domains](https://github.com/mthcht/awesome-lists/tree/main/Lists/Domains/TOP1M)

## File Information
- **`top_10000_domains.csv`**: A CSV file containing the top 10,000 domains ranked by popularity.
- **`top_domains_850KB.csv`**: A reduced version (~850KB) for efficient processing in security platforms like Sentinel.
- Each row consists of:
  - `Rank`: The position of the domain based on traffic.
  - `Domain`: The domain name.

## Usage
This dataset can be used for:
- Web analytics and research.
- Cybersecurity and threat intelligence.
- Filtering and allowlisting domains.
- Efficient ingestion in **Microsoft Sentinel** and similar platforms.

## License
This dataset is provided as-is and should be used in compliance with the original data provider's terms.

## Contributions
Contributions and suggestions are welcome! Feel free to open an issue or submit a pull request if you have improvements or additional insights.

