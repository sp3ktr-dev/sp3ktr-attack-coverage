# Sp3ktr ATT&CK Coverage Analyzer

A command-line tool that cross-references your Wazuh SIEM alert data against the full MITRE ATT&CK Enterprise framework to identify detection coverage and gaps.

Adapted for Wazuh + Elasticsearch from the original concept by @Antonlovesdnb.

## What It Does

- Queries your Wazuh indexer for all alerts over a configurable lookback period
- Extracts MITRE ATT&CK technique IDs from Wazuh rule mappings
- Cross-references against the full MITRE ATT&CK Enterprise framework
- Generates a coverage report showing overall coverage percentage, coverage by tactic, top firing rules, covered techniques, and gap analysis by tactic

## Requirements

Python 3.8+, Wazuh 4.x, pip install requests python-dotenv

## Setup

1. Clone the repo
2. Download enterprise-attack.json from MITRE CTI GitHub
3. Copy .env.example to .env and fill in your credentials
4. Run: python3 attack_coverage.py 30

## Stack

Wazuh 4.x, OpenSearch, Suricata, Zeek, ELK Stack

## Credit

Adapted from original concept by @Antonlovesdnb

## License

MIT
