#!/usr/bin/env python3
"""
Spektr ATT&CK Coverage Analyzer
Adapted for Wazuh + ELK from original concept by @Antonlovesdnb
Queries Elasticsearch for Wazuh alert MITRE mappings and cross-references
against the full MITRE ATT&CK Enterprise framework.
"""

import json
import sys
import os
import requests
from datetime import datetime, timedelta, timezone
from urllib3.exceptions import InsecureRequestWarning
from dotenv import dotenv_values
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration — loaded from .env file or environment variables
config = dotenv_values(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

ELK_HOST = config.get("WAZUH_HOST", os.environ.get("WAZUH_HOST", "https://localhost:9200"))
ELK_USER = config.get("WAZUH_USER", os.environ.get("WAZUH_USER", "admin"))
ELK_PASS = config.get("WAZUH_PASS", os.environ.get("WAZUH_PASS", ""))
ATTACK_JSON = config.get("ATTACK_JSON", os.environ.get("ATTACK_JSON", "./enterprise-attack.json"))
DAYS = int(config.get("DAYS", os.environ.get("DAYS", "30")))
INDEX = "wazuh-alerts-4.x-*"

def get_wazuh_mitre_coverage(days=30):
    """Query ELK for all MITRE techniques seen in Wazuh alerts"""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": since
                }
            }
        },
        "aggs": {
            "mitre_tactics": {
                "terms": {
                    "field": "rule.mitre.tactic",
                    "size": 50
                }
            },
            "mitre_techniques": {
                "terms": {
                    "field": "rule.mitre.id",
                    "size": 500
                }
            },
            "top_rules": {
                "terms": {
                    "field": "rule.id",
                    "size": 20
                },
                "aggs": {
                    "rule_description": {
                        "terms": {
                            "field": "rule.description",
                            "size": 1
                        }
                    }
                }
            }
        }
    }
    
    response = requests.post(
        f"{ELK_HOST}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(ELK_USER, ELK_PASS),
        verify=False
    )
    
    data = response.json()
    
    techniques = {}
    for bucket in data.get("aggregations", {}).get("mitre_techniques", {}).get("buckets", []):
        techniques[bucket["key"]] = bucket["doc_count"]
    
    tactics = {}
    for bucket in data.get("aggregations", {}).get("mitre_tactics", {}).get("buckets", []):
        tactics[bucket["key"]] = bucket["doc_count"]
    
    rules = []
    for bucket in data.get("aggregations", {}).get("top_rules", {}).get("buckets", []):
        desc = ""
        if bucket.get("rule_description", {}).get("buckets"):
            desc = bucket["rule_description"]["buckets"][0]["key"]
        rules.append({
            "id": bucket["key"],
            "count": bucket["doc_count"],
            "description": desc
        })
    
    return techniques, tactics, rules

def load_attack_framework(path):
    """Load and parse MITRE ATT&CK enterprise framework"""
    with open(path) as f:
        data = json.load(f)
    
    techniques = {}
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        
        if not tech_id:
            continue
            
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        
        techniques[tech_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "description": obj.get("description", "")[:200]
        }
    
    return techniques

def generate_report(covered, all_techniques, tactics, top_rules, days):
    """Generate coverage report"""
    total = len(all_techniques)
    covered_count = len(covered)
    coverage_pct = (covered_count / total * 100) if total > 0 else 0
    
    # Group uncovered by tactic
    uncovered = {k: v for k, v in all_techniques.items() if k not in covered}
    
    tactic_coverage = {}
    for tech_id, tech_data in all_techniques.items():
        for tactic in tech_data["tactics"]:
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = {"total": 0, "covered": 0}
            tactic_coverage[tactic]["total"] += 1
            if tech_id in covered:
                tactic_coverage[tactic]["covered"] += 1

    report = []
    report.append("=" * 60)
    report.append("SPEKTR SECURITY LAB — MITRE ATT&CK COVERAGE REPORT")
    report.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    report.append(f"Lookback: {days} days")
    report.append("=" * 60)
    report.append("")
    report.append(f"OVERALL COVERAGE: {covered_count}/{total} techniques ({coverage_pct:.1f}%)")
    report.append("")
    report.append("COVERAGE BY TACTIC:")
    for tactic, counts in sorted(tactic_coverage.items()):
        pct = (counts["covered"] / counts["total"] * 100) if counts["total"] > 0 else 0
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        report.append(f"  {tactic:<35} [{bar}] {pct:.0f}%")
    
    report.append("")
    report.append("TOP 20 FIRING RULES (last 30 days):")
    for rule in top_rules[:20]:
        report.append(f"  Rule {rule['id']:>6} | {rule['count']:>6} alerts | {rule['description'][:50]}")
    
    report.append("")
    report.append(f"COVERED TECHNIQUES ({covered_count}):")
    for tech_id in sorted(covered.keys()):
        tech = all_techniques.get(tech_id, {})
        report.append(f"  {tech_id:<12} {covered[tech_id]:>6} alerts | {tech.get('name', 'Unknown')}")
    
    report.append("")
    report.append(f"COVERAGE GAPS — NOT DETECTED ({len(uncovered)} techniques):")
    report.append("  Focus areas for detection improvement:")
    
    # Group gaps by tactic
    gaps_by_tactic = {}
    for tech_id, tech_data in uncovered.items():
        for tactic in tech_data["tactics"]:
            if tactic not in gaps_by_tactic:
                gaps_by_tactic[tactic] = []
            gaps_by_tactic[tactic].append(f"{tech_id} - {tech_data['name']}")
    
    for tactic in sorted(gaps_by_tactic.keys()):
        report.append(f"\n  [{tactic.upper()}]")
        for tech in sorted(gaps_by_tactic[tactic])[:10]:
            report.append(f"    ✗ {tech}")
        if len(gaps_by_tactic[tactic]) > 10:
            report.append(f"    ... and {len(gaps_by_tactic[tactic]) - 10} more")
    
    return "\n".join(report)

if __name__ == "__main__":
    days = int(sys.argv[1]) if len(sys.argv) > 1 else DAYS
    
    print(f"[*] Querying Wazuh alerts from last {days} days...")
    covered_techniques, active_tactics, top_rules = get_wazuh_mitre_coverage(days)
    print(f"[*] Found {len(covered_techniques)} MITRE techniques in alerts")
    
    print("[*] Loading ATT&CK framework...")
    all_techniques = load_attack_framework(ATTACK_JSON)
    print(f"[*] Loaded {len(all_techniques)} ATT&CK techniques")
    
    print("[*] Generating report...")
    report = generate_report(covered_techniques, all_techniques, active_tactics, top_rules, days)
    
    # Save report
    filename = f"attack_coverage_{datetime.now(timezone.utc).strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    
    print(report)
    print(f"\n[*] Report saved to {filename}")
