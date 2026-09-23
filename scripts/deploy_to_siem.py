#!/usr/bin/env python3
import os
import sys
import yaml
import json
import argparse
import requests

from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows


def convert_sigma_to_query(rule_path: str) -> tuple[dict, str]:
    """Parse a Sigma rule and convert its selection logic to an ECS Lucene query string."""
    with open(rule_path, "r", encoding="utf-8") as f:
        rule_yaml = yaml.safe_load(f)

    # Ingest into pySigma collection
    collection = SigmaCollection.load_ruleset([rule_path])

    # Convert condition to Lucene query mapped to Windows Elastic Common Schema (ECS)
    backend = LuceneBackend(ecs_windows())
    queries = backend.convert(collection)

    if not queries:
        raise ValueError(f"Could not convert rule {rule_path}")

    return rule_yaml, queries[0]


def deploy_rule_to_kibana(rule_meta: dict, query_str: str, kibana_url: str, api_key: str):
    """Deploy or update a detection rule via the Kibana Detection Engine API."""
    rule_id = rule_meta.get("id")
    endpoint = f"{kibana_url.rstrip('/')}/api/detection_engine/rules"

    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
    }

    # Map Sigma schema to Kibana Rule Definition
    payload = {
        "rule_id": rule_id,
        "name": rule_meta.get("title"),
        "description": rule_meta.get("description", "Automated Detection as Code Rule"),
        "severity": rule_meta.get("level", "medium").lower(),
        "risk_score": 50,
        "type": "query",
        "query": query_str,
        "language": "kuery",
        "index": ["winlogbeat-*", "logs-endpoint.events.*"],
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "tags": rule_meta.get("tags", []),
        "false_positives": rule_meta.get("falsepositives", []),
    }

    resp = requests.post(endpoint, headers=headers, json=payload, timeout=30)

    if resp.status_code == 200:
        print(f"[+] Rule created successfully in Kibana: {rule_meta.get('title')}")
    elif resp.status_code == 409:
        print(f"[*] Rule '{rule_id}' already exists. Patching existing rule...")
        patch_endpoint = f"{endpoint}?rule_id={rule_id}"
        patch_payload = {k: v for k, v in payload.items() if k not in ["rule_id", "type"]}
        update_resp = requests.patch(patch_endpoint, headers=headers, json=patch_payload, timeout=30)
        if update_resp.status_code == 200:
            print(f"[+] Rule updated successfully: {rule_meta.get('title')}")
        else:
            print(f"[!] Failed to update rule: {update_resp.status_code} - {update_resp.text}")
            sys.exit(1)
    else:
        print(f"[!] Kibana API deployment error: {resp.status_code} - {resp.text}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Convert and deploy Sigma rules to Kibana Detection Engine")
    parser.add_argument("--passed-file", default="passed_rules.txt", help="File listing passed rules")
    parser.add_argument("--prod-dir", default="rules/production", help="Directory for promoted rules")
    parser.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", "http://127.0.0.1:5601"))
    parser.add_argument("--api-key", default=os.getenv("KIBANA_API_KEY", "eU0xS3I2QUJwaUdVMWZHbzRsb2k6LWJCa1hCRDJUMWFya09yMHA0aUE4dw=="))
    args = parser.parse_args()

    if not os.path.exists(args.passed_file):
        print(f"[*] File '{args.passed_file}' not found. Nothing to deploy.")
        sys.exit(0)

    with open(args.passed_file, "r") as f:
        rule_paths = [line.strip() for line in f if line.strip()]

    if not rule_paths:
        print("[*] No passed rules listed in file. Skipping deployment.")
        sys.exit(0)

    os.makedirs(args.prod_dir, exist_ok=True)

    for path in rule_paths:
        if not os.path.exists(path):
            print(f"[!] Skipping non-existent path: {path}")
            continue

        print(f"[*] Processing rule: {path}")
        rule_meta, query_str = convert_sigma_to_query(path)
        print(f"    [+] Query generated: {query_str}")

        # Promote YAML file to production directory
        prod_target = os.path.join(args.prod_dir, os.path.basename(path))
        with open(prod_target, "w", encoding="utf-8") as out_f:
            yaml.dump(rule_meta, out_f, sort_keys=False)
        print(f"    [+] Promoted to: {prod_target}")

        # Push to Kibana if API Key is configured
        if args.api_key:
            deploy_rule_to_kibana(rule_meta, query_str, args.kibana_url, args.api_key)
        else:
            print("    [!] KIBANA_API_KEY not set. Converted and promoted locally without SIEM push.")


if __name__ == "__main__":
    main()
