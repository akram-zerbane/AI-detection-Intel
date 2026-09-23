from datetime import timedelta
from elasticsearch import Elasticsearch
from agent.schemas import CalderaExecutionPayload, DetectionLogArtifact, SigmaRuleOutput, RuleRefineRequest
from typing import List

class ElasticService:
    def __init__(self, es_url: str, api_key: str = None, username: str = None, password: str = None):
        if api_key:
            self.client = Elasticsearch(es_url, api_key=api_key)
        elif username and password:
            self.client = Elasticsearch(es_url, basic_auth=(username, password))
        else:
            self.client = Elasticsearch(es_url)

    def fetch_attack_telemetry(self, payload: CalderaExecutionPayload, buffer_seconds: int = 15) -> List[DetectionLogArtifact]:
        # Add buffer window to account for log shipping latency
        time_from = (payload.start_time - timedelta(seconds=buffer_seconds)).isoformat()
        time_to = (payload.end_time + timedelta(seconds=buffer_seconds)).isoformat()

        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_from,
                                "lte": time_to
                            }
                        }
                    }
                ],
                "should": [
                    {"term": {"host.hostname": payload.target_host}},
                    {"term": {"winlog.computer_name": payload.target_host}},
                    {"term": {"agent.name": payload.target_host}}
                ],
                "minimum_should_match": 1
            }
        }

        response = self.client.search(
            index=["sysmon-*", "suricata-*", "winlogbeat-*"],
            query=query,
            size=100
        )

        artifacts: List[DetectionLogArtifact] = []
        for hit in response["hits"]["hits"]:
            src = hit["_source"]
            artifacts.append(
                DetectionLogArtifact(
                    event_id=src.get("winlog", {}).get("event_id"),
                    image=src.get("process", {}).get("executable") or src.get("winlog", {}).get("event_data", {}).get("Image"),
                    command_line=src.get("process", {}).get("command_line") or src.get("winlog", {}).get("event_data", {}).get("CommandLine"),
                    parent_image=src.get("process", {}).get("parent", {}).get("executable") or src.get("winlog", {}).get("event_data", {}).get("ParentImage"),
                    network_destination=src.get("destination", {}).get("ip"),
                    raw_log=src
                )
            )
        return artifacts
