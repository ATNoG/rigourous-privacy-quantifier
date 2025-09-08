from pydantic import BaseModel, Field
import json

class Anomaly(BaseModel):
    cve_id: str
    cpe: str
    description: str
    cvss31_vector_string: str
    base_score: float
    base_severity: str
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str

class RiskScore(BaseModel):
    anomalies: list[Anomaly] = Field(alias="anomalies--1", default=[])

class TraMessage(BaseModel):
    type: str | None = None
    spec_version: str | None = None
    id: str | None = None
    created: str | None = None
    modified: str | None = None
    risk_score: RiskScore | None = Field(alias="risk-score", default=None)

    @classmethod
    def from_str(cls, message: str) -> "TraMessage | None":
        try:
            # sometimes the message is encoded twice so we need to decode twice as well
            data = json.loads(message)
            if type(data) == str:
                data = json.loads(data)

            # print(f"Parsed message: {str(data)[:100] + ' ...'}", flush=True)
            return TraMessage(**data)
        except Exception as e:
            # print(f"Failed to parse message: {e}", flush=True)
            return None
