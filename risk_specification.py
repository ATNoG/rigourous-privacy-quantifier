from cvss_to_priv import compute_privacy_score
from tra_message import Anomaly, TraMessage
from pydantic import BaseModel
from config import Config

class RiskSpecification(BaseModel):
    cpe: str
    risk_score: float
    privacy_score: float
    anomalies: list[Anomaly]

    @classmethod
    def from_tra_message(cls, config: Config, tra_message: TraMessage) -> "RiskSpecification | None":
        if not tra_message.risk_score or not tra_message.risk_score.anomalies or not tra_message.risk_score.anomalies[0].cpe:
            return None

        print(tra_message.risk_score)

        data = {}
        risk_score, privacy_score = RiskSpecification._calculate_scores(config, tra_message.risk_score.anomalies)

        data["cpe"]           = tra_message.risk_score.anomalies[0].cpe
        data["anomalies"]     = tra_message.risk_score.anomalies
        data["risk_score"]    = risk_score
        data["privacy_score"] = privacy_score
        return RiskSpecification(**data)

    @classmethod
    def _calculate_scores(cls, config: Config, anomalies: list[Anomaly]) -> tuple[float, float]:
        risk_score = 0.0
        privacy_score = 0.0
        for anomaly in anomalies:
            if anomaly.base_score:
                risk_score += anomaly.base_score

            if anomaly.cvss31_vector_string:
                privacy_score += compute_privacy_score(config, anomaly.cvss31_vector_string)

        return (risk_score / len(anomalies), privacy_score / len(anomalies))
