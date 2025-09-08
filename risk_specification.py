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

        # print(tra_message.risk_score)
        scores = RiskSpecification._calculate_scores(config, tra_message.risk_score.anomalies)
        if scores == None:
            return None

        data = {}
        data["cpe"]           = tra_message.risk_score.anomalies[0].cpe
        data["anomalies"]     = tra_message.risk_score.anomalies
        data["risk_score"]    = scores[0]
        data["privacy_score"] = scores[1]
        return RiskSpecification(**data)

    @classmethod
    def _calculate_scores(cls, config: Config, anomalies: list[Anomaly]) -> tuple[float, float] | None:
        risk_score = 0.0
        privacy_score = 0.0
        calculated_score = False
        for anomaly in anomalies:
            if anomaly.base_score:
                risk_score += anomaly.base_score

            if anomaly.cvss31_vector_string:
                score = compute_privacy_score(config, anomaly.cvss31_vector_string)
                if score == None:
                    print("Failed to compute the privacy score")
                    continue

                privacy_score += score
                calculated_score = True

        return (risk_score / len(anomalies), privacy_score / len(anomalies)) if calculated_score else None
