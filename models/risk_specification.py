from models.tra_message import Anomaly, TraMessage
from cvss_to_priv import compute_privacy_score
from models.config import Config
from pydantic import BaseModel
import json

class RiskSpecification(BaseModel):
    cpe: str
    anomalies: list[Anomaly]

    @classmethod
    def from_tra_message(cls, tra_message: TraMessage) -> "RiskSpecification | None":
        if not tra_message.risk_score or not tra_message.risk_score.anomalies or not tra_message.risk_score.anomalies[0].cpe:
            return None

        data = {"cpe": tra_message.risk_score.anomalies[0].cpe, "anomalies": tra_message.risk_score.anomalies}
        return RiskSpecification(**data)

    def get_risk_data(self, config: Config) -> dict | None:
        scores = self._calculate_scores(config)
        if scores == None:
            return None

        data = json.loads(self.model_dump_json())
        data.update({"risk_score": scores[0], "privacy_score": scores[1]})
        return data

    # TODO: even if just a single risk score is calculated, this still reports success. what should the threshold be
    #       for the result to be considered a success??
    def _calculate_scores(self, config: Config) -> tuple[float, float] | None:
        risk_score = 0.0
        privacy_score = 0.0
        calculated_score = False
        for anomaly in self.anomalies:
            risk_score += anomaly.base_score

            priv_score = compute_privacy_score(config, anomaly.cvss31_vector_string)
            if type(priv_score) == float:
                privacy_score += priv_score
                calculated_score = True

        return (risk_score / len(self.anomalies), privacy_score / len(self.anomalies)) if calculated_score else None
