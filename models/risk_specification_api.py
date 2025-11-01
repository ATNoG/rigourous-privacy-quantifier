from models.config import Config
import requests

# TODO: would it be useful to have a "risk specification" pydantic model to check the validity of the data before sending?
class RiskSpecificationApi:
    _endpoint: str
    _timeout: int

    def __init__(self, config: Config):
        self._endpoint = config.risk_specification_api_endpoint
        self._timeout = config.risk_specification_api_timeout

    def send_risk_data(self, risk_data: dict) -> bool:
        try:
            # risk_data["cpe"] = "emqx"
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self._endpoint, headers=headers, json=risk_data)
            return response.ok
        except:
            return False
