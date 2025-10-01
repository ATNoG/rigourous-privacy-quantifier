from models import Config
import requests

class RiskSpecificationApi:
    _endpoint: str
    _timeout: int

    def __init__(self, config: Config):
        self._endpoint = config.risk_specification_api_endpoint
        self._timeout = config.risk_specification_api_timeout

    def send_risk_data(self, risk_data: dict) -> bool:
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self._endpoint, headers=headers, json=risk_data)
            return response.ok
        except:
            return False
