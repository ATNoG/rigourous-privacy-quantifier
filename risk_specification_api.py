from risk_specification import RiskSpecification
import requests

class RiskSpecificationApi:
    _endpoint: str

    def __init__(self, endpoint: str):
        self._endpoint = endpoint

    def send_risk_specification(self, risk_specification: RiskSpecification) -> bool:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(self._endpoint, headers=headers, json=risk_specification.model_dump_json())
        return response.ok
