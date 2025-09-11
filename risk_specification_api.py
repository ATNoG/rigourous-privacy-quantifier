from risk_specification import RiskSpecification
import requests

class RiskSpecificationApi:
    _endpoint: str
    _timeout: int

    def __init__(self, endpoint: str, timeout: int):
        self._endpoint = endpoint
        self._timeout = timeout

    def send_risk_specification(self, risk_specification: RiskSpecification) -> bool:
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self._endpoint, headers=headers, json=risk_specification.model_dump_json())
            return response.ok
        except:
            return False
