from pydantic import BaseModel
from pathlib import Path
import json

class Config(BaseModel):
    ca_cert: Path
    kafka_address: str
    security_protocol: str
    kafka_topic: str
    sasl_mechanism: str
    sasl_plain_username: str
    sasl_plain_password: str
    risk_specification_api_endpoint: str
    auto_offset_reset: str
    skynet_token: str

    @classmethod
    def from_config_path(cls, str_path: str) -> "Config | None":
        try:
            path = Path(str_path)
            final = {}

            # get the certificate file
            final["ca_cert"] = path / "ca-cert.pem"
            if not final["ca_cert"].exists():
                return None

            # get random configs
            with (path / "config.json").open() as f:
                json_data = json.load(f)
                final.update(json_data["kafka"])
                final.update({"risk_specification_api_endpoint": json_data["risk_specification_api_endpoint"]})
                final.update(json_data["skynet"])

            return cls(**final)
        except:
            return None
