from models.priv_guide_report import PrivGuideReport
from pydantic import BaseModel
from pathlib import Path
import json

class Config(BaseModel):
    # kafka
    kafka_ca_cert: Path
    kafka_address: str
    kafka_security_protocol: str
    kafka_topic: str
    kafka_sasl_mechanism: str
    kafka_sasl_plain_username: str
    kafka_sasl_plain_password: str
    kafka_auto_offset_reset: str

    # skynet
    skynet_token: str
    skynet_model: str
    skynet_instance_count: int
    skynet_timeout: int
    skynet_max_runs: int

    # risk_specification_api
    risk_specification_api_endpoint: str
    risk_specification_api_timeout: int

    # privacy guide report
    priv_guide_report: PrivGuideReport

    @classmethod
    def from_config_path(cls, str_path: str, priv_guide_report: PrivGuideReport) -> "Config | None":
        try:
            path = Path(str_path)
            final = {}

            # get the certificate file
            final["kafka_ca_cert"] = path / "ca-cert.pem"
            if not final["kafka_ca_cert"].exists():
                return None

            # get random configs
            with (path / "config.json").open() as f:
                json_data = json.load(f)
                for category in json_data:
                    for value_key in json_data[category]:
                        final.update({f"{category}_{value_key}": json_data[category][value_key]})

            final["priv_guide_report"] = priv_guide_report
            return cls(**final)
        except:
            return None
