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

    @classmethod
    def from_config_path(cls, str_path: str) -> "Config | None":
        try:
            path = Path(str_path)
            final = {}

            # get the certificate file
            final["ca_cert"] = path / "ca-cert.pem"
            if not final["ca_cert"].exists():
                return None

            # get the kafka configs
            with (path / "config.json").open() as f:
                final.update(json.load(f)["kafka"])

            return cls(**final)
        except:
            return None
