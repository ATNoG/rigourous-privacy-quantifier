from models.priv_guide_report import PrivGuideReport
from models.config import Config
from kafka import KafkaProducer
import json, logging

def send_message_kafka(producer: KafkaProducer, topic: str, key: bytes, value: bytes):
    try:
        producer.send(topic, key=key.decode('utf-8'), value=value.decode('utf-8'))
        producer.flush() # ensure all messages are sent

        logging.info(f"Message sent to topic '{topic}' with key '{key}' and value '{value}'")
        print(f"Message sent to topic '{topic}' with key '{key}' and value '{value}'")
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
        print(f"Failed to send message: {e}")

def main():
    priv_guide_report = PrivGuideReport.from_file_path("priv_guide_report_examples/example0.json")
    if not priv_guide_report:
        print("Could not parse priv guide report.")
        exit(1)

    config = Config.from_config_path("config/", priv_guide_report)
    if not config:
        print("Could not build config from config directory.")
        exit(1)

    kafka_topic = "testing123"
    producer = KafkaProducer(
        bootstrap_servers=config.kafka_address,
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda v: json.dumps(v).encode('utf-8'),
        ssl_cafile=config.kafka_ca_cert,
        ssl_check_hostname=False,
        security_protocol=config.kafka_security_protocol,
        sasl_mechanism=config.kafka_sasl_mechanism,
        sasl_plain_username=config.kafka_sasl_plain_username,
        sasl_plain_password=config.kafka_sasl_plain_password
    )

    data = {
        "type": "risk_score",
        "version": "2.1",
        "id": "bundle--cd2a2cf9-18f3-480a-aaa5-c4b59ce6910b",
        "created": "2025-06-13 07:22:26.520353553",
        "modified": "2025-06-13 07:22:26.520357255",
        "risk-score": {
            "anomalies--1": [
                {
                    "cve_id": "CVE-2022-41763",
                    "cpe": "cpe:2.3:a:nokia:access_management_system:9.7.05:*:*:*:*:*:*:*",
                    "description": "An issue was discovered in NOKIA AMS 9.7.05. Remote Code Execution exists via the debugger of the ipAddress variable. A remote user, authenticated to the AMS server, could inject code in the PING function. The privileges of the command executed depend on the user that runs the service.",
                    "cvss31_vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    "base_score": 8.8,
                    "base_severity": "HIGH",
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "LOW",
                    "user_interaction": "NONE",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH"
                }
            ]
        }
    }

    message_key = b"RIGOUROUS-key"
    message_value = json.dumps(data)
    send_message_kafka(producer, kafka_topic, message_key, message_value.encode('utf-8'))
    producer.close()

if __name__ == "__main__":
    main()
