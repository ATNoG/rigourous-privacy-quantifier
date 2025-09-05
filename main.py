from risk_specification_api import RiskSpecificationApi
from kafka import KafkaConsumer, KafkaAdminClient
from risk_specification import RiskSpecification
from tra_message import TraMessage
import logging, random, string
from config import Config

# debug fn
def get_topics(config: Config):
    client = KafkaAdminClient (
        bootstrap_servers   = config.kafka_address,
        security_protocol   = config.security_protocol,
        ssl_cafile          = config.ca_cert,
        sasl_mechanism      = config.sasl_mechanism,
        sasl_plain_username = config.sasl_plain_username,
        sasl_plain_password = config.sasl_plain_password,
    )

    print(client.list_topics())
    client.close()

def _init_kafka(config: Config) -> KafkaConsumer:
    group_id           = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    enable_auto_commit = True

    consumer = KafkaConsumer (
        config.kafka_topic,
        bootstrap_servers   = config.kafka_address,
        security_protocol   = config.security_protocol,
        ssl_cafile          = config.ca_cert,
        sasl_mechanism      = config.sasl_mechanism,
        sasl_plain_username = config.sasl_plain_username,
        sasl_plain_password = config.sasl_plain_password,
        auto_offset_reset   = config.auto_offset_reset,
        group_id            = group_id,
        enable_auto_commit  = enable_auto_commit
    )

    print(f"Kafka consumer topics: {consumer.topics()}")
    return consumer

def _receive_kafka_messages(config: Config, consumer: KafkaConsumer):
    try:
        logging.info(f'Subscribed to topic: {config.kafka_topic}')
        print(f'Subscribed to topic: {config.kafka_topic}', flush=True)

        # process every kafka message
        counter = 0
        for message in consumer:
            logging.info(f"Received message: {message.value.decode('utf-8')}")
            print(f"Received message: {message.value.decode('utf-8')}", flush=True)

            successful_send = _send_risk_specification(config, message.value.decode('utf-8'))
            if successful_send:
                logging.info("Successfully sent risk specification")
                print(f"Successfully sent risk specification", flush=True)

            # for tests only
            counter += 1
            if counter >= 999999999999999:
                exit(0)

            print()

    except KeyboardInterrupt:
        logging.error("Process interrupted by user")
        print("Process interrupted by user")
    except Exception as e:
        logging.error(f"Failed to receive message: {e}")
        print(f"Failed to receive message: {e}")
    finally:
        consumer.close()

def _send_risk_specification(config: Config, message: str) -> bool:
    tra_message = TraMessage.from_str(message)
    if not tra_message:
        return False

    risk_specification = RiskSpecification.from_tra_message(config, tra_message)
    if not risk_specification:
        return False

    return RiskSpecificationApi(config.risk_specification_api_endpoint).send_risk_specification(risk_specification)

def main(config: Config):
    # kafka_topic = "R12-AID-TRA" # kafka_topic = "test_kafka"
    kafka_topic = "R13-AID"
    # kafka_topic = "MTD-AID"
    # kafka_topic = "testing123"

    config.kafka_topic = kafka_topic
    consumer = _init_kafka(config)
    _receive_kafka_messages(config, consumer)

if __name__ == "__main__":
    config = Config.from_config_path("config/")
    if not config:
        print("Could not build config from config directory.")
        exit(1)

    get_topics(config)
    main(config)
