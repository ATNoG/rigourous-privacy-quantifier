from models.risk_specification_api import RiskSpecificationApi
from models.risk_specification import RiskSpecification
from models.priv_guide_report import PrivGuideReport
from kafka import KafkaConsumer, KafkaAdminClient
from models.tra_message import TraMessage
from models.config import Config
import logging, random, string

# debug fn
def get_topics(config: Config):
    client = KafkaAdminClient (
        bootstrap_servers   = config.kafka_address,
        security_protocol   = config.kafka_security_protocol,
        ssl_cafile          = config.kafka_ca_cert,
        sasl_mechanism      = config.kafka_sasl_mechanism,
        sasl_plain_username = config.kafka_sasl_plain_username,
        sasl_plain_password = config.kafka_sasl_plain_password,
    )

    print(client.list_topics())
    client.close()

def init_kafka(config: Config) -> KafkaConsumer:
    group_id           = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    enable_auto_commit = True

    consumer = KafkaConsumer (
        config.kafka_topic,
        bootstrap_servers   = config.kafka_address,
        security_protocol   = config.kafka_security_protocol,
        ssl_cafile          = config.kafka_ca_cert,
        sasl_mechanism      = config.kafka_sasl_mechanism,
        sasl_plain_username = config.kafka_sasl_plain_username,
        sasl_plain_password = config.kafka_sasl_plain_password,
        auto_offset_reset   = config.kafka_auto_offset_reset,
        group_id            = group_id,
        enable_auto_commit  = enable_auto_commit
    )

    # print all the the available kafka topics in a comma separated list
    kafka_consumer_topics = list(consumer.topics())
    print(f"Kafka consumer topics: {kafka_consumer_topics[0]}", end="")
    for i in range(1, len(kafka_consumer_topics)):
        print(f", {kafka_consumer_topics[i]}", end="")
    print()

    return consumer

def process_kafka_messages(config: Config, consumer: KafkaConsumer):
    inv_msg_counter = 0
    try:
        logging.info(f'Subscribed to topic: {config.kafka_topic}')
        print(f'Subscribed to topic: {config.kafka_topic}', flush=True)

        # process every kafka message
        for message in consumer:
            # logging.info(f"Received message: {message.value.decode('utf-8')}")
            # print(f"Received message: {message.value.decode('utf-8')[:80] + ' ...'}", flush=True)

            invalid_message = process_kafka_message(config, inv_msg_counter, message.value.decode('utf-8'))
            inv_msg_counter = inv_msg_counter + 1 if invalid_message else 0

            # if _send_risk_specification(config, message.value.decode('utf-8')):
            #     logging.info("Successfully sent risk specification")
            #     print(f"Successfully sent risk specification", flush=True)
            # else:
            #     msg_counter += 1
            #     print(f"\rFailed to create/send risk score for {msg_counter} message(s)", end="", flush=True)
            #     # logging.info("Failed to send risk specification")
            #     # print("Failed to send risk specification", flush=True)

    except KeyboardInterrupt:
        # logging.error("Process interrupted by user")
        print(f"{'\n' if inv_msg_counter > 0 else ''}\rProcess interrupted by user. Closing ...")
    except Exception as e:
        # logging.error(f"Failed to receive message: {e}")
        print(f"Failed to receive message: {e}")
    finally:
        consumer.close()

# TODO: a good idea would be to get some info about the problem and why it didn't work??
def process_kafka_message(config: Config, inv_msg_counter: int, message: str) -> bool:
    # build a TRA message object from the received kafka message, if possible
    tra_message = TraMessage.from_str(message)
    if not tra_message:
        print(f"\rReceived {inv_msg_counter} invalid message(s)", end="", flush=True)
        return True

    # build the risk specification object from the TRA message
    risk_specification = RiskSpecification.from_tra_message(tra_message)
    if not risk_specification:
        print(f"\rReceived {inv_msg_counter} invalid message(s)", end="", flush=True)
        return True

    # TODO: need to make sure that this `risk_data` is perfectly valid for the risk specification api
    # calculate the privacy score
    print(f"{'\n' if inv_msg_counter > 0 else ''}Received a valid message: {message[:80] + ' ...'}")
    risk_data = risk_specification.get_risk_data(config)
    if not risk_data:
        print("    Failed to calculate the privacy risk score")
        return False

    # send the privacy risk score
    print(f"    Calculated a risk score of {risk_data["privacy_score"]}")
    if not RiskSpecificationApi(config).send_risk_data(risk_data):
        print("    Failed to send the risk score")
        return False

    print("    Successfully created and sent the risk specification")
    return False

def main(config: Config):
    consumer = init_kafka(config)
    process_kafka_messages(config, consumer)

if __name__ == "__main__":
    priv_guide_report = PrivGuideReport.from_file_path("priv_guide_report_examples/example0.json")
    if not priv_guide_report:
        print("Could not parse priv guide report.")
        exit(1)

    config = Config.from_config_path("config/", priv_guide_report)
    if not config:
        print("Could not build config from config directory.")
        exit(1)

    # config.kafka_topic = "test_kafka"
    # config.kafka_topic = "R12-AID-TRA"
    # config.kafka_topic = "R13-AID"
    # config.kafka_topic = "MTD-AID"
    config.kafka_topic = "testing123"

    # get_topics(config)
    main(config)
