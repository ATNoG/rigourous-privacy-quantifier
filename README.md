# Privacy Quantifier

## Prerequisites

```sh
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Running

*Requires access to **IT LLM (skynet.av.it.pt)**, e.g., through VPN or in premises.*

### ONE Testbed access

Connect with **OpenVPN** and use **kubeconfig** file to manage resources in **itav** namespace, e.g., to find **RISK_SPECIFICATION_API** endpoint (kubectl --kubeconfig config/kubeconfig get services).

### Config file

Before running this, a json config file **must** be created in `config/config.json` with the following schema:
```json
{
    "kafka": {
        "address": "string",
        "security_protocol": "string",
        "topic": "string",
        "sasl_mechanism": "string",
        "sasl_plain_username": "string",
        "sasl_plain_password": "string",
        "auto_offset_reset": "string"
    },
    "skynet": {
        "token": "string",
        "model": "string",
        "instance_count": "int",
        "timeout": "int",
        "max_runs": "int"
    },
    "risk_specification_api": {
        "endpoint": "string",
        "timeout": "int"
    }
}
```

### Privguide report

*Requires* a json [privguide](https://github.com/ATNoG/rigourous-devprivops) report.

## Running the script

To run the script:
```sh
python3 main.py
```

*Note:* Depending on where the config file and privguide report are saved, you may have to edit the source code to point to those files.
