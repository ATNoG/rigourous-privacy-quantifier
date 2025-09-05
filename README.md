# Privacy Quantifier

## Prerequisites

```sh
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Running

*Requires access to **IT LLM**, e.g., through VPN or in premises.*

### ONE Testbed access

Connect with **OpenVPN** and use **kubeconfig** file to manage resources in **itav** namespace, e.g., to find **RISK_SPECIFICATION_API** endpoint (kubectl --kubeconfig kubeconfig get services).

### Running the script

```sh
python3 main.py
```
