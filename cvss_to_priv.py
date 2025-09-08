from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics, requests, re
from config import Config
from typing import Any

cvss3_1 = {
    "Base Score": {
        "AV": ["Attack Vector",                        {"N": "Across the Internet", "A": "Bound to the same protocol", "L": "Same Network", "P": "Needs Physical Access"}],
        "AC": ["Attack Complexity",                    {"L": "Low","H": "High"}],
        "PR": ["Minimum Attacker Privileges Required", {"N": "None/Unauthorized", "L": "Low/Authorized with low priveleges", "H": "High/Authorized with high priveleges"}],
        "UI": ["User Interaction Required",            {"N": "None", "R": "Required"}],
        "S":  ["Scope",                                {"U": "Unchanged", "C": "Changed"}],
        "C":  ["Impact to Confidentiality",            {"N": "None", "L": "Low", "H": "High"}],
        "I":  ["Impact to Integrity",                  {"N": "None", "L": "Low", "H": "High"}],
        "A":  ["Impact to Availability",               {"N": "None", "L": "Low", "H": "High"}],
    },
    "Temporal Score": {
        "E":  ["Exploit Code Maturity", {"X": "Not Defined", "U": "Unproven", "P": "Proof-of-Concept", "F": "Functional", "H": "High"}],
        "RL": ["Remediation Level",     {"X": "Not Defined", "O": "Official Fix", "T": "Temporary Fix", "W": "Workaround", "U": "Unavailable"}],
        "RC": ["Report Confidence",     {"X": "Not Defined", "U": "Unknown", "R": "Reasonable", "C": "Confirmed"}]
    },
    "Environmental Score": {
        "CR":  ["Confidentiality Impact",       {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"}],
        "IR":  ["Integrity Impact",             {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"}],
        "AR":  ["Availability Impact",          {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"}],
        "MAV": ["Modified Attack Vector",       {"X": "Not Defined", "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}],
        "MAC": ["Modified Attack Complexity",   {"X": "Not Defined", "L": "Low", "H": "High"}],
        "MPR": ["Modified Privileges Required", {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}],
        "MUI": ["Modified User Interaction",    {"X": "Not Defined", "N": "None", "R": "Required"}],
        "MS":  ["Modified Scope",               {"X": "Not Defined", "U": "Unchanged", "C": "Changed"}],
        "MC":  ["Modified Confidentiality",     {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}],
        "MI":  ["Modified Integrity",           {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}],
        "MA":  ["Modified Availability",        {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}]
    }
}

# TODO: maybe this should support more than just cvss3.1
def cvss_to_readable_text(cvss: str) -> str | None:
    # check if the CVSS string starts with the expected version identifier
    if cvss.split('/')[0] != "CVSS:3.1":
        return None

    # iterate over the scopes defined in the CVSS dictionary
    result = ""
    for scope in cvss3_1:
        temp, has_category = "", False

        # parse each category and its value from the CVSS string
        for value in cvss.split("/")[1:]:
            category, category_value = value.split(":")

            # check if the category exists in the current CVSS scope
            if category in cvss3_1[scope]:
                has_category = True

                # retrieve the category name and its corresponding value from the CVSS dictionary
                name = cvss3_1[scope][category][0]
                val  = cvss3_1[scope][category][1][category_value]

                # append the formatted category and value to the temporary result
                temp += f"    {name}: {val}\n"

        # if the scope has at least one category, add it to the final result
        if has_category:
            result += f"{scope}:\n{temp}"

    return result.rstrip()

def send_prompt_to_instance(url: str, headers: dict, data: dict, timeout: int) -> dict[str, Any]:
    """Sends the `data` as a prompt to a single LLM instance at `url`.\n
    The return will be a dict with an `error` key to indicate if something went wrong (boolean). In the case that it did,
    an `error-str` key will be provided with the error string. Otherwise, a `response` key will be provided with the LLM answer as a string.
    """

    try:
        response = requests.post(url, headers=headers, json=data, timeout=timeout)
        response.raise_for_status()
        return {"error": False, "response": response.json()["choices"][0]["message"]["content"]}
    except requests.RequestException as e:
        return {"error": True, "error-str": str(e)}

def send_prompt_to_multiple_instances(config: Config, cvss: str, instance_count: int, model: str, timeout: int) -> list[dict[str, Any]]:
    """Get a dictionaty with `instance_count` LLM responses.\n
    Each answer will be acquired from :func:`send_prompt_to_instance`.\n
    """

    assert instance_count > 0

    url = "https://skynet.av.it.pt/api/chat/completions"
    prompt  = "Based on the following CVSS report about a component:\n"
    prompt += cvss
    prompt += "\nPlease evaluate the component based on the risk to privacy, from 1.0-10.0 (both inclusive), with one decimal place, following these immutable rules:\n"
    prompt += "- Lower score is less risk.\n"
    prompt += "- Give me ONLY the score without any other text."
    # prompt += "- Think of the score range as being uniform so, DO NOT favour certain values in detriment of others."
    # prompt += "- BE AS PREDICTABLE AND METHODIC AS POSSIBLE."

    headers = {
        'Authorization': f'Bearer {config.skynet_token}',
        'Content-Type': 'application/json'
    }

    data = {
        "model": model,
        "messages": [{
            "role": "user",
            "content": prompt
        }],
        # not all models support this but the ones that do **should** benefit from this
        "temperature": 0.2
    }

    results = []
    with ThreadPoolExecutor(max_workers=instance_count) as executor:
        futures = [executor.submit(send_prompt_to_instance, url, headers, data, timeout) for _ in range(instance_count)]
        for future in as_completed(futures):
            results.append(future.result())

    return results

def get_result(res: str) -> float | None:
    """Extract the float result from the LLM answer.\n
    If the float cannot be extracted, `None` will be returned.
    """

    pat = re.compile(r"\d(?:\.\d)?")
    r = pat.findall(res)
    if len(r) > 0:
        if isinstance(r, list):
            r = r[0]
        if not isinstance(r, float):
            r = float(r)
        return r
    else:
        return None

# TODO: maybe ignore runs with the std dev too high??
def do_query(config: Config, cvss: str, instance_count: int, model: str, timeout: int) -> float | None:
    responses = send_prompt_to_multiple_instances(config, cvss, instance_count, model, timeout)

    values = []
    for response in responses:
        if not response["error"]:
            # get the model response but ignore the thinking
            res = response["response"]
            if "</think>" in response["response"]:
                res = response["response"].split("</think>")[1]

            # ignore the invalid responses
            value = get_result(res)
            if value == None:
                continue

            values.append(value)

    # we need at least 2 values for calculating the standard deviation and at least 70% of valid answers to calculate the risk
    if len(values) < 2 or len(values) < instance_count * 0.7:
        print("Got no valid responses.")
        return None

    mean = round(sum(values) / len(values), 1)
    std_dev = statistics.stdev(values)
    if std_dev >= 1.0:
        values = [val for val in values if (val >= (mean - std_dev)) and (val <= (mean + std_dev))]

    if len(values) < 2:
        print("Got no valid responses.")
        return None

    privacy_score = round(sum(values) / len(values), 1)
    return privacy_score

def compute_privacy_score(config: Config, cvss: str) -> float | None:
    "Evaluate the `cvss` impact to privacy as a score from `0.0 to 10.0`."

    # configs
    model = "phi3.5:latest"
    instance_count = 7
    timeout = 60
    max_runs = 5

    cvss_readable = cvss_to_readable_text(cvss)
    if cvss_readable == None:
        print("Failed to parse the cvss with an invalid format")
        return None

    count = 0
    privacy_score = do_query(config, cvss_readable, instance_count, model, timeout)
    while privacy_score == None and count < max_runs:
        privacy_score = do_query(config, cvss_readable, instance_count, model, timeout)
        count += 1

    if count >= max_runs:
        return None

    return privacy_score
