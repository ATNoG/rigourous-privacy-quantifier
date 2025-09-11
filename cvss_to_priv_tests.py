from concurrent.futures import ThreadPoolExecutor, as_completed
import requests, re, statistics, json, time, itertools
from config import Config
from pathlib import Path
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

# def cvss_to_readable_text(cvss: str) -> str | None:
#     """Convert from the `cvss 3.1` format to `readable text`.\n
#     In the event that this convertion is not possible, `None` will be returned.
#     Example:\n
#     cvss:\n
#         CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n
#     Readable Text:
#         Attack Vector: Remotely Exploitable\n
#         Attack Complexity: Low\n
#         Privileges Required: Low\n
#         User Interaction Required? No\n
#         Scope: Unchanged\n
#         Impact to Confidentiality: High\n
#         Impact to Integrity: High\n
#         Impact to Availability: High
#     """
#     if cvss.split('/')[0] != "CVSS:3.1":
#         return None
#     result = ""
#     for cat in cvss.split('/')[1:]:
#         match cat.split(':')[0]:
#             case "AV":
#                 result += "Attack Vector: "
#                 match cat.split(":")[1]:
#                     case "N":
#                         result += "Remotely Exploitable\n"
#                         continue
#                     case "A":
#                         result += "Adjacent Network Access Needed\n"
#                         continue
#                     case "L":
#                         result += "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.\n"
#                         continue
#                     case "P":
#                         result += "Physical Access Needed\n"
#                         continue
#                     case _:
#                         return None
#             case "AC":
#                 result += "Attack Complexity: "
#                 match cat.split(":")[1]:
#                     case "L":
#                         result += "Low\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case _:
#                         return None
#             case "PR":
#                 result += "Privileges Required: "
#                 match cat.split(":")[1]:
#                     case "L":
#                         result += "Low\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case "N":
#                         result += "None\n"
#                         continue
#                     case _:
#                         return None
#             case "UI":
#                 result += "User Interaction Required? "
#                 match cat.split(":")[1]:
#                     case "R":
#                         result += "Required\n"
#                         continue
#                     case "N":
#                         result += "None\n"
#                         continue
#                     case _:
#                         return None
#             case "S":
#                 result += "Scope: "
#                 match cat.split(":")[1]:
#                     case "U":
#                         result += "Unchanged\n"
#                         continue
#                     case "C":
#                         result += "Changed\n"
#                         continue
#                     case _:
#                         return None
#             case "C":
#                 result += "Impact to Confidentiality: "
#                 match cat.split(":")[1]:
#                     case "L":
#                         result += "Low\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case "N":
#                         result += "None\n"
#                         continue
#                     case _:
#                         return None
#             case "I":
#                 result += "Impact to Integrity: "
#                 match cat.split(":")[1]:
#                     case "L":
#                         result += "Low\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case "N":
#                         result += "None\n"
#                         continue
#                     case _:
#                         return None
#             case "A":
#                 result += "Impact to Availability: "
#                 match cat.split(":")[1]:
#                     case "L":
#                         result += "Low\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case "N":
#                         result += "None\n"
#                         continue
#                     case _:
#                         return None
#             case "E":
#                 result += "Exploit Code Maturity: "
#                 match cat.split(":")[1]:
#                     case "X":
#                         result += "Not Defined\n"
#                         continue
#                     case "H":
#                         result += "High\n"
#                         continue
#                     case "F":
#                         result += "Functional\n"
#                         continue
#                     case "P":
#                         result += "Proof-of-concept\n"
#                         continue
#                     case "U":
#                         result += "Unproven\n"
#                         continue
#                     case _:
#                         return None
#             case "RL":
#                 result += "Remediation Level: "
#                 match cat.split(":")[1]:
#                     case "X":
#                         result += "Not Defined\n"
#                         continue
#                     case "O":
#                         result += "Official Fix\n"
#                         continue
#                     case "T":
#                         result += "Temporary Fix\n"
#                         continue
#                     case "W":
#                         result += "Workaround\n"
#                         continue
#                     case "U":
#                         result += "Unavailable\n"
#                         continue
#                     case _:
#                         return None
#             case "RC":
#                 result += "Report Confidence: "
#                 match cat.split(":")[1]:
#                     case "X":
#                         result += "Not Defined\n"
#                         continue
#                     case "C":
#                         result += "Confirmed\n"
#                         continue
#                     case "R":
#                         result += "Reasonable\n"
#                         continue
#                     case "U":
#                         result += "Unknown\n"
#                         continue
#                     case _:
#                         return None
#             case _:
#                 return None
#     return result

def send_prompt_to_instance(url: str, headers: dict, data: dict, timeout: int) -> dict[str, Any]:
    """Sends the `data` as a prompt to a single LLM instance at `url`.\n
    The return will be a dict with an `error` key to indicate if something went wrong (boolean). In the case that it did,
    an `error-str` key will be provided with the error string. Otherwise, a `response` key will be provided with the LLM answer as a string.
    """

    start = time.time()
    try:
        response = requests.post(url, headers=headers, json=data, timeout=timeout)
        response.raise_for_status()
        return {"error": False, "response": response.json()["choices"][0]["message"]["content"], "time": time.time() - start}
    except requests.RequestException as e:
        return {"error": True, "error-str": str(e), "time": time.time() - start}

def send_prompt_to_multiple_instances(config: Config, cvss: str) -> list[dict[str, Any]]:
    """Get a dictionaty with `instance_count` LLM responses.\n
    Each answer will be acquired from :func:`send_prompt_to_instance`.\n
    """

    assert config.skynet_instance_count > 0

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
        "model": config.skynet_model,
        "messages": [{
            "role": "user",
            "content": prompt
        }],
        # not all models support this but the ones that do **should** benefit from this
        "temperature": 0.2
    }

    results = []
    with ThreadPoolExecutor(max_workers=config.skynet_instance_count) as executor:
        futures = [executor.submit(send_prompt_to_instance, url, headers, data, config.skynet_timeout) for _ in range(config.skynet_instance_count)]
        for future in as_completed(futures):
            results.append(future.result())

    return results

# TODO: maybe ignore runs with the std dev too high??
def do_query(config: Config, cvss: str) -> dict[str, Any] | None:
    responses = send_prompt_to_multiple_instances(config, cvss)

    values = []
    for response in responses:
        if not response["error"]:
            # get the model response but ignore the thinking
            res = response["response"]
            if "</think>" in response["response"]:
                res = response["response"].split("</think>")[1]

            value = get_result(res)
            if value == None:
                continue

            print(f"Value: {value}")
            values.append(value)
        else:
            print(f"Error: {response["error-str"][:100] + ' ...'}")

    # we need at least 2 values for calculating the standard deviation and at least 70% of valid answers to calculate the risk
    if len(values) < 2 or len(values) < config.skynet_instance_count * 0.7:
        print("Got no valid responses")
        return None

    mean = round(sum(values) / len(values), 1)
    std_dev_before = statistics.stdev(values)
    if std_dev_before >= 1.0:
        values = [val for val in values if (val >= (mean - std_dev_before)) and (val <= (mean + std_dev_before))]

    if len(values) < 2:
        print("Got no valid responses")
        return None

    std_dev_after = statistics.stdev(values)
    risk_level = round(sum(values) / len(values), 1)
    print(f"Risk level: {risk_level}")
    print(f"Standard deviation before: {std_dev_before}")
    print(f"Standard deviation after:  {std_dev_after}")

    times = [response["time"] for response in responses]
    return {
        "values": values,
        "risk_level": risk_level,
        "standard_deviation": std_dev_after,
        "avg_time": sum(times) / len(times),
    }

    # url = "https://skynet.av.it.pt/api/chat/completions"
    # token = "SOME TOKEN"
    # # prompt = """Based on the given report about a component, evaluate it based on privacy risk, from 1-10, with one decimal place.
    # # Lower score is less risk.
    # # Output only the score without any other text.
    # # Evaluate based on this data:"""
    # prompt  = "Based on the following cvss report about a component:\n\n"
    # prompt += cvss_to_readable_text(cvss)
    # prompt += "\nPlease evaluate the component based on the privacy risk, from 1-10 (both inclusive), with one decimal place, following these immutable rules:\n"
    # prompt += "- Lower score is less risk.\n"
    # prompt += "- Give me ONLY the score without any other text.\n"
    # prompt += "- BE AS PREDICTABLE AND METHODIC AS POSSIBLE."
    # headers = {
    #     'Authorization': f'Bearer {token}',
    #     'Content-Type': 'application/json'
    # }
    # data = {
    #     "model": "deepseek-r1:8b",
    #     "messages": [{
    #         "role": "user",
    #         "content": prompt
    #     }],
    #     # todo: does this deepseek support this??
    #     "temperature": 0.2
    # }
    # response = requests.post(url, headers=headers, json=data, timeout=30)
    # response = response.json()["choices"][0]["message"]["content"]
    # print(response)
    # exit(0)
    # if not response.ok:
    #     return {}
    # return response.json()

def save_privacy_score(config: Config, cvss: str, score: float):
    # configs
    # config.skynet_model = "gemma3:12b"
    config.skynet_instance_count = 7
    config.skynet_timeout = 60
    run_count = 10

    tests_folder = cvss.replace("/", "-")
    plot_data = {"invalid_runs": 0, "runs": []}
    cvss_readable = cvss_to_readable_text(cvss)
    assert cvss_readable != None
    while len(plot_data["runs"]) < run_count:
        data = do_query(config, cvss_readable)

        # make sure that unsuccessful risk evaluations are ignored
        if not data:
            plot_data["invalid_runs"] += 1
            print("Got run with no valid data!")
            continue

        plot_data["runs"].append(data)

    # save the results for ploting
    Path(f"tests/{score}-{tests_folder}").mkdir(parents=True, exist_ok=True)
    with open(f"tests/{score}-{tests_folder}/{config.skynet_model}.json", "w") as f:
        json.dump(plot_data, f, indent=4)

    # response = ""
    # while True:
    #     response = do_query(cvss).get("choices", [{}])[0].get("message", {}).get("content", "")
    #     split_response = response.split("</think>")
    #     print(f"LLM response: {response}")
    #     if len(split_response) > 1:
    #         result = validate_result(split_response[1])
    #         if result < 0.0:
    #             break
    #     break
    # return result

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

def generate_cvss_vectors():
    # all (without environmental metrics) possible values for cvss3.1
    metrics = {
        # base score metrics
        'AV': ('N', 'A', 'L', 'P'),
        'AC': ('L', 'H'),
        'PR': ('N', 'L', 'H'),
        'UI': ('N', 'R'),
        'S':  ('U', 'C'),
        'C':  ('N', 'L', 'H'),
        'I':  ('N', 'L', 'H'),
        'A':  ('N', 'L', 'H'),
        # # temporal score metrics
        # 'E':  ('X', 'U', 'P', 'F', 'H'),
        # 'RL': ('X', 'O', 'T', 'W', 'U'),
        # 'RC': ('X', 'U', 'R', 'C')
    }

    # get the metric names and their values
    metric_keys = list(metrics.keys())
    value_sets = [metrics[key] for key in metric_keys]

    # create the generator for all combinations
    all_combinations = itertools.product(*value_sets)

    # yield each combination formatted as a cvss3.1 string
    for combination in all_combinations:
        vector_parts = [f"{key}:{val}" for key, val in zip(metric_keys, combination)]
        yield f"CVSS:3.1/{'/'.join(vector_parts)}"

if __name__ == "__main__":
    config = Config.from_config_path("config/")
    if not config:
        print("Could not build config from config directory.")
        exit(1)

    # TODO: generate all the possible cvss combinations and test them all
    # cvss = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

    cvss, score = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.5  # 2.5  --> https://nvd.nist.gov/vuln/detail/CVE-2024-35281
    # cvss, score = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L", 3.1  # 3.1  --> https://nvd.nist.gov/vuln/detail/CVE-2024-3181
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3  # 4.3  --> https://nvd.nist.gov/vuln/detail/cve-2022-21592
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3  # 5.3  --> https://nvd.nist.gov/vuln/detail/CVE-2020-14635
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1  # 6.1  --> https://nvd.nist.gov/vuln/detail/CVE-2025-30709
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5  # 7.5  --> https://nvd.nist.gov/vuln/detail/cve-2014-0160
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8  # 9.8  --> https://nvd.nist.gov/vuln/detail/CVE-2019-9874
    # cvss, score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0 # 10.0 --> https://nvd.nist.gov/vuln/detail/cve-2021-44228

    # save_privacy_score(config, cvss, score)

    count = 0
    cvss_generator = generate_cvss_vectors()
    for cvss in cvss_generator:
        count += 1

    print(count)
