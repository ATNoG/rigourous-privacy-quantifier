from argparse import ArgumentParser
import matplotlib.pyplot as plt
from pathlib import Path
from sys import argv
import json

def plot(test_files: list[Path], title: str):
    if len(test_files) == 0:
        print("No test files are present!")
        exit(1)

    # create a figure and axes to have more control over the sizes
    _fig, ax = plt.subplots(figsize=(11, 6))

    # plot all the files
    for file in test_files:
        with file.open("r") as f:
            file_json = json.load(f)
            risk_values = [run["risk_level"] for run in file_json["runs"]]
            avg_times = [run["avg_time"] for run in file_json["runs"]]

            # set the label for each line/plot
            avg_time = round(sum(avg_times) / len(avg_times), 2)
            score    = str(file).split("/")[1].split("-")[0]
            label    = file.name.removeprefix("test_results-").removesuffix(".json")
            label   += f' -- {file_json["invalid_runs"]} invalid runs -- {avg_time:.2f}s avg time -- {score}'

            line, = ax.plot(risk_values, marker='o', label=f'Run {len(risk_values) + 1}')
            line.set_label(label)

    ax.set_xticks(list(range(10)))
    ax.set_xlabel("Run")

    ax.set_yticks([i * 0.5 for i in range(0, 21)]) # shows 0.0 to 10.0 in steps of 0.5
    ax.set_ylabel("Risk")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1), fancybox=True, shadow=True)
    ax.grid(True)

    plt.title(title)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    parser = ArgumentParser(description="A utility to parse LLM response tests.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--test-files", type=Path, nargs='+', help="A list of paths to JSON test files to parse.")
    group.add_argument("--model", type=str, help="Plot the data for a specific LLM model.", choices=[
        "phi3.5:latest",
        "phi4:latest",
        "deepseek-r1:8b",
        "deepseek-r1:7b",
        "deepseek-r1:1.5b",
        "deepseek-r1:14b",
        "qwen2.5:14b",
        "qwen2.5:0.5b",
        "qwen2.5:1.5b",
        "qwen2.5:3b",
        "qwen2.5:7b",
        "llama3.2:3b",
        "llama3.2:1b",
        "llama3.2:8b",
        "gemma3:4b",
        "gemma3:1b",
        "gemma3:12b",
        "mistral:latest",
    ])

    no_args = len(argv) == 1
    args = parser.parse_args()

    if no_args:
        # get a list of cvss from the tests directory
        cvss_list = [d.name.replace("-", "/") for d in Path("tests").iterdir()]
        test_files = [[f for f in Path(f"tests/{cvss.replace("/", "-")}").glob("*.json") if f.is_file()] for cvss in cvss_list]
        for cvss_test_files in test_files:
            cvss = str(cvss_test_files[0]).removeprefix("tests/").removesuffix(f"/{cvss_test_files[0].name}").replace("-", "/")
            plot(cvss_test_files, cvss)
    elif args.test_files:
        # plot just the requested test files
        plot(args.test_files, "Manual plots")
    else:
        # plot all the files corresponding to the requested model
        assert(args.model)

        # grab all the test files for the specific model
        cvss_list = [d.name.replace("-", "/") for d in Path("tests").iterdir()]
        test_files = [f for cvss in cvss_list for f in Path(f"tests/{cvss.replace("/", "-")}").glob(f"{args.model}.json")]
        plot(test_files, args.model)
