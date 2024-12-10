import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random
from tqdm import tqdm

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
NEUROSYMSA_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../../")
sys.path.append(NEUROSYMSA_ROOT_DIR)

try:
    from codeql.strategies_v2.config import CVES_MAPPED_W_COMMITS_DIR, CVE_REPO_TAGS_DIR
except:
    print("[ERROR] Configuration file (config.py) not found. Under strategies directory, do\n\n\tcp config_template.py config.py\n\nand modify the content of config.py")
    exit(1)

from codeql.strategies_v2.neusym_vul import SAPipeline
from codeql.strategies_v2.codeql_vul import CodeQLSAPipeline
from codeql.strategies_v2.queries import QUERIES

CWE_QUERIES = {
    "22": {
        "vanilla": "cwe-022wLLM",
        "posthoc": "cwe-022wLLM-posthoc-filter",
        "codeql": "cwe-022wCodeQL",
        "codeql-exp": "cwe-022wCodeQLExp",
    },
    "78": {
        "vanilla": "cwe-078wLLM",
        "posthoc": "cwe-078wLLM-posthoc-filter",
        "codeql": "cwe-078wCodeQL",
        "codeql-exp": "cwe-078wCodeQLExp",
    },
    "79": {
        "vanilla": "cwe-079wLLM",
        "posthoc": "cwe-079wLLM-posthoc-filter",
        "codeql": "cwe-079wCodeQL",
        "codeql-exp": "cwe-079wCodeQLExp",
    },
    "94": {
        "vanilla": "cwe-094wLLM",
        "posthoc": "cwe-094wLLM-posthoc-filter",
        "codeql": "cwe-094wCodeQL",
        "codeql-exp": "cwe-094wCodeQLExp",
    },
}

def collect_cves_and_db_names(cwe_id: str):
    cves_to_run = []
    all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR).dropna(subset=["cwe", "cve", "commits"])
    all_project_tags = pd.read_csv(CVE_REPO_TAGS_DIR).dropna(subset=["project", "cve", "tag"])
    for (_, proj_row) in tqdm(all_cves_with_commit.iterrows(), desc=f"Collecting stats for CWE-{cwe_id}", total=len(all_cves_with_commit)):
        # Check relevance
        if f"CWE-{cwe_id}" not in proj_row["cwe"].split(";"):
            continue
        cve_id = proj_row["cve"]
        relevant_project_tag = all_project_tags[all_project_tags["cve"] == cve_id]
        if len(relevant_project_tag) == 0:
            continue
        project_tag_row = relevant_project_tag.iloc[0]
        project_name = project_tag_row["project"]
        yield (cve_id, project_name, proj_row, project_tag_row)

def get_num_values(field):
    return 1

def num_alerts(pipeline, ty):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query_name = CWE_QUERIES[cwe_id_short][ty]

    if ty == "vanilla" or ty == "posthoc":
        result_sarif = open(f"{pipeline.project_output_path}/{query_name}/results.sarif")
    elif ty == "codeql" or ty == "codeql-exp":
        cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
        query = CWE_QUERIES[cwe_id_short][ty]
        codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
        result_sarif = open(codeql_pipeline.query_output_result_sarif_path)

    sarif_json = json.load(result_sarif)
    return len([() for a in sarif_json["runs"][0]["results"] if "codeFlows" in a])

def num_paths_from_stats(pipeline, kind):
    stats_file = open(pipeline.final_output_json_path)
    stats_json = json.load(stats_file)
    return stats_json[kind]["num_paths"]

def num_paths_from_codeql_stats(pipeline, ty):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query = CWE_QUERIES[cwe_id_short][ty]
    codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
    stats_json = json.load(open(codeql_pipeline.final_output_json_path))
    return stats_json[f"num_paths"]

def num_paths(pipeline, ty):
    if ty == "vanilla":
        return num_paths_from_stats(pipeline, "vanilla_result")
    elif ty == "posthoc":
        return num_paths_from_stats(pipeline, "posthoc_filter_result")
    elif ty == "codeql" or ty == "codeql-exp":
        return num_paths_from_codeql_stats(pipeline, ty)
    else:
        raise Exception(f"Unknown type {ty}")

def recall_from_stats(pipeline, kind, granularity):
    stats_file = open(pipeline.final_output_json_path)
    stats_json = json.load(stats_file)
    return int(stats_json[kind][f"recall_{granularity}"])

def recall_from_codeql_stats(pipeline, ty, granularity):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query = CWE_QUERIES[cwe_id_short][ty]
    codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
    stats_json = json.load(open(codeql_pipeline.final_output_json_path))
    return int(stats_json[f"recall_{granularity}"])

def recall(pipeline, ty, granularity):
    if ty == "vanilla":
        return recall_from_stats(pipeline, "vanilla_result", granularity)
    elif ty == "posthoc":
        return recall_from_stats(pipeline, "posthoc_filter_result", granularity)
    elif ty == "codeql" or ty == "codeql-exp":
        return recall_from_codeql_stats(pipeline, ty, granularity)
    else:
        raise Exception(f"Unknown type {ty}")

def num_pass_fix_paths_from_stats(pipeline, kind, granularity):
    stats_file = open(pipeline.final_output_json_path)
    stats_json = json.load(stats_file)
    return stats_json[kind][f"num_tp_paths_{granularity}"]

def num_pass_fix_paths_from_codeql_stats(pipeline, ty, granularity):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query = CWE_QUERIES[cwe_id_short][ty]
    codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
    stats_json = json.load(open(codeql_pipeline.final_output_json_path))
    return stats_json[f"num_tp_paths_{granularity}"]

def num_pass_fix_paths(pipeline, ty, granularity):
    if ty == "vanilla":
        return num_pass_fix_paths_from_stats(pipeline, "vanilla_result", granularity)
    elif ty == "posthoc":
        return num_pass_fix_paths_from_stats(pipeline, "posthoc_filter_result", granularity)
    elif ty == "codeql" or ty == "codeql-exp":
        return num_pass_fix_paths_from_codeql_stats(pipeline, ty, granularity)
    else:
        raise Exception(f"Unknown type {ty}")

def num_pass_fix_alerts_from_stats(pipeline, kind, granularity):
    stats_file = open(pipeline.final_output_json_path)
    stats_json = json.load(stats_file)
    return stats_json[kind][f"num_tp_results_{granularity}"]

def num_pass_fix_alerts_from_codeql_stats(pipeline, ty, granularity):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query = CWE_QUERIES[cwe_id_short][ty]
    codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
    stats_json = json.load(open(codeql_pipeline.final_output_json_path))
    return stats_json[f"num_tp_results_{granularity}"]

def num_pass_fix_alerts(pipeline, ty, granularity):
    if ty == "vanilla":
        return num_pass_fix_alerts_from_stats(pipeline, "vanilla_result", granularity)
    elif ty == "posthoc":
        return num_pass_fix_alerts_from_stats(pipeline, "posthoc_filter_result", granularity)
    elif ty == "codeql" or ty == "codeql-exp":
        return num_pass_fix_alerts_from_codeql_stats(pipeline, ty, granularity)
    else:
        raise Exception(f"Unknown type {ty}")

FIELDS = {
    "cwe": lambda ctx: f"CWE-{ctx.cwe_id}",
    "cve": lambda ctx: ctx.cve_id,
    "author": lambda ctx: ctx.project_name.split("_")[0],
    "package": lambda ctx: ctx.project_name.split("_")[2],
    "tag": lambda ctx: ctx.project_name.split("_")[4],
    "num-alerts": num_alerts,
    "num-paths": num_paths,
    "recall": recall,
    "num-alerts-pass-fix": num_pass_fix_alerts,
    "num-paths-pass-fix": num_pass_fix_paths,
}

def main(args):
    cwe_ids = args.cwe_id
    for cwe_id in cwe_ids:
        # First collect the set of CVEs
        cve_id_and_db_names = collect_cves_and_db_names(cwe_id)

        # Then run on each of them
        for (i, (cve_id, db_name, _, _)) in enumerate(cve_id_and_db_names):
            if args.filter is not None and args.filter not in db_name:
                continue

            try:
                ctx = SAPipeline(db_name, CWE_QUERIES[cwe_id]["vanilla"], args.run_id, no_logger=True)
            except Exception as e:
                if args.print_error:
                    print(e)
                continue
            for (i, field) in enumerate(args.fields):
                if "(" in field:
                    field_key = field[:field.index("(")]
                    field_args = tuple(field[field.index("(") + 1:field.index(")")].split(","))
                else:
                    field_key = field
                    field_args = ()
                if field_key not in FIELDS: print(f"Unknown field `{field}`; aborting")
                if i > 0: print("\t", end="")
                try:
                    result = FIELDS[field_key](ctx, *field_args)
                    num_values = get_num_values(field)
                    if num_values > 1:
                        if (type(result) == tuple or type(result) == list) and len(result) == num_values:
                            for (j, x) in enumerate(result):
                                if j > 0:
                                    print("\t", end="")
                                print(x, end="")
                        else:
                            for j in range(num_values):
                                if j > 0:
                                    print("\t", end="")
                                print(result, end="")
                    else:
                        print(result, end="")
                except Exception as e:
                    if args.print_error:
                        print(e)
                    for j in range(get_num_values(field)):
                        if j > 0:
                            print("\t", end="")
                        print(None, end="")
            print("\n", end="")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe-id", type=str, nargs="*", choices=["22", "79", "78", "94"], default=["22", "78", "79", "94"])
    parser.add_argument("--run-id", type=str, default="default")
    parser.add_argument("--fields", type=str, nargs="*", default=[])
    parser.add_argument("--use-final-result-fields", action="store_true")
    parser.add_argument("--use-codeql-result-fields", action="store_true")
    parser.add_argument("--print-error", action="store_true")
    parser.add_argument("--filter", type=str)
    args = parser.parse_args()

    if args.use_final_result_fields:
        args.fields = [
            "cwe",
            "cve",
            "author",
            "package",
            "tag",
            "recall(vanilla,method)",
            "num-alerts(vanilla)",
            "num-paths(vanilla)",
            "num-paths-pass-fix(vanilla,method)",
            "recall(posthoc,method)",
            "num-alerts(posthoc)",
            "num-paths(posthoc)",
            "num-paths-pass-fix(posthoc,method)",
            "recall(codeql,method)",
            "num-alerts(codeql)",
            "num-paths(codeql)",
            "num-paths-pass-fix(codeql,method)",
        ]
    if args.use_codeql_result_fields:
        args.fields = [
            "cwe",
            "cve",
            "author",
            "package",
            "tag",
            "recall(codeql,method)",
            "num-alerts(codeql)",
            "num-paths(codeql)",
            "num-alerts-pass-fix(codeql,method)",
            "num-paths-pass-fix(codeql,method)",
        ]

    main(args)
