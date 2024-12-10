import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import tabulate
from multiprocessing import Pool

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
        "srcOnly": "cwe-022wLLMSourcesOnly",
        "sinkOnly": "cwe-022wLLMSinksOnly"
    },
    "78": {
        "vanilla": "cwe-078wLLM",
        "posthoc": "cwe-078wLLM-posthoc-filter",
        "codeql": "cwe-078wCodeQL",
        "codeql-exp": "cwe-078wCodeQLExp",
        "srcOnly": "cwe-078wLLMSourcesOnly",
        "sinkOnly": "cwe-078wLLMSinksOnly"
    },
    "79": {
        "vanilla": "cwe-079wLLM",
        "posthoc": "cwe-079wLLM-posthoc-filter",
        "codeql": "cwe-079wCodeQL",
        "codeql-exp": "cwe-079wCodeQLExp",
        "srcOnly": "cwe-079wLLMSourcesOnly",
        "sinkOnly": "cwe-079wLLMSinksOnly"
    },
    "94": {
        "vanilla": "cwe-094wLLM",
        "posthoc": "cwe-094wLLM-posthoc-filter",
        "codeql": "cwe-094wCodeQL",
        "codeql-exp": "cwe-094wCodeQLExp",
        "srcOnly": "cwe-094wLLMSourcesOnly",
        "sinkOnly": "cwe-094wLLMSinksOnly"
    },
}

model_maps = {
    'llama-8b': 'test-llama',
    'llama-70b': 'test-llama70-f-2',
    'gemma-7b': 'test-gemma',
    'deepseek-33b': 'test-deepseekcoder-33b',
    'deepseek-7b': 'test-deepseekcoder-7b',
    'mistral-7b': 'test-mistral-7b',
    'gpt4': 'test0',
    'gpt3.5': 'test-gpt35'
}

name_maps = {
    'llama-8b': 'Llama 3 8b',
    'llama-70b': 'Llama 70b',
    'gemma-7b': 'Gemma 7b',
    'deepseek-33b': 'DeepSeekCoder 33b',
    'deepseek-7b': 'DeepSeekCoder 7b',
    'mistral-7b': 'Mistral 7b',
    'gpt4': 'GPT 4',
    'gpt3.5': 'GPT 3.5'
}

def collect_cves_and_db_names(cwe_id: str):
    cves_to_run = []
    all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR).dropna(subset=["cwe", "cve", "commits"])
    all_project_tags = pd.read_csv(CVE_REPO_TAGS_DIR).dropna(subset=["project", "cve", "tag"])
    whitelist=[k.strip() for k in open(f"{NEUROSYMSA_ROOT_DIR}/whitelist.txt").readlines()]
    for (_, proj_row) in all_cves_with_commit.iterrows():
        # Check relevance
        if f"CWE-{cwe_id}" not in proj_row["cwe"].split(";"):
            continue
        cve_id = proj_row["cve"]
        if cve_id not in whitelist:
            continue
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
        sarif_json = json.load(result_sarif)
        return len(sarif_json["runs"][0]["results"])
    elif ty == "codeql" or ty == "codeql-exp":
        cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
        query = CWE_QUERIES[cwe_id_short][ty]
        codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
        result_sarif = open(codeql_pipeline.query_output_result_sarif_path)
        sarif_json = json.load(result_sarif)
        return len(sarif_json["runs"][0]["results"])

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
    return stats_json[kind][f"num_tp_{granularity}"]

def num_pass_fix_paths_from_codeql_stats(pipeline, ty, granularity):
    cwe_id_short = QUERIES[pipeline.query]["cwe_id_short"]
    query = CWE_QUERIES[cwe_id_short][ty]
    codeql_pipeline = CodeQLSAPipeline(pipeline.project_name, query)
    stats_json = json.load(open(codeql_pipeline.final_output_json_path))
    return stats_json[f"num_tp_{granularity}"]

def num_pass_fix_paths(pipeline, ty, granularity):
    if ty == "vanilla":
        return num_pass_fix_paths_from_stats(pipeline, "vanilla_result", granularity)
    elif ty == "posthoc":
        return num_pass_fix_paths_from_stats(pipeline, "posthoc_filter_result", granularity)
    elif ty == "codeql" or ty == "codeql-exp":
        return num_pass_fix_paths_from_codeql_stats(pipeline, ty, granularity)
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
    "num-paths-pass-fix": num_pass_fix_paths,
}

def to_int(x):
    if isinstance(x, (int, float)):
        return x
    if isinstance(x, str):
        return int(x.split()[0])

def compare(all_llm_results: dict, common=True):
    #print(all_llm_results)
    codeql = {'22': 22, '78': 1, '79': 4, "94": 0}
    common_projects = dict()
    for llm in all_llm_results.keys():
        llm_results = all_llm_results[llm]
        for cwe in llm_results.keys():
            for project in llm_results[cwe].keys():
                #if len(llm_results[cwe][project].keys()) > 4:
                if "recall(vanilla,method)" not in  llm_results[cwe][project]:
                    continue
                common_projects[cwe+"::"+project] = common_projects.get(cwe+"::"+project, 0) + 1
    if common:
        common_projects = [k for k in common_projects.keys() if common_projects[k] == len(all_llm_results.keys())]
    #print(len(common_projects))
    table = []
    for cwe in all_llm_results[list(all_llm_results.keys())[0]].keys():
        cwe_projects = [p.split("::")[-1] for p in common_projects if cwe + "::" in p]
        cur_row = ["CWE-0" + cwe, len(cwe_projects),  codeql[cwe]]
        for llm in all_llm_results.keys():
            recall=0
            for project in all_llm_results[llm][cwe].keys():
                if project in cwe_projects:
                    try:
                        recall+=all_llm_results[llm][cwe][project]["recall(vanilla,method)"]
                    except: pass
            if recall >= codeql[cwe]:
                cur_row.append(str(recall) + " \\green{{($\\uparrow {0}$)}}".format(recall-codeql[cwe]))
            else:
                cur_row.append(str(recall) + " \\red{{($\\downarrow {0}$)}}".format(codeql[cwe] - recall))
        table.append(cur_row)
    def overall(table, i):
        s=sum([to_int(k[i]) for k in table])
        if i >= 3:
            if s >= 27:
                return str(s) + " \\green{{($\\uparrow {0}$)}}".format(s-27)
            else:
                return str(s) + " \\red{{($\\downarrow {0}$)}}".format(27-s)
        else:
            return s
    table.append(["--"] + [overall(table, i) for i in range(1, len(table[0]))])
    print(tabulate.tabulate(table, headers=["CWE", "Projects", "CodeQL"] + list(all_llm_results.keys())))
    print(tabulate.tabulate(table, headers=["CWE", "Projects", "CodeQL"] + list(all_llm_results.keys()), tablefmt="latex_raw"))

def parallel_process_src_sink(inp):
    db_name, cwe_id, args, query_type = inp
    cur_result_dict = dict()

    cur_result_dict['dbname'] = db_name
    cur_result_dict['cwe_id'] = cwe_id

    # cur_result_dict_sink_only = dict()
    # cur_result_dict_sink_only['dbname'] = db_name
    # cur_result_dict_sink_only['cwe_id'] = cwe_id

    cur_result = []

    try:
        ctx = SAPipeline(db_name, CWE_QUERIES[cwe_id][query_type], args.run_id, no_logger=True, llm="llama-3-8b")
    except Exception as e:
        print("Error", str(db_name))
        return None
    for (i, field) in enumerate(args.fields):
        if "(" in field:
            field_key = field[:field.index("(")]
            field_args = tuple(field[field.index("(") + 1:field.index(")")].split(","))
        else:
            field_key = field
            field_args = ()
        if field_key not in FIELDS: print(f"Unknown field `{field}`; aborting")
        try:
            result = FIELDS[field_key](ctx, *field_args)
            num_values = get_num_values(field)
            if num_values > 1:
                if (type(result) == tuple or type(result) == list) and len(result) == num_values:
                    for (j, x) in enumerate(result):
                        cur_result.append(x)
                else:
                    for j in range(num_values):
                        cur_result.append(result)
            else:
                cur_result.append(result)
            cur_result_dict[field] = result
        except Exception as e:
            if args.print_error:
                print(e)
    return cur_result_dict

def parallel_process(inp):
    db_name, cwe_id, args = inp
    #print(db_name)
    cur_result_dict = dict()
    cur_result_dict['dbname'] = db_name
    cur_result_dict['cwe_id'] = cwe_id
    cur_result = []
    try:
        ctx = SAPipeline(db_name, CWE_QUERIES[cwe_id]["vanilla"], args.run_id, no_logger=True, llm="llama-3-8b")
    except Exception as e:
        print("Error", str(db_name))
        return None
    for (i, field) in enumerate(args.fields):
        if "(" in field:
            field_key = field[:field.index("(")]
            field_args = tuple(field[field.index("(") + 1:field.index(")")].split(","))
        else:
            field_key = field
            field_args = ()
        if field_key not in FIELDS: print(f"Unknown field `{field}`; aborting")
        try:
            result = FIELDS[field_key](ctx, *field_args)
            num_values = get_num_values(field)
            if num_values > 1:
                if (type(result) == tuple or type(result) == list) and len(result) == num_values:
                    for (j, x) in enumerate(result):
                        cur_result.append(x)
                else:
                    for j in range(num_values):
                        cur_result.append(result)
            else:
                cur_result.append(result)
            cur_result_dict[field] = result
        except Exception as e:
            if args.print_error:
                print(e)
            #return None

    #if len(cur_result) < len(args.fields):
    #    return None
        #continue

    return cur_result_dict


# def load_or_get_src_sink(args):
#     llm_results_src, llm_results_sink = load_src_sink(args)
#     if llm_results_src is None or args.reload:
#         llm_results_src, llm_results_sink = get_src_sink_only(args)
#         save_src_sink(args, llm_results_src, llm_results_sink)
#     return llm_results_src, llm_results_sink

# def load_src_sink(args):
#     import os
#     store_dir="saved_results"
#     os.makedirs(store_dir, exist_ok=True)
#     output_path_src = f"{store_dir}/src_{args.cwe_id[0]}.json"
#     output_path_sink = f"{store_dir}/sink_{args.cwe_id[0]}.json"
#     if os.path.exists(output_path_src) and os.path.exists(output_path_sink):
#         with open(output_path_src) as f:
#             llm_results_src = json.load(f)
#         with open(output_path_sink) as f:
#             llm_results_sink = json.load(f)
#         return llm_results_src, llm_results_sink
#     return None, None

# def save_src_sink(args, llm_results_src, llm_results_sink):
#     import os
#     store_dir="saved_results"
#     os.makedirs(store_dir, exist_ok=True)
#     output_path_src = f"{store_dir}/src_{args.cwe_id[0]}.json"
#     output_path_sink = f"{store_dir}/sink_{args.cwe_id[0]}.json"
#     with open(output_path_src, "w") as f:
#         json.dump(llm_results_src, f)
#     with open(output_path_sink, "w") as f:
#         json.dump(llm_results_sink, f)

def load_or_get(llm, args):
    llm_results = load(llm)
    if llm_results is None or args.reload:
        llm_results=main(args)
        save(llm, llm_results)
    return llm_results

def load(llm):
    import os
    store_dir="saved_results"
    os.makedirs(store_dir, exist_ok=True)
    output_path = f"{store_dir}/{llm}.json"
    if os.path.exists(output_path):
        with open(output_path) as f:
            return json.load(f)
    return None

def save(llm, all_results):
    import os
    store_dir="saved_results"
    os.makedirs(store_dir, exist_ok=True)
    output_path = f"{store_dir}/{llm}.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f)

def main(args):
    cwe_ids = args.cwe_id
    results_table = []
    errors = dict()
    #results_table.append(args.fields)
    all_results = dict()
    for cwe_id in cwe_ids:
        all_results[cwe_id] = dict()

    for cwe_id in cwe_ids:
        # First collect the set of CVEs
        cve_id_and_db_names = list(collect_cves_and_db_names(cwe_id))

        # Then run on each of them
        dbnames=[ (k[1], cwe_id, args) for k in cve_id_and_db_names]
        #print(dbnames)
        from tqdm import tqdm
        with Pool(20) as p:
            all_result_dicts = list(tqdm(p.imap(parallel_process, dbnames), total=len(dbnames)))
            for r in all_result_dicts:
                if r is not None:
                    all_results[cwe_id][r['dbname']] = r
                    #results_table.append([r[k] for k in args.fields])
                if r is None or len(r) < len(args.fields):
                    errors[cwe_id] = errors.get(cwe_id, []) + [r['dbname']]

def get_src_sink_only(args):
    cwe_ids = args.cwe_id

    errors = dict()
    all_results_src = dict()
    all_results_sink = dict()
    for cwe_id in cwe_ids:
        all_results_src[cwe_id] = dict()
        all_results_sink[cwe_id] = dict()

    for cwe_id in cwe_ids:

        #cve_id_and_db_names = collect_cves_and_db_names(cwe_id)
        dbname_src = [ (k[1], cwe_id, args, "srcOnly") for k in collect_cves_and_db_names(cwe_id)]
        dbname_sink = [ (k[1], cwe_id, args, "sinkOnly") for k in collect_cves_and_db_names(cwe_id)]
        #print(dbnames)
        from tqdm import tqdm
        with Pool(20) as p:
            all_result_dicts = list(tqdm(p.imap(parallel_process_src_sink, dbname_src), total=len(dbname_src)))
            for r in all_result_dicts:
                if r is not None:
                    all_results_src[cwe_id][r['dbname']] = r
                    #results_table.append([r[k] for k in args.fields])
                # if r is None or len(r) < len(args.fields):
                #     errors[cwe_id] = errors.get(cwe_id, []) + [r['dbname']]
        with Pool(20) as p:
            all_result_dicts = list(tqdm(p.imap(parallel_process_src_sink, dbname_sink), total=len(dbname_sink)))
            for r in all_result_dicts:
                if r is not None:
                    all_results_sink[cwe_id][r['dbname']] = r
                    #results_table.append([r[k] for k in args.fields])
                # if r is None or len(r) < len(args.fields):
                #     errors[cwe_id] = errors.get(cwe_id, []) + [r['dbname']]



    return all_results_src, all_results_sink



def posthoc(all_llm_results, args, llms, common_results, common=True):

    common_projects = dict()
    for llm in llms:
        llm_results = all_llm_results[llm]
        for cwe in llm_results.keys():
            final_cve_cwe = json.load(open(f"posthoc_cves_{cwe}.json"))
            #print(llm, cwe, len(llm_results[cwe].keys()))
            for project in llm_results[cwe].keys():
                #if len(llm_results[cwe][project].keys()) > 4:
                project_cve = re.findall(r"CVE-\d+-\d+", project)[0]
                #print(project_cve)
                if project_cve in final_cve_cwe:
                    if "num-paths(posthoc)" in llm_results[cwe][project]:
                        #print(llm, cwe, project, llm_results[cwe][project]["recall(posthoc,method)"])
                        common_projects[cwe+"::"+project] = common_projects.get(cwe+"::"+project, 0) + 1
                    else:
                        print("Error", llm, cwe, project)
    if common:
        common_projects = [k for k in common_projects.keys() if common_projects[k] == len(llms)]
        #print(common_projects)    elif load_posthoc_cves:
        common_cves = {
            "22": json.load(open("posthoc_cves_22.json")),
            "78": json.load(open("posthoc_cves_78.json")),
            "79": json.load(open("posthoc_cves_79.json")),
            "94": json.load(open("posthoc_cves_94.json")),
        }
        common_projects = [
            k for k in common_projects.keys() if any(cve in k.split("::")[1] for cve in common_cves[k.split("::")[0]])
        ]
        # print(common_projects)
        # print(len(common_projects))
        # print({k: len(v) for k, v in common_cves.items()})
        # exit()

    codeql_results = dict()

    for cwe in common_results:
        codeql_results[cwe] = dict()
        final_cves = json.load(open(f"posthoc_cves_{cwe}.json"))
        cwe_projects = [p.split("::")[-1] for p in common_projects if cwe + "::" in p]
        for project in common_results[cwe]:
            codeql_results[cwe][project] = dict()
            project_cve = re.findall(r"CVE-\d+-\d+", project)[0]
            if project in cwe_projects and project_cve in final_cves:
                for field in common_results[cwe][project]:
                    if 'codeql' in field:
                        codeql_results[cwe][project][field] = common_results[cwe][project][field]
            else:
                codeql_results[cwe].pop(project)

    #print(codeql_results)
    results_table = []
    headersA= ["CWE", "CodeQL", "CodeQL"]
    headersB= [" ", "Paths", "Recall"]
    for llm in llms:
        headersA.extend([f"{llm}", f"{llm}"])
        headersB.extend(["Paths", "Recall"])
    results_table.append(headersB)
    aggregates=[]
    total_paths_pre = 0
    total_paths_post = 0
    total_reduction = 0
    total_projects = 0
    num_projects = dict()
    paths_dict = dict()
    recall_dict = dict()
    reduction_dict = dict()
    precision_dict = dict()
    for cwe in args.cwe_id:
        cur_result = []
        cwe_projects = [p.split("::")[-1] for p in common_projects if cwe + "::" in p]
        num_projects[cwe] = len(cwe_projects)
        #final_cves = json.load(open(f"cwe_{cwe}.json"))
        for llm in llms:
            #print(llm, cwe)
            alerts_pre = 0
            alerts_post = 0
            paths_pre = 0
            paths_post = 0
            recall_pre = 0
            recall_post = 0
            paths_precision = 0
            projects=0
            reduction=0
            zero_alarm = 0
            for project in all_llm_results[llm][cwe].keys():
                project_cve = re.findall(r"CVE-\d+-\d+", project)[0]
                #print(project_cve, llm, cwe, project)
                if project in cwe_projects:
                    alerts_pre += all_llm_results[llm][cwe][project]["num-alerts(vanilla)"]
                    paths_pre += all_llm_results[llm][cwe][project]["num-paths(vanilla)"]
                    alerts_post += all_llm_results[llm][cwe][project]["num-alerts(posthoc)"]
                    paths_post += all_llm_results[llm][cwe][project]["num-paths(posthoc)"]
                    recall_pre += all_llm_results[llm][cwe][project]["recall(vanilla,method)"]
                    recall_post += all_llm_results[llm][cwe][project]["recall(posthoc,method)"]

                    if all_llm_results[llm][cwe][project]["num-paths(posthoc)"] != 0:
                        paths_precision += all_llm_results[llm][cwe][project]["num-paths-pass-fix(posthoc,method)"] / all_llm_results[llm][cwe][project]["num-paths(posthoc)"]
                    else:
                        zero_alarm += 1

                    if  all_llm_results[llm][cwe][project]["recall(posthoc,method)"] > all_llm_results[llm][cwe][project]["recall(vanilla,method)"]:
                        print("Error", llm, cwe, project)

                    #print(cwe, project)
                    #reduction += (paths_pre-paths_post)
                    projects += 1

            print(f"LLM: {llm}, {cwe}, {zero_alarm}")

            reduction = (paths_pre-paths_post)
            paths_dict[llm] = paths_dict.get(llm, []) + [((paths_pre, paths_post), projects)]
            recall_dict[llm] = recall_dict.get(llm, []) + [((recall_pre, recall_post), projects)]
            reduction_dict[llm] = reduction_dict.get(llm, []) + [(reduction, paths_pre, projects)]
            precision_dict[llm] = precision_dict.get(llm, []) + [(paths_precision, projects)]

            # if projects > 0:
            #     alerts_pre = alerts_pre/projects
            #     alerts_post = alerts_post/projects
            #     paths_pre = paths_pre/projects
            #     paths_post = paths_post/projects

            cur_result.extend([f"{paths_post/projects:.0f} (\\green{{$\\downarrow {(reduction*100/paths_pre):.0f}$\\%}})", f"{recall_post:.0f}  (\\red{{$\\downarrow {recall_pre-recall_post}$}})"])

        codeql_avg_paths = sum([codeql_results[cwe][project]["num-paths(codeql)"] for project in codeql_results[cwe]])/projects

        codeql_recall = sum([codeql_results[cwe][project]["recall(codeql,method)"] for project in codeql_results[cwe]])
        codeql_precision = sum([codeql_results[cwe][project]["num-paths-pass-fix(codeql,method)"] / codeql_results[cwe][project]["num-paths(codeql)"] if codeql_results[cwe][project]["num-paths(codeql)"] > 0 else 0 for project in codeql_results[cwe]])
        print(f"CodeQL CWE {cwe}: Precision {codeql_precision}")

        # num_zero_codeql_precision = sum([0 if codeql_results[cwe][project]["num-paths(codeql)"] > 0 else 1 for project in codeql_results[cwe]])
        # print(f"CodeQL CWE {cwe}: Count of 0 {num_zero_codeql_precision``}")

        paths_dict['codeql'] = paths_dict.get('codeql', []) + [(sum([codeql_results[cwe][project]["num-paths(codeql)"] for project in codeql_results[cwe]]), len(codeql_results[cwe]))]
        recall_dict['codeql'] = recall_dict.get('codeql', []) + [(sum([codeql_results[cwe][project]["recall(codeql,method)"] for project in codeql_results[cwe]]), len(codeql_results[cwe]))]
        cur_result = [cwe] + [f"{codeql_avg_paths:.0f}", f"{codeql_recall}"] + cur_result
        results_table.append(cur_result)

    print(precision_dict)

    aggregates = ["\\textbf{All}"]
    #average codeql paths
    aggregates.append(f"{sum([k[0] for k in paths_dict['codeql']])/sum([k[1] for k in paths_dict['codeql']]):.0f}")
    # total codeql recall
    aggregates.append(f"{sum([k[0] for k in recall_dict['codeql']]):.0f}")
    for llm in all_llm_results.keys():
        paths_pre = sum([k[0][0] for k in paths_dict[llm]])
        paths_post = sum([k[0][1] for k in paths_dict[llm]])
        reduction = (sum([k[0] for k in reduction_dict[llm]])*100)/sum([k[1] for k in reduction_dict[llm]])
        recall_pre = sum([k[0][0] for k in recall_dict[llm]])
        recall_post = sum([k[0][1] for k in recall_dict[llm]])
        projects = sum([k[1] for k in recall_dict[llm]])
        #aggregates.extend([f"{paths_pre/projects:.0f}/{paths_post/projects:.0f}", f"{reduction/projects:.0f}\\%", f"{recall_post}(\\red{{($\\downarrow {recall_pre-recall_post}$)}}")"])
        paths_per_vul_pre = (paths_pre)/projects
        paths_per_vul_post = (paths_post)/projects
        aggregates.extend([ f"{paths_post}/{paths_pre}/{paths_per_vul_post:.0f} (\\green{{$\\downarrow {reduction:.0f}$\\%}})",  f"{recall_post}(\\red{{$\\downarrow {recall_pre-recall_post}$}})"])
    results_table.append(aggregates)
    print(tabulate.tabulate(results_table, headers=headersA, floatfmt=".0f"))
    print(tabulate.tabulate(results_table, headers=headersA, tablefmt="latex_raw", floatfmt=".0f"))

def plot_venn(recall_scores, codeql_scores):
    import matplotlib.pyplot as plt
    # set font size
    plt.rcParams.update({'font.size': 30})

    #from matplotlib_venn import venn2
    import venn
    project_list = []
    for cwe in recall_scores['gpt4'].keys():
        for project in recall_scores[k][cwe].keys():
            project_list.append((cwe, project))
    flattened_recall = dict()
    for llm in recall_scores.keys():
        flattened_recall[llm] = []
        for i, (cwe, project) in enumerate(project_list):
            if "recall(vanilla,method)" in recall_scores[llm][cwe][project] and recall_scores[llm][cwe][project]["recall(vanilla,method)"] > 0:
                flattened_recall[llm].append(i)
        #print(flattened_recall[llm]


    codeql_flattened_recall = []
    for i, (cwe, project) in enumerate(project_list):
        if "recall(codeql,method)" in codeql_scores[cwe][project] and codeql_scores[cwe][project]["recall(codeql,method)"] > 0:
            codeql_flattened_recall.append(i)
    #print(flattened_recall[llm])

    llms = ['gemma-7b', 'llama-8b', 'mistral-7b', 'deepseek-7b', 'deepseek-33b',  'llama-70b', 'gpt3.5', 'gpt4']

    # detected by none
    sums = [sum([1 if i in flattened_recall[l] else 0 for l in llms]) for i in range(len(project_list))]
    print(sums)
    print("No detected", len([k for k in sums if k == 0]))
    print("Detected by all", len([k for k in sums if k == len(llms)]))
    print("Detected by one", len([k for k in sums if k == 1]))
    print("Detected by two", len([k for k in sums if k == 2]))
    print("Detected by at least one", len([k for k in sums if k > 0]))
    print("Detected by at least two", len([k for k in sums if k > 1]))
    print("Detected by at least three", len([k for k in sums if k > 2]))
    print("Only detected by GPT 4:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['gpt4']]))
    print("Only detected by GPT 3.5:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['gpt3.5']]))
    print("Only detected by Llama 8b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['llama-8b']]))
    print("Only detected by Llama 70b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['llama-70b']]))
    print("Only detected by Mistral 7b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['mistral-7b']]))
    print("Only detected by DeepSeek 7b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['deepseek-7b']]))
    print("Only detected by DeepSeek 33b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['deepseek-33b']]))
    print("Only detected by Gemma 7b:", len([i for i in range(len(project_list)) if sums[i] == 1 and i in flattened_recall['gemma-7b']]))

    print("Detected by all but CodeQL", len([i for i in range(len(project_list)) if sums[i] == len(llms) and i not in codeql_flattened_recall]))
    print("Detected by CodeQL but not by any other", len([i for i in range(len(project_list)) if i in codeql_flattened_recall and sums[i] == 0]))
    codeql_no_gpt4 = [i for i in range(len(project_list)) if i in codeql_flattened_recall and i not in flattened_recall['gpt4']]
    print(codeql_no_gpt4, project_list[codeql_no_gpt4[0]])

    print("Detected by CodeQL but not GPT 4", len(codeql_no_gpt4))

    return


    # compute venn subsets
    labels = venn.get_labels([flattened_recall[k] for k in llms], fill=['number'])
    print(labels)
    fig, ax = venn.venn5(labels, names=[name_maps[k] for k in llms], fontsize=22)
    #fig.show()
    #venn2(subsets = (10, 5, 2), set_labels = ('Group A', 'Group B'))
    fig.savefig("venn5.png", bbox_inches='tight')


def ablation(results_src, results_sink, results_original, common_results):
    table =[]
    headers = ["CWE", "22", "22", "78", "78", "79", "79","94","94"]

    # codeql
    cur_result = ["CodeQL"]
    for cwe in ["22", "78", "79", "94" ]:
        llm="gpt4"
        paths = sum([common_results[cwe][project]["num-paths(codeql)"] for project in common_results[cwe]])/len(common_results[cwe])
        recall = sum([common_results[cwe][project]["recall(codeql,method)"] for project in common_results[cwe]])
        cur_result.extend([f"{paths:.0f}", f"{recall:.0f}"])
    table.append(cur_result)

    # source only
    cur_result = ["Source Only"]
    for cwe in ["22", "78", "79", "94" ]:
        llm="gpt4"
        paths = sum([results_src[llm][cwe][project]["num-paths(vanilla)"] for project in results_src[llm][cwe]])/len(results_src[llm][cwe])
        recall = sum([results_src[llm][cwe][project]["recall(vanilla,method)"] for project in results_src[llm][cwe]])
        cur_result.extend([f"{paths:.0f}", f"{recall:.0f}"])
    table.append(cur_result)
    # sink only
    cur_result = ["Sink Only"]
    for cwe in ["22", "78", "79", "94" ]:
        llm="gpt4"
        paths = sum([results_sink[llm][cwe][project]["num-paths(vanilla)"] for project in results_sink[llm][cwe]])/len(results_sink[llm][cwe])
        recall = sum([results_sink[llm][cwe][project]["recall(vanilla,method)"] for project in results_sink[llm][cwe]])
        cur_result.extend([f"{paths:.0f}", f"{recall:.0f}"])
    table.append(cur_result)

    # original
    cur_result = ["Original"]
    for cwe in ["22", "78", "79", "94" ]:
        llm="gpt4"
        #for llm in results_original.keys():
        paths = sum([results_original[llm][cwe][project]["num-paths(vanilla)"] for project in results_original[llm][cwe]])/len(results_original[llm][cwe])
        recall = sum([results_original[llm][cwe][project]["recall(vanilla,method)"] for project in results_original[llm][cwe]])
        cur_result.extend([f"{paths:.0f}", f"{recall:.0f}"])
    table.append(cur_result)
    print(table)
    print(tabulate.tabulate(table, headers=headers, floatfmt=".0f"))
    print(tabulate.tabulate(table, headers=headers, tablefmt="latex_raw", floatfmt=".0f"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe-id", type=str, nargs="*", choices=["22", "79", "78", "94"], default=["22", "78", "79", "94"])
    parser.add_argument("--run-id", type=str, default="default")
    parser.add_argument("--fields", type=str, nargs="*", default=[])
    parser.add_argument("--use-final-result-fields", action="store_true")
    parser.add_argument("--print-error", action="store_true")
    parser.add_argument("--filter", type=str)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    if args.use_final_result_fields:
        args.fields = [
            "cwe",
            "cve",
            "author",
            "package",
            #"tag",
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
    results_d = dict()
    results_src_only_d = dict()
    results_sink_only_d = dict()
    #for k in ['gemma-7b', 'llama-8b', 'mistral-7b', 'deepseek-7b', 'deepseek-33b',  'llama-70b', 'gpt3.5', 'gpt4']:
    llms = [ 'deepseek-7b', 'llama-70b',  'gpt4']
    for k in llms:
        args.run_id=model_maps[k]
        # llm_results = load(model_maps[k])
        # if llm_results is None or args.reload:
        #     llm_results=main(args)
        #     save(model_maps[k], llm_results)
        results_d[k] = load_or_get(model_maps[k], args)
        #results_src_only, results_sink_only = get_src_sink_only(args)
        #results_src_only_d[k] = results_src_only
        #results_sink_only_d[k] = results_sink_only

    args.run_id = 'common'
    common_results = load_or_get('common', args)

    #ablation(results_src_only_d, results_sink_only_d, results_d, common_results)

    #print(results_src_only_d)
    #print(common_results)
    #plot_venn(results_d, common_results)
    #print(results_d['gpt4']['22'])
    #compare(results_d, common=True)
    llms = ['deepseek-7b','llama-70b', 'gpt4' ]
    posthoc(results_d, args, llms, common_results, common=False)
