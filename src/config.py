import os

IRIS_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")

CODEQL_DIR = "path/to/codeql"
CODEQL_DB_PATH = f"{IRIS_ROOT_DIR}/data/codeql-dbs"
PROJECT_SOURCE_CODE_DIR = f"{IRIS_ROOT_DIR}/data/cwe-bench-java/project-sources"
PACKAGE_NAMES_PATH = f"{IRIS_ROOT_DIR}/data/cwe-bench-java/package-names"
OUTPUT_DIR = f"{IRIS_ROOT_DIR}/output"
ALL_METHOD_INFO_DIR = f"{IRIS_ROOT_DIR}/data/cwe-bench-java/data/fix_info.csv"
CVES_MAPPED_W_COMMITS_DIR = f"{IRIS_ROOT_DIR}/data/cwe-bench-java/data/project_info.csv"