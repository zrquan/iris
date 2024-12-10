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

from codeql.strategies_v2.config import CODEQL_DIR, CODEQL_DB_PATH, PACKAGE_NAMES_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR
from codeql.strategies_v2.queries import QUERIES

CODEQL = f"{CODEQL_DIR}/codeql"
CODEQL_CUSTOM_QUERY_DIR = f"{CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries"

class CWEQueryResultPostprocessor:
    def __init__(self):
        pass
