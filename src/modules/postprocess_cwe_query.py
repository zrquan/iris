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

from src.config import CODEQL_DIR 

CODEQL = f"{CODEQL_DIR}/codeql"
CODEQL_CUSTOM_QUERY_DIR = f"{CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries"

class CWEQueryResultPostprocessor:
    def __init__(self):
        pass
