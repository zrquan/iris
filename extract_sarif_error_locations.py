import json
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("input", type=str)
args = parser.parse_args()

sarif = json.load(open(args.input))
results = sarif["runs"][0]["results"]
paths = [x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for x in results]
files = [os.path.basename(p).replace(".java", "") for p in paths]

print(files)
