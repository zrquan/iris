#!/usr/bin/env sh
# Works with https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.15.3
CODEQL_DIR="$HOME/tools/codeql"
CODEQL="${CODEQL_DIR}/codeql"

ds="$HOME/projects/NeurosymbolicSA/datasets/OWASP/BenchmarkJava"
ds="$HOME/projects/NeurosymbolicSA/projects/xstream_CVE-2020-26217_xstream-XSTREAM_1_4_13/xstream"
ds="$HOME/projects/NeurosymbolicSA/projects/xstream_CVE-2020-26259_xstream-XSTREAM_1_4_14/xstream"
ds="$HOME/projects/NeurosymbolicSA/projects/plexus-utils_CVE-2017-1000487_plexus-utils-plexus-utils-3.0.14/plexus-utils"
ds="$HOME/projects/NeurosymbolicSA/projects/maven-shared-utils_CVE-2022-29599_maven-shared-utils-maven-shared-utils-3.3.2/maven-shared-utils"
ds="$HOME/projects/NeurosymbolicSA/projects/zt-zip_CVE-2018-1002201_zt-zip-zt-zip-1.12/zt-zip"
ds="$HOME/projects/NeurosymbolicSA/projects/plexus-archiver_CVE-2018-1002200_plexus-archiver-plexus-archiver-3.5/plexus-archiver"

query20="${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/Security/CWE/CWE-020/UntrustedDataToExternalAPI.ql"
query22="${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/Security/CWE/CWE-022/"
query78exp="${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/experimental/Security/CWE/CWE-078"
query78="${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/Security/CWE/CWE-078/"
myquery="$HOME/projects/NeurosymbolicSA/codeql/strategies/queries/fetch_apis.ql"
mysecquery="$HOME/projects/NeurosymbolicSA/codeql/strategies/find_vul.ql"
db="maven-shared-utils"
db="zt-zip"
db="plexus-archiver"
db="undertow-io__undertow_CVE-2014-7816_1.2.0.Beta2"
db="Perwendel__spark_CVE-2016-9177_2.5"
#db="plexus-utils-3.0.14"
#db="maven-shared-utils-3.3.2"
#db="owasp"

# ${CODEQL} database create codeql-dbs/$db --source-root=$ds --language=java
# exit 0
#${CODEQL} database analyze codeql-dbs/owasp --format=sarif-latest --output=outputs.sarif $query20
mkdir -p outputs/$db
mkdir -p "${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries"
#exit 0
#${CODEQL} database analyze codeql-dbs/$db --format=sarif-latest --output=outputs/$db/outputs78.sarif $query78 $query78exp
#${CODEQL} database analyze codeql-dbs/$db --format=csv          --output=outputs/$db/outputs78.csv $query78 $query78exp
#${CODEQL} database analyze codeql-dbs/owasp --format=sarif-latest --output=outputs22.sarif $query22

cp $myquery ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/
cp $mysecquery ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/
${CODEQL} database analyze codeql-all-dbs/$db --format=csv --output=outputs/$db/cwe22.csv ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/find_vul.ql
${CODEQL} database analyze codeql-all-dbs/$db --format=sarif-latest --output=outputs/$db/cwe22.sarif ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/find_vul.ql

#${CODEQL} query run  --database=codeql-dbs/$db --output outputs/$db/apis.bqrs  -- ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/fetch_apis.ql
#${CODEQL} bqrs decode outputs/$db/apis.bqrs --format=csv  -o outputs/$db/apis.csv


#${CODEQL} database analyze codeql-dbs/owasp --format=sarif-latest --rerun --output=outputs_my.sarif ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/myquery.ql
