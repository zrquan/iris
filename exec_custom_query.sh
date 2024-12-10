#!/usr/bin/env bash
# Works with https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.15.3
CODEQL_DIR="$HOME/codeql-2.15.3/codeql"
CODEQL="${CODEQL_DIR}/codeql"
PROJECT="$HOME/projects/NeurosymbolicSA"

#ds="$PROJECT/datasets/OWASP/BenchmarkJava"
#myquery="$PROJECT/codeql/myquery.ql"
myquery=$1
db=$2
type=$3
myquery_name=`basename $myquery`
result_name=`echo $myquery_name | cut -d'.' -f1`
echo $myquery_name

# if [ ! -e codeql-dbs/$db ]; then
#     echo "Creating owasp db"
#     mkdir -p codeql-dbs
#     ${CODEQL} database create codeql-dbs/$db --source-root=$ds --language=java
# fi
cd $PROJECT/codeql
mkdir -p outputs/$db
mkdir -p ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries
# copy myquery to allow finding codeql libs
cp $myquery ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/

# generate intermediate format file
#${CODEQL} query run  --database=codeql-all-dbs/$db --output outputs/$db/${result_name}.bqrs -- ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/$myquery_name

# generate csv
#${CODEQL} bqrs decode outputs/$db/${result_name}.bqrs --format=csv  -o outputs/$db/${result_name}.csv
if [ "${type}" == "analyze" ]; then 
    ${CODEQL} database analyze  --rerun codeql-all-dbs-gh/$db --format=sarif-latest --output=outputs/$db/${result_name}.sarif $1
    ${CODEQL} database analyze codeql-all-dbs-gh/$db --format=csv --output=outputs/$db/${result_name}.csv $1
    echo outputs/$db/${result_name}.csv
else
    ${CODEQL} query run  --database=codeql-all-dbs-gh/$db --output outputs/$db/${result_name}.bqrs -- ${CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries/$myquery_name
    ${CODEQL} bqrs decode outputs/$db/${result_name}.bqrs --format=csv  -o outputs/$db/${result_name}.csv
    realpath outputs/$db/${result_name}.csv
fi

