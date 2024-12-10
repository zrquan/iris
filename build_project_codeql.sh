#!/usr/bin/env bash
cve=$1
cwe=$2
if [ -z ${cwe} ]; then 
echo "Missing cwe"
fi


#slug=`echo $1 | rev | cut -d"/" -f1,2 | rev`
slug=$1
version=`echo $cwe`

echo $slug,$version

proj_dir="$HOME/projects/NeurosymbolicSA/projects_${cwe}"

n=`echo $slug| cut -d"/" -f2`
nfull=`echo $slug | sed 's|/|__|'`

#cd $proj_dir


repo_dir="${n}_${cwe}"
echo $repo_dir

if [ -e $proj_dir/$repo_dir ]; then
 echo "ok"; 
 else
 exit 1
 fi 

CODEQL_DIR="$HOME/codeql-2.15.3/codeql"
CODEQL="${CODEQL_DIR}/codeql"

#if [[ "$mvnv" == *"3.5"* ]]; then 
#MVN="$HOME/projects/apache-maven-3.5.0/bin/mvn"
MVNPATH321="$HOME/projects/apache-maven-3.2.1/bin"
MVNPATH350="$HOME/projects/apache-maven-3.5.0/bin"
#elif [[ "$mvnv" == *"3.9"* ]]; then 
#MVN="mvn"
#MVNPATH="$HOME/apache-maven-3.9.6/bin"
#else
#	MVN="$HOME/projects/apache-maven-3.5.0/bin/mvn"
#fi

JAVAHOME7="$HOME/projects/java-versions/jdk1.7.0_80" 
JAVAHOME8="$HOME/projects/java-versions/jdk1.8.0_391"
JAVAHOME17="$HOME/bin/jdk-17.0.9/"
JAVAHOME5="$HOME/java-versions/jdk1.5.0_22"

GRADLE764="/home/saikatd/gradle-versions/gradle-7.6.4/bin/gradle"
GRADLE6="/home/saikatd/gradle-versions/gradle-6.8.2/bin/gradle"


MVNPATH=MVNPATH321
GRADLE=GRADLE764
JAVAHOME=JAVAHOME5

MVN="$MVNPATH/mvn"
echo "Building:$repo_dir"

#export PATH="$MVNPATH:$PATH"
#export JAVA_HOME=${JAVAHOME}
mvncmd="${MVN} clean package -B -V -e -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true"
gradlecmd="${GRADLE} build --parallel"
mkdir -p codeql-all-dbs-gh
mkdir -p codeql-build-logs-gh
if [ ! -e ${proj_dir}/${repo_dir} ]; then 
echo "Skipping ${proj_dir}/${repo_dir}"
exit 0
fi
mvncmd="mvn clean package -B -V -e -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true"



##########
if [ ! -e codeql-all-dbs-gh/${repo_dir}/db-java ]; then 

    export PATH="$HOME/projects/apache-maven-3.5.0/bin:$PATH"
    export JAVA_HOME="$HOME/projects/java-versions/jdk1.8.0_391"

    echo "Try 1, $repo_dir,MVN35,Java8"
    ${CODEQL} database create codeql-all-dbs-gh/${repo_dir} --source-root=${proj_dir}/${repo_dir} --language=java --overwrite  --command="${mvncmd}"> codeql-build-logs-gh/${repo_dir}.log 2>&1
fi 
if [ ! -e codeql-all-dbs-gh/${repo_dir}/db-java  ]; then 
    echo "Try 2, $repo_dir,MVN35,Java17"
    export JAVA_HOME="$HOME/bin/jdk-17.0.9/"
    ${CODEQL} database create codeql-all-dbs-gh/${repo_dir} --source-root=${proj_dir}/${repo_dir} --language=java --overwrite  --command="${mvncmd}">> codeql-build-logs-gh/${repo_dir}.log 2>&1
fi 
if [ ! -e codeql-all-dbs-gh/${repo_dir}/db-java  ]; then 
    echo "Try 3, $repo_dir,MVN396,Java17"     
    export JAVA_HOME="$HOME/bin/jdk-17.0.9/"
    export PATH="$HOME/apache-maven-3.9.6/bin:$PATH"
    ${CODEQL} database create codeql-all-dbs-gh/${repo_dir} --source-root=${proj_dir}/${repo_dir} --language=java --overwrite  --command="${mvncmd}">> codeql-build-logs-gh/${repo_dir}.log 2>&1
fi
if [ $? -ne 0 ]; then 
    echo "Try 4, $repo_dir,MVN396,Java8"     
    export JAVA_HOME="$HOME/projects/java-versions/jdk1.8.0_391"
    export PATH="$HOME/apache-maven-3.9.6/bin:$PATH"
    ${CODEQL} database create codeql-all-dbs-gh/${repo_dir} --source-root=${proj_dir}/${repo_dir} --language=java --overwrite  --command="${mvncmd}">> codeql-build-logs-gh/${repo_dir}.log 2>&1
fi



if [ ! -e codeql-all-dbs-gh/${repo_dir}/db-java ]; then 
    echo "Try 5, $repo_dir, MVN321, Java7"     
    export PATH="${MVNPATH321}:$PATH"
    export JAVA_HOME="${JAVAHOME7}"
    MVN="$MVNPATH321/mvn"
    mvncmd="${MVN} clean package -B -V -e -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true"

    ${CODEQL} database create codeql-all-dbs-gh/${repo_dir} --source-root=${proj_dir}/${repo_dir} --language=java --overwrite  >> codeql-build-logs-gh/${repo_dir}.log 2>&1
    echo "codeql-build-logs-gh/${repo_dir}.log"
fi

if [ ! -e codeql-all-dbs-gh/${repo_dir}/db-java ]; then 
echo "[ERROR],$repo_dir"
echo "cleaning"
rm -rf codeql-all-dbs-gh/${repo_dir}
else
echo "[SUCCESS],$repo_dir"
fi