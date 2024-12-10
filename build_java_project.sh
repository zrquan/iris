#!/usr/bin/env bash
# ./build_java_project.sh [java project directory]

proj_dir="$1"

# download maven from https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/*/apache-maven-X.Y.Z-bin.tar.gz
MVNPATH321="$HOME/projects/apache-maven-3.2.1/bin"
MVNPATH350="$HOME/projects/apache-maven-3.5.0/bin"

#download java from https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html 
#JAVAHOME7="$HOME/projects/java-versions/jdk1.7.0_80" 
JAVAHOME8="$HOME/projects/java-versions/jdk1.8.0_202"
JAVAHOME17="$HOME/projects/java-versions/jdk-17.0.11"
#JAVAHOME5="$HOME/java-versions/jdk1.5.0_22"
# GRADLE764="/home/saikatd/gradle-versions/gradle-7.6.4/bin/gradle"
# GRADLE6="/home/saikatd/gradle-versions/gradle-6.8.2/bin/gradle"

# choose appropriate mavn and java versions
MVNPATH=${MVNPATH350}
JAVAHOME=${JAVAHOME8}


MVN="$MVNPATH/mvn"
echo "Building:$proj_dir"

export PATH="$MVNPATH:$PATH"
export JAVA_HOME=${JAVAHOME}
mvncmd="${MVN} clean package -B -V -e -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true"
#gradlecmd="${GRADLE} build --parallel"


cd ${proj_dir}
${mvncmd} 

mvn -Dtest=ZipArchiverTest test