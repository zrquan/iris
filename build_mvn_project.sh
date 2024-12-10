#!/usr/bin/env bash
# mvn command
mvn clean package -f pom.xml -B -V -e -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true
echo $JAVA_HOME