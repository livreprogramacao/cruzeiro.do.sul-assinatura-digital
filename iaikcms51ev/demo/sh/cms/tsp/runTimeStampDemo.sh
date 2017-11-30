#!/bin/sh

. ../../setEnvironment.sh

# add iaik_tsp.jar to classpath
CP=$CP:../../../lib/eval/tsp/iaik_tsp.jar

$JAVA -classpath $CP demo.cms.tsp.TimeStampDemo


