#!/bin/sh

. ../../setEnvironment.sh


# classpath for JDK 1.2, 1.3 
# CP=$CP:../../../lib/iaik_esdh.jar

# classpath for JDK 1.4 or later
CP=$CP:../../../lib/signed/iaik_esdh.jar

$JAVA -classpath $CP demo.cms.authenticatedData.AuthenticatedDataOutputStreamDemo


