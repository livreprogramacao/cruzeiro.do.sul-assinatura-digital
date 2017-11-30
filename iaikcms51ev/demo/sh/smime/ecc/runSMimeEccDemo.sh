#!/bin/sh

. ../../setEnvironment.sh

# classpath for JDK 1.2, 1.3
# CP=$CP:../../../lib/eval/ecc/iaik_ecc.jar

# classpath for JDK 1.4 
# CP=$CP:../../../lib/eval/ecc/signed/iaik_ecc.jar

# classpath for JDK 1.5 or later 
CP=$CP:../../../lib/eval/ecc/signed/iaik_eccelerate.jar
CP=$CP:../../../lib/eval/ecc/signed/iaik_eccelerate_cms.jar
CP=$CP:../../../lib/eval/ecc/signed/iaik_eccelerate_addon.jar

$JAVA -classpath $CP demo.smime.ecc.SMimeEccDemo


