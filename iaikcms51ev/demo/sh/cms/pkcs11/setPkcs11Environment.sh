#!/bin/sh

# Do not run this batch file separatly. It is called by the
# other batch files to setup the classpath for the PKCS#11 demos

. ../../setEnvironment.sh

# add PKCS#11 wrapper and provider jars to classpath (JKD 1.2, JDK 1.3))
# CP=$CP:../../../lib/eval/pkcs11/iaikPkcs11Wrapper.jar:../../../lib/eval/pkcs11/iaikPkcs11Provider.jar

# add PKCS#11 wrapper and provider jars to classpath (JKD 1.4 or later)
CP=$CP:../../../lib/eval/pkcs11/iaikPkcs11Wrapper.jar:../../../lib/eval/pkcs11/signed/iaikPkcs11Provider.jar


# set the path where to find the pkcs11wrapper.so
JAVA_LIBRARY_PATH="../../../lib/eval/pkcs11/linux_x86"

