#!/bin/sh

. setPkcs11Environment.sh

$JAVA -classpath $CP -Djava.library.path=$JAVA_LIBRARY_PATH demo.smime.pkcs11.ImplicitSignedMailDemo $@


