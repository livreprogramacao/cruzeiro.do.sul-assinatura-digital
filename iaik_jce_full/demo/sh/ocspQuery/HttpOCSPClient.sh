#!/bin/sh

. ../setEnvironment.sh

$JAVA -classpath $CP demo.x509.ocsp.HttpOCSPClient $@

