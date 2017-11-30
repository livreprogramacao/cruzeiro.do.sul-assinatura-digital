#!/bin/sh

. ../setEnvironment.sh

$JAVA -classpath $CP demo.x509.net.ldap.LdapCrlSearch $@

