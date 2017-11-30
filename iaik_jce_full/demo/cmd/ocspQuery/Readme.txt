This directory contains a batch file for retrieving an ocsp request 
from a server and dumping it to System.out

The required libraries (iaik_jce.jar, iaik_jce_demo.jar, 
jdk11x_update.jar -- for JDK11x) have to be located in 
the ../../../lib directory. 

Usage:

HttpOCSPClient [<responder url> <target certs file> [<requestor key (PKCS12)> <password>]]
or:
HttpOCSPClient [<responder url> <target cert file> <target issuer cert file> [<requestor key (PKCS12)> <password>]]

Examples: 
HttpOCSPClient http://ocspdemo.iaik.at John_TestUser.p7c 
HttpOCSPClient http://ocspdemo.iaik.at John_TestUser.der TestCa.der 
