This directory contains shell scripts for running 
several S/MIME demos showing the usage of the
IAIK-CMS/SMIME library for signing, encrypting,...
and decrypting, verifying,... S/MIME messages.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.
The JavaMail (TM) and JavaBeans (TM) Activation 
Framework (JAF) files (mail.jar, activation.jar)
are also located in the ../../../lib directory.



SMimeDemo:
==========

Shows how to use the JavaMail(TM) API together with 
IAIK-CMS (S/MIME) to handle (creation, encrypting, 
signing,... parsing, decrypting, verifying,...) 
S/MIME messages. Combines the functionality of the 
SMimeSend and SMimeShow demos without the necessity
of being connected to a mail server (the messages 
are written and read from streams).


Usage:

Start the demo by running

   ./runSMimeDemo.sh 



SMimeV3Demo:
==========

Same as SMimeDemo, but also uses v3-style key identifier
and recipient info types.

THIS DEMO REQUIRES TO HAVE iaik_esdh.jar IN YOUR CLASSPATH
WHICH BY DEFAULT IS NOT INCLUDED IN THE IAIK-CMS DISTRIBUTION.
You can download iaik_esdh.jar from http://jce.iaik.tugraz.at/download/
and put it into the ../../../lib (unsigned version) and
../../../lib/signed directory (signed version).



Usage:

Start the demo by running

   ./runSMimeDemo.sh



BinarySignedDemo:
=================

Shows how to create, sign and then parse/verify a mulitpart/signed 
message where the content is not canonicalized.



Usage:

Start the demo by running

   ./runBinarySignedDemo.sh




SMimeSendDemo:
==============

Shows how to use the JavaMail(TM) API together with IAIK-CMS (S/MIME) to
create, sign, encrypt,... and send S/MIME mails over the internet. 
Requires that you are are connected to a mail server which sends your
messages to the intended recipient(s). Receiving and parsing the
messages created by this demo is demonstrated by the SMimeShow demo.
Note that this demo uses the certificates from the demo keystore.
By default this demo used "mailhost" as host, "John SMime" as sender
name, and "smimetest@iaik.tugraz.at" as sender and also as recipient 
mail address. "smimetest@iaik.tugraz.at" is also the email address
contained in the demo certificates. Although you should specify other
email addresses to send the test messages to yourself, be aware that 
the certificate email check may fail on the receiving side (SMimeShowDemo).



Usage:

Start the demo by running the shell script and specifying
mail host, sender name, sender and recipient mail address:

   ./runSMimeSendDemo.sh [-H host] [-S sender name] [-F (From) sender address] [-T (To) recipient address]

e.g.:


   ./runSMimeSendDemo.sh -H mailhost -S "John SMime" -F smimetest@iaik.tugraz.at -T smimetest@iaik.tugraz.at




SMimeShowDemo:
==============

Shows how to use the JavaMail(TM) API together with IAIK-CMS
(S/MIME) to download S/MIME messages from a mail server and
parse and decrypt (if necessary) their contents and verify
any included signatures. Requires that you are are connected
to a mail server from which you can download the messages
created by the SMimeSend demo.



Usage:

Start the demo by running the shell script and specifying
mail host, protocol, and user and password of your mail
account:

   ./runSMimeShowDemo.sh [-T protocol] [-H host] [-U user] [-P password]

e.g.:


   ./runSMimeShowDemo.sh -T pop3 -H mailhost -U smimetest -P password

See the SMimeShowDemo Javadoc/Source for additional
parameters you can specify.



ProcessMessageDemo:
===================

Shows how to cryptographically process (e.g. sign or encrypt) a received
message.



Usage:

Start the demo by running

   ./runProcessMessageDemo.sh



CMSStreamDemo:
==============

Demonstrates the CMS related part of the S/MIME library for
creating/parsing signed and/or encrypted CMS messages.


THIS DEMO REQUIRES TO HAVE iaik_esdh.jar IN YOUR CLASSPATH
WHICH BY DEFAULT IS NOT INCLUDED IN THE IAIK-CMS DISTRIBUTION.
You can download iaik_esdh.jar from http://jce.iaik.tugraz.at/download/
and put it into the ../../../lib (unsigned version) and
../../../lib/signed directory (signed version).


Usage:

Start the demo by running

   ./runCMSStreamDemo.sh