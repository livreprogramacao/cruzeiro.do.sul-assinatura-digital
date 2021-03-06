This directory contains shell scripts for running S/MIME demos
showing how to use elliptic curve cryptography (ECDSA, ECDH) 
for signing or encrypting S/MIME messages.

The required libraries (iaik_jce.jar, iaik_cms.jar, iaik_cms_demo.jar) 
have to be located in the ../../../lib directory. If you are using a JDK
version > 1.3, you will need the signed version of 
iaik_jce.jar located in the ../../../lib/signed directory.
The JavaMail (TM) and JavaBeans (TM) Activation 
Framework (JAF) files (mail.jar, activation.jar)
are also located in the ../../../lib directory.

THESE DEMOS REQUIRE TO HAVE IAIK ECCelerate(TM) LIBRARY IN YOUR CLASSPATH
WHICH BY DEFAULT IS NOT INCLUDED IN THE IAIK-CMS DISTRIBUTION.
You can download iaik_eccelerate.jar and iaik_eccelerate_cms.jar 
(CMS SecurityProvider for ECCelerate) from http://jce.iaik.tugraz.at/download/
and put it into the ../../../lib/eval/ecc/signed directory.
If you want to use point compression and arithmetic speedups
you also may put the iaik_eccelerate_addon.jar file into the
../../../lib/eval/ecc/signed directory (however, please be aware about
patent regulations, see the IAIK-ECCelerate(TM) documentation for more
information).

Since IAIK ECCelerate requires JDK 1.5 or later, please contact 
us (jce-support@iaik.tugraz.at) to get our old IAIK-ECC library 
if you want to use Elliptic Curve Cryptography with JDK versions prior 1.5. 


SMimeEccDemo:
=============

Shows how to use elliptic curve cryptography (ECDSA, ECDH) 
for signing or encrypting S/MIME messages.

Usage:

Start the demo by running

   > runSMimeEccDemo.sh 



SMimeEccSuiteBDemo:
===================

Demonstrates the usage of the IAIK S/MIME implementation 
to create and parse ECDSA signed and/or ECDH based encrypted
S/MIMEv3 messages according to RFC 5008 ("Suite B in 
Secure/Multipurpose Internet Mail Extensions"):

Usage:

Start the demo by running

   > runSMimeEccSuiteBDemo.sh 



