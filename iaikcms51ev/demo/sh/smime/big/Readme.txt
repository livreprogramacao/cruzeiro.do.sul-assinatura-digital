This directory contains a shell script for running 
an S/MIME demo showing the usage of a temporary file 
directory for intermediately storing message contents
during parsing and cryptographically processing big
S/MIME messages.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.
The JavaMail (TM) and JavaBeans (TM) Activation 
Framework (JAF) files (mail.jar, activation.jar)
are also located in the ../../../lib directory.



Usage:
======

Start the demo by running

   ./runBigSMimeMailDemo.sh 



The data for this demo is randomly created and stored into a
file which is deleted again at the end of this demo. Note
that running this demo may take some certain time because
it processes some MB of data.

