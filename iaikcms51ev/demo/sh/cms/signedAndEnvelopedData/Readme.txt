This directory contains shell scripts for running demos
showing how to use a sequentiel combination of the
CMS content types SignedData and EnvelopedData for
signing and encrypting digital documents.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.



SignedAndEnvelopedDataDemo:
===========================

Shows how to use the CMS SignedData(Stream) and EnvelopedData(Stream)
classes for signing and encrypting digital documents. Contains
stream and non-stream based samples for both, sender (signing,
encrypting) and recipient (decrypting, verifying) side Signed-
and EnvelopedData processing.

Usage:

Start the demo by running

   ./runSignedAndEnvelopedDataDemo.sh 


SignedAndEnvelopedDataOutputStreamDemo:
=======================================

Shows how to use the IAIK-CMS SignedDataOutputStream and 
EnvelopedDataOutputStream  classes for signing and encrypting 
digital documents.

Usage:

Start the demo by running

   ./runSignedAndEnvelopedDataOutputStreamDemo.sh 





