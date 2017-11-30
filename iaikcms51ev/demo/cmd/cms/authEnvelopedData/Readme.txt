This directory contains cmd files for running demos
showing how to use the CMS content type AuthEnvelopedData
for authenticated encrypting some contents.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the 
../../../lib directory. If you are using a JDK
version > 1.3, you will need the signed version of 
iaik_jce.jar located in the ../../../lib/signed directory.

THIS DEMO REQUIRES TO HAVE iaik_esdh.jar IN YOUR CLASSPATH
WHICH BY DEFAULT IS NOT INCLUDED IN THE IAIK-CMS DISTRIBUTION.
You can download iaik_esdh.jar from http://jce.iaik.tugraz.at/download/
and put it into the ../../../lib (unsigned version) and
../../../lib/signed directory (signed version).



AuthEnvelopedDataDemo:
======================

Shows how to use the IAIK-CMS AuthEnvelopedData and
AuthEnvelopedDataStream implementations.

Usage:

Start the demo by running

   > runAuthEnvelopedDataDemo.bat 


AuthEnvelopedDataOutputStreamDemo:
==================================

Shows how to use the IAIK-CMS AuthEnvelopedDataOutputStream
implementation.

Usage:

Start the demo by running

   > runAuthEnvelopedDataOutputStreamDemo.bat 





