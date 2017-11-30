This directory contains cmd files for running demos
showing how to use the CMS content type AuthenticatedData
for protecting the integrity of some contents be means
of a Message Authentication Code.

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



AuthenticatedDataDemo:
======================

Shows how to use the IAIK-CMS AuthenticatedData and
AuthenticatedDataStream implementations.

Usage:

Start the demo by running

   > runAuthenticatedDataDemo.bat 


AuthenticatedDataOutputStreamDemo:
==================================

Shows how to use the IAIK-CMS AuthenticatedDataOutputStream
implementation.

Usage:

Start the demo by running

   > runAuthenticatedDataOutputStreamDemo.bat 





