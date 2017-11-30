This directory contains shell scripts for running PKCS#7 - CMS
interoperability demos.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.
                                                                     

PKCS7CMSDataDemo:
=================

Compares the PKCS#7 Data(Stream) implementation of the IAIK-JCE
library with the CMS Data(Stream) implementation of IAIK-CMS.

Usage:

Start the demo by running

   ./runPKCS7CMSDataDemo.sh 



PKCS7CMSDigestedDataDemo:
=========================

Compares the PKCS#7 DigestedData(Stream) implementation of the 
IAIK-JCE library with the CMS DigestedData(Stream) implementation
of IAIK-CMS.


Usage:

Start the demo by running

   ./runPKCS7CMSDigestedDataDemo.sh 



PKCS7CMSEncryptedContentInfoDemo:
=================================

Compares the PKCS#7 EncryptedContentInfo(Stream) implementation of
the IAIK-JCE library with the CMS EncryptedContentInfo(Stream) 
implementation of IAIK-CMS.


Usage:

Start the demo by running

   ./runPKCS7CMSEncryptedContentInfoDemo.sh 




PKCS7CMSEncryptedDataDemo:
==========================

Compares the PKCS#7 EncryptedData(Stream) implementation of the 
IAIK-JCE library with the CMS EncryptedData(Stream) implementation
of IAIK-CMS.

Usage:

Start the demo by running

   ./runPKCS7CMSEncryptedDataDemo.sh 




PKCS7CMSEnvelopedDataDemo:
==========================

Compares the PKCS#7 EnvelopedData(Stream) implementation of the 
IAIK-JCE library with the CMS EnvelopedData(Stream) implementation
of IAIK-CMS.

Usage:

Start the demo by running

   ./runPKCS7CMSEnvelopedDataDemo.sh 



PKCS7CMSSignedDataDemo:
=======================

Compares the PKCS#7 SignedData(Stream) implementation of the 
IAIK-JCE library with the CMS SignedData(Stream) implementation 
of IAIK-CMS.

Usage:

Start the demo by running

   ./runPKCS7CMSSignedDataDemo.sh 



