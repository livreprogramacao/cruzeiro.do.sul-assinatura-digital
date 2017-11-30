This directory contains cmd files for running demos
showing how to use the CMS content type EnvelopedData
for content en/decryption.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the 
../../../lib directory. If you are using a JDK
version > 1.3, you will need the signed version of 
iaik_jce.jar located in the ../../../lib/signed directory.


ArcFourEnvelopedDataDemo:
=========================

Shows how to handle EnvelopedData messages when the ARCFOUR
(RC4(TM) compatible) stream cipher is used for encrypting 
the content. Compares automatic EncryptedContentInfo 
processing with application/user written EncryptedContentInfo
processing.

Usage:

Start the demo by running

   > runArcFourEnvelopedDataDemo.bat 



CAST128EnvelopedDataDemo:
=========================

Shows how to handle EnvelopedData messages when CAST128 is used
for encrypting the content. Compares automatic 
parameter/EncryptedContentInfo processing with 
application/user written parameter/EncryptedContentInfo
processing.


Start the demo by running

   > runCAST128EnvelopedDataDemo.bat 



EncryptedContentInfoDemo:
=========================

Shows how the EncryptedContentInfo and EncryptedContentInfoStream
implementations maybe used for building/encoding/parsing 
EnvelopedData objects.


Start the demo by running

   > runEncryptedContentInfoDemo.bat 



EnvelopedDataDemo:
==================

Shows how to use the IAIK-CMS EnvelopedData and EnvelopedDataStream
classes for recipient-specific encrypting digital documents. Contains
stream and non-stream based samples for both, sender (encrypting,
encoding) and recipient (parsing, decrypting) side EnvelopedData
processing. Demonstrates the usage of the basic RecipientInfo types
KeyTransRecipientInfo, KeyAgreeRecipientInfo and KEKRecipientInfo
with key management techniques RSA, ESDH and TripleDES KeyWrap,
respectively.

THIS DEMO REQUIRES TO HAVE iaik_esdh.jar IN YOUR CLASSPATH
WHICH BY DEFAULT IS NOT INCLUDED IN THE IAIK-CMS DISTRIBUTION.
You can download iaik_esdh.jar from http://jce.iaik.tugraz.at/download/
and put it into the ../../../lib (unsigned version) and
../../../lib/signed directory (signed version).

Usage:

Start the demo by running

   > runEnvelopedDataDemo.bat 




EnvelopedDataOutputStreamDemo:
==============================

Shows how to use the IAIK-CMS EnvelopedDataOutputStream
implementation.

Usage:

Start the demo by running

   > runEnvelopedDataOutputStreamDemo.bat 



FileEncryptionDemo:
===================

Shows how to use the CMS PasswordRecipientInfo type for
password based encrypting the contents of a file (and 
later decrypting it again) with the CMS EnvelopedDataStream
content type. The file encrypted by this demo is named
"test.html" and is located in the current working directory.

Usage:

Start the demo by running

   > runFileEncryptionDemo.bat 




OaepEnvelopedDataDemo:
======================

Uses RSA key transport with PKCS#1v2.1 OAEP padding for 
encrypting the content encryption key of a CMS EnvelopedData 
message.  	


Usage:

Start the demo by running

   > runOaepEnvelopedDataDemo.bat 



PasswordRecipientInfoDemo:
==========================

Shows how to password-based encrypt/decrypt digital documents 
by using the CMS EnvelopedData RecipientInfo type 
PasswordRecipientInfo (RFC 2311). Contains stream and
non-stream based demos.  	


Usage:

Start the demo by running

   > runPasswordRecipientInfoDemo.bat



RC2EnvelopedDataDemo:
=====================

Shows how to handle EnvelopedData messages when RC2 is used for
encrypting the content. Compares automatic parameter/EncryptedContentInfo
processing with application/user written parameter/EncryptedContentInfo
processing.  	


Usage:

Start the demo by running

   > runRC2EnvelopedDataDemo.bat

