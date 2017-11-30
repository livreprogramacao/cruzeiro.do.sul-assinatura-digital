This directory contains shell scripts for running demos
showing how to use the CMS content type SignedData 
for signing digital documents.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.


CertListDemo:
=============

Parses a CMS (PKCS#7) formatted certificate list (.p7c)

Usage:

Start the demo by running the shell script and specifying the
.p7c file to be parsed:

   ./runCertListDemo.sh <cert list file>

e.g.:

  ./runCertListDemo.sh certList.p7c


CounterSignatureDemo:
=====================

Shows how to counter-sign ("sign in serial") a SignedData message.

Usage:

Start the demo by running 

   ./runCounterSignatureDemo.sh



PssSignedDataDemo:
==================

SignedData demo that uses the PKCS#v2.1 RSA PSS signature scheme.

Usage:

Start the demo by running 

   ./runPssSignedDataDemo.sh


SignedDataDemo:
===============

Shows how to use the IAIK-CMS SignedData and SignedDataStream
classes for signing digital documents. Contains stream and
non-stream based samples for both, sender (signing, encoding) 
and recipient (parsing, verifying) side SignedData processing.
Demonstrates the usage of different signature algorithms 
(RSA, DSA) and key identifiers (IssuerAndSerialNumber, 
SubjectKeyIdentifier).

Usage:

Start the demo by running

   ./runSignedDataDemo.sh 



SignedDataOutputStreamDemo:
===========================

Shows how to use the IAIK-CMS SignedDataOutputStream class for
signing digital documents.

Usage:

Start the demo by running

   ./runSignedDataOutputStreamDemo.sh 



SignedDataDemoWithAdditionalSignerInfo:
=======================================

Shows how to use the non-stream based SignedData implementation
for adding a new signer to an already existing SignedData object.

Usage:

Start the demo by running

   ./runSignedDataDemoWithAdditionalSignerInfo.sh 





SignedDataStreamDemoWithAdditionalSignerInfo:
=============================================

Shows how to use the stream based SignedData implementation for
adding a new signer to an already existing SignedData object.

Usage:

Start the demo by running

   ./runSignedDataStreamDemoWithAdditionalSignerInfo.sh 



