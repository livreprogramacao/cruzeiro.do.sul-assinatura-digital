This directory contains shell scripts for running 
several S/MIME-ESS (Enhanced Security Services
for S/MIME, RFC 2634).

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.
The JavaMail (TM) and JavaBeans (TM) Activation 
Framework (JAF) files (mail.jar, activation.jar)
are also located in the ../../../lib directory.


MLADemo:
========

Shows how to use the ESS library for implementing an
ESS mailing list agent. The demo simulates all 
representative samples given by the ESS specification
(RFC 2634, section 4.2.1).

Usage:

Start the demo by running

   ./runMLADemo.sh


SecurityLabelDemo:
==================

Shows how to handle the ESS SecurityLabel attribute to 
control access to the content of a S/MIME message.

Usage:

Start the demo by running

   ./runSecurityLabelDemo.sh 




SignedReceiptDemo:
==================

Shows how to use the ESS library for handling the ESS 
SignedReceipt attribute (the originator creates and 
sends a message containing a ReceiptRequest; the recipient
parses the request and sends back a mesage with a 
SignedReceipt; finally the originator parses and verifies
the SignedReceipt).

Usage:

Start the demo by running

   ./runSignedReceiptDemo.sh 



SigningCertificateDemo:
=======================

Shows how to handle the ESS SigningCertificate attribute 
for including signer certificate identification information
into a CMS SignerInfo object.

Usage:

Start the demo by running

   ./runSigningCertificateDemo.sh 




SigningCertificateV2Demo:
=========================

Shows how to handle the ESS SigningCertificateV2 attribute 
for including signer certificate identification information
into a CMS SignerInfo object.

Usage:

Start the demo by running

   ./runSigningCertificateV2Demo.sh 




TripleWrappingDemo:
==================

Shows how to handle (create, parse) triple wrapped 
(signed - encrypted - signed) S/MIME messages.


Usage:

Start the demo by running

   ./runTripleWrappingDemo.sh 



