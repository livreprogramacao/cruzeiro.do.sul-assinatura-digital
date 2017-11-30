This directory contains shell scripts for running demos
showing how to use the IAIK-PKCS#11 provider with
IAIK-CMS for signing or decrypting contents with
a key stored on a smart card.

The required libraries (iaik_jce.jar, iaik_cms.jar, 
iaik_cms_demo.jar) have to be located in the ../../../lib directory.
If you are using a JDK version > 1.3, you will need the signed 
version of iaik_jce.jar located in the ../../../lib/signed directory.
The IAIK PKCS#11 files (eval versions; iaikPkcs11Wrapper.jar; 
iaikPkcs11Provider.jar, signed and unsigned version; shared
library pkcs11wrapper.so) are located in the ../../../lib/eval/pkcs11
direcory.

When running the demos you must specify where to find the PKCS#11
module for your smartcard or HSM.



ExplicitSignedDataStreamDemo:
=============================

Shows how to sign data (explicit, the content data is not included) according
to CMS using the IAIK PKCS#11 provider for accessing the private key on
a smart card.

Usage:

Start the demo by running the shell script and specifying the name of
(and path to) the PKCS#11 module to be used:

   ./runExplicitSignedDataStreamDemo.sh <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.so" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   ./runExplicitSignedDataStreamDemo.sh aetpkss1.so 


ImplicitSignedDataStreamDemo:
=============================

Shows how to sign data (implicit, the content data is included) according
to CMS using the IAIK PKCS#11 provider for accessing the private key on
a smart card.

Usage:

Start the demo by running the shell script and specifying the name of
(and path to) the PKCS#11 module to be used:

   ./runImplicitSignedDataStreamDemo.sh <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.so" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   ./runImplicitSignedDataStreamDemo.sh aetpkss1.so


EnvelopedDataStreamDemo:
========================

Shows how to en- and decrypt data with the CMS EnvelopedData type using
the IAIK PKCS#11 provider for accessing the private key on a smart card.

Usage:

Start the demo by running the shell script and specifying the name of
(and path to) the PKCS#11 module to be used:

   ./runEnvelopedDataStreamDemo.sh <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.so" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   ./runEnvelopedDataStreamDemo.sh aetpkss1.so  




