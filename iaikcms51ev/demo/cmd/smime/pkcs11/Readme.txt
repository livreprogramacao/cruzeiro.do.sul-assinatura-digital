This directory contains cmd files for running demos
showing how to use the IAIK-PKCS#11 provider with
IAIK-CMS/SMIME for signing or decrypting S/MIME
messages with a key stored on a smart card.

The required libraries (iaik_jce.jar, iaik_cms.jar,
iaik_cms_demo.jar) have to be located in the 
../../../lib directory. If you are using a JDK
version > 1.3, you will need the signed version of 
iaik_jce.jar located in the ../../../lib/signed directory.
The JavaMail (TM) and JavaBeans (TM) Activation 
Framework (JAF) files (mail.jar, activation.jar)
are also located in the ../../../lib directory.


The IAIK PKCS#11 files (eval versions; iaikPkcs11Wrapper.jar; 
iaikPkcs11Provider.jar, signed and unsigned version; shared
library pkcs11wrapper.dll) are located in the ../../../lib/eval/pkcs11
direcory.

When running the demos you must specify where to find the PKCS#11
module for your smartcard or HSM.



ExplicitSignedMailDemo:
=======================

Shows how to sign S/MIME messages (content type multipart/signed) 
using the IAIK PKCS#11 provider for accessing the private key on 
a smart card.

Usage:

Start the demo by running the batch file and specifying the name of
(and path to) the PKCS#11 module to be used:

   > runExplicitSignedMailDemo.bat <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.dll" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   > runExplicitSignedMailDemo.bat aetpkss1.dll 




ImplicitSignedMailDemo:
=======================

Shows how to sign S/MIME messages (content type multipart/signed) 
using the IAIK PKCS#11 provider for accessing the private key on 
a smart card.

Usage:

Start the demo by running the batch file and specifying the name of
(and path to) the PKCS#11 module to be used:

   > runImplicitSignedMailDemo.bat <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.dll" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   > runImplicitSignedMailDemo.bat aetpkss1.dll 



EncryptedMailDemo:
==================

Shows how to en- and decrypt S/MIME messages using the IAIK PKCS#11 
provider for accessing the private key on a smart card.

Usage:

Start the demo by running the batch file and specifying the name of
(and path to) the PKCS#11 module to be used:

   > runEncryptedMailDemo.bat <PKCS#11 module name> 

e.g. (assuming that the module to be used ("aetpkss1.dll" for 
      G&D StarCos and Rainbow iKey 3000) is located in your
      current working directory):

   > runEncryptedMailDemo.bat aetpkss1.dll  




