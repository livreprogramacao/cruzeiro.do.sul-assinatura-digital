This directory contains a batch file (setEnvironment.bat) 
for setting the environment variables (classpath) required 
for the several IAIK-CMS/SMIME demos. 

The batch file included in this directory must not be
executed separately. It is automatically called from the 
demo launching batch files contained in the sub folders 
of this directory. However, before running a demo you may
have to edit the setEnvironment.bat file to point to the
JDK version you want to use. 
By default the VM currently installed on your computer
is taken assuming that you are using a JDK version >= 1.4.
If you use a JDK version < 1.4 please disable the current
classpath settings in setEnvironment.bat and enable the
classpath entry suitable for your JDK by removing the
initial @rem from the corresponding line.


For running any of the demos go into the corresponding
sub-folder and read the instructions of its Readme.txt
file.

The following demos are located in the following
sub-folders of this directory:

CMS Demos:
==========

- basic: Basic demos for all CMS content types
- authenticatedData: CMS AuthenticatedData content type demos
- authEnvelopedData: CMS AuthEnvelopedData content type demos
- compressedData: CMS CompressedData content type demos
- data: CMS Data content type demos
- digestedData: CMS DigestedData content type demos
- encryptedData: CMS EncryptedData content type demos
- envelopedData: CMS EnvelopedData content type demos
- signedData: CMS SignedData content type demos
- signedAndEnvelopedData: CMS Signed- and EnvelopedData demos
- pkcs7cms: CMS - PKCS#7 interoparability demos
- ecc: Elliptic Curve EnvelopedData and SignedData demos; requires
       the IAIK-ECCelerate(TM) library in your classpath
- pkcs11: PKCS#11 CMS demos
- tsp: Shows how to add a time stamp to a SignedData message


S/MIME Demos:
=============

- basic: Basic S/MIME demos for signing, encrypting,... and decrypting, 
         verifying,... S/MIME messages
- big: Processing very big messages by intermedially storing
       message contents in a temporary directory 
- ecc: Elliptic Curve S/MIME demos; requires
       the IAIK-ECCelerate(TM) library in your classpath
- ess: Enhanced Security Services for S/MIME (ESS) demos
- pkcs11: PKCS#11 S/MIME demos



