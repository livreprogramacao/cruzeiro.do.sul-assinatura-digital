This directory contains makefiles written for GNU-Make. The Makefile.win32 
works under Windows using Cygwin GNU utilities.
Modify the paths in the Makefile.win32 if necessary. You may also need to 
configure a different PKCS#11 library in the 
resources\iaik\pkcs\pkcs11\provider\IAIKPkcs11.properties to fit your
PKCS#11 hardware. Do not forget to repackage and resign the applet's jar 
file, after modifying the configuration.
For the RSASigningApplet demo to run, you must copy the pkcs11wrapper.dll
file to a location where your Java VM can find it. This may be the system
directory or the bin directory of your Java plug-in. Moreover, the applet
need to be signed, otherwise it would not be able to access the 
pkcs11wrapper.dll library and install JCA providers. 
Since the applet also uses the wrapper, the wrapper also needs to be signed.
And you will also need to use the signed versions of the IAIK PKCS#11 JCE
provider and of the IAIK JCE (software-)provider.
There is a demo keystore with a signature key in the test directory which can 
be used for testing purposes. You may use SUN's jarsigner tool for signing the 
demo jar file and the wrapper jar file or you may also use the JarSigner from 
IAIK, which is available together with the IAIK CMS-S/MIME package. You can 
download an evaluation version from our website
http://jce.iaik.tugraz.at/sic/Download.
The RSASigningDemoApplet.html starts the applet. You must open the Java console 
of your VM to see the output. This applet was only tested with SUN's Java plug-
in 1.4.0_02. If you want to run it with an older version, you must ensure that 
you have the JCE framework included. If you use IAIK's implementation, i.e. 
iaik_javax_crypto.jar, you can put it in the jre/lib/ext directory of your plug-
in, or you can just add it to the applet. If you just add it to the applet,
it may be necessary to sign the jar file.
If you have problems with access rights with SUN's Java plug-in, you may try to
import the signing certificate into your plug-in as trusted certificate.
