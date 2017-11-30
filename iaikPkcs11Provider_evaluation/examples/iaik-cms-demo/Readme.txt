These demos show how to use the IAIK PKCS#11 provider in combination with  
IAIK CMS for signed and encrypted data and email. 
The demos show how to sign and decrypt data in CMS format. Moreover, there
is a demo showing how to sign an email using the S/MIME functionality of
IAIK CMS.
Configure your PKCS#11 module by editing the 
resources/iaik/pkcs/pkcs11/provider/IAIKPkcs11.properties file.
If not already present, you must place the IAIK CMS library file iaik_cms.jar
in the lib directory. You can download an evaluation version from our website
http://jce.iaik.tugraz.at/sic/Download.
In addition, you have to place the JAR files of the Java Mail API (mail.jar)
and for JDK < 1.6 the Java Activation Framework (activation.jar) in the lib directory.
