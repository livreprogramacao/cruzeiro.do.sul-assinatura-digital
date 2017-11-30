@rem Do not run this batch file separatly. It is called by the
@rem other batch files to setup the classpath for the PKCS#11 demos


@echo on

call ../../setEnvironment

@rem add PKCS#11 wrapper and provider jars to classpath (JKD 1.2, JDK 1.3))
@rem set CP=%CP%;../../../lib/eval/pkcs11/iaikPkcs11Wrapper.jar;../../../lib/eval/pkcs11/iaikPkcs11Provider.jar;

@rem add PKCS#11 wrapper and provider jars to classpath (JKD 1.4 or later)
set CP=%CP%;../../../lib/eval/pkcs11/iaikPkcs11Wrapper.jar;../../../lib/eval/pkcs11/signed/iaikPkcs11Provider.jar;


@rem set the path where to find the pkcs11wrapper.dll
set JAVA_LIBRARY_PATH=../../../lib/eval/pkcs11/win_x86

