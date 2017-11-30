@echo on

call setPkcs11Environment

"%JAVA%" -classpath %CP% -Djava.library.path=%JAVA_LIBRARY_PATH% demo.cms.pkcs11.ExplicitSignedDataStreamDemo %*

pause
