@echo on

call setPkcs11Environment

"%JAVA%" -classpath %CP% -Djava.library.path=%JAVA_LIBRARY_PATH% demo.smime.pkcs11.ImplicitSignedMailDemo %*

pause
