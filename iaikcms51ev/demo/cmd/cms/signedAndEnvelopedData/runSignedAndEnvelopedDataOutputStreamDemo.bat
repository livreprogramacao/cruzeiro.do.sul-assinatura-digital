@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.signedAndEnvelopedData.SignedAndEnvelopedDataOutputStreamDemo

pause
