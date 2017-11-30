@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.signedData.SignedDataOutputStreamDemo

pause
