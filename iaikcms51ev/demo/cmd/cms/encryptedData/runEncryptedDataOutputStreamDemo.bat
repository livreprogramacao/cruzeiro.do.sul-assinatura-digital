@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.encryptedData.EncryptedDataOutputStreamDemo

pause
