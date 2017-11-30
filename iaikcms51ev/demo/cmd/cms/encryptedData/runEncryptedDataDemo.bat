@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.encryptedData.EncryptedDataDemo

pause
