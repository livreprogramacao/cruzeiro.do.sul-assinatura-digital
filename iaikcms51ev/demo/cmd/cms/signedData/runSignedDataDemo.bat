@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.signedData.SignedDataDemo

pause
