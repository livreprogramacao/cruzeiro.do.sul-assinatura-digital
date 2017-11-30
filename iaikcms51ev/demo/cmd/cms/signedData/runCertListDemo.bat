@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.signedData.CertListDemo %1

pause
