@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.envelopedData.EnvelopedDataOutputStreamDemo

pause
