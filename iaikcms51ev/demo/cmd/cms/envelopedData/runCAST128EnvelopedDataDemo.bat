@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.envelopedData.CAST128EnvelopedDataDemo

pause
