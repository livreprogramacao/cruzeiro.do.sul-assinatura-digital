@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.digestedData.DigestedDataDemo

pause
