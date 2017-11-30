@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.data.DataOutputStreamDemo

pause
