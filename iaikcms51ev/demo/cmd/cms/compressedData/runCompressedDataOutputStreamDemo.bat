@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.compressedData.CompressedDataOutputStreamDemo

pause
