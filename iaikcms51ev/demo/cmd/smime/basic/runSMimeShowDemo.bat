@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.smime.basic.SMimeShowDemo %*

pause
