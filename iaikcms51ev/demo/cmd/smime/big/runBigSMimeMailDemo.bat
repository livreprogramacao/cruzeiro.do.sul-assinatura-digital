@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.big.BigSMimeMailDemo

pause
