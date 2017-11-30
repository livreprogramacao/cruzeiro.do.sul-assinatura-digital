@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.basic.BinarySignedDemo

pause
