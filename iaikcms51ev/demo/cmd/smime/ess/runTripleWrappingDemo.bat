@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.ess.TripleWrappingDemo

pause
