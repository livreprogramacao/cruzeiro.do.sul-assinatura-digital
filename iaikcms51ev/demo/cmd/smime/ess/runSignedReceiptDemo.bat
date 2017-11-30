@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.ess.SignedReceiptDemo

pause
