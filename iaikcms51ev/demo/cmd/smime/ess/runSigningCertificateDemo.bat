@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.ess.SigningCertificateDemo

pause
