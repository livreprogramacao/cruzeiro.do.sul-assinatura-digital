@echo on

call ../../setEnvironment


"%JAVA%" -classpath %CP% demo.smime.ess.SigningCertificateV2Demo

pause
