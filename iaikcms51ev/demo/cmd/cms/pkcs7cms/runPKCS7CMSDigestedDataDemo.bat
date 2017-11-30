@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.pkcs7cms.PKCS7CMSDigestedDataDemo

pause
