@echo on

call ../../setEnvironment

@rem classpath for JDK 1.1, 1.2, 1.3 
rem set CP=%CP%;../../../lib/iaik_esdh.jar;

@rem classpath for JDK 1.4 or later
set CP=%CP%;../../../lib/signed/iaik_esdh.jar;

"%JAVA%" -classpath %CP% demo.cms.authenticatedData.AuthEnvelopedDataOutputStreamDemo

pause
