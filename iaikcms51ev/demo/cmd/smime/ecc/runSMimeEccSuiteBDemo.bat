@echo on

call ../../setEnvironment

@rem classpath for JDK 1.2, 1.3
@rem set CP=%CP%;../../../lib/eval/ecc/signed/iaik_ecc.jar

@rem classpath for JDK 1.4
@rem set CP=%CP%;../../../lib/eval/ecc/signed/iaik_ecc.jar

@rem classpath for JDK 1.5 or later 
set CP=%CP%;../../../lib/eval/ecc/signed/iaik_eccelerate.jar;
set CP=%CP%;../../../lib/eval/ecc/signed/iaik_eccelerate_cms.jar;
set CP=%CP%;../../../lib/eval/ecc/signed/iaik_eccelerate_addon.jar

"%JAVA%" -classpath %CP% demo.smime.ecc.SMimeEccSuiteBDemo

pause
