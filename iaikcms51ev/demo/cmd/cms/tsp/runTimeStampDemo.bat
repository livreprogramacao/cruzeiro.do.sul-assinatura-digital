@echo on

call ../../setEnvironment

@rem add iaik_tsp.jar to classpath
set CP=%CP%;../../../lib/eval/tsp/iaik_tsp.jar

"%JAVA%" -classpath %CP% demo.cms.tsp.TimeStampDemo

pause
