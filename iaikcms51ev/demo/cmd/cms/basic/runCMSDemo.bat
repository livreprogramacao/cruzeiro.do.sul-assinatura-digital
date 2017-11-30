@echo on

call ../../setEnvironment

"%JAVA%" -classpath %CP% demo.cms.basic.CMSDemo

pause
