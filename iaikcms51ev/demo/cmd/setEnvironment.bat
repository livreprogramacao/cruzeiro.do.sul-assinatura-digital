@rem setting classpath and jre used by the demo batch files

@rem *********************
@rem *     CLASSPATH     *
@rem *********************

@rem for JDK 1.2.x or JDK 1.3.x
@rem set CP=../../../lib/iaik_jce.jar;../../../lib/iaik_cms.jar;../../../lib/iaik_cms_demo.jar;../../../lib/activation.jar;../../../lib/mail.jar

@rem for JDK 1.4 and JDK 1.5
rem set CP=../../../lib/signed/iaik_jce.jar;../../../lib/iaik_cms.jar;../../../lib/iaik_cms_demo.jar;../../../lib/activation.jar;../../../lib/mail.jar

@rem for JDK 1.6 and later
set CP=../../../lib/signed/iaik_jce.jar;../../../lib/iaik_cms.jar;../../../lib/iaik_cms_demo.jar;../../../lib/mail.jar



@rem *********************
@rem *      Java VM      *
@rem *********************


@rem set which Java VM to use

@rem jre for 1.2.2
@rem set JAVA=C:/Java/jdk1.2.2/bin/java.exe

@rem jre for 1.3.1
@rem set JAVA=C:/Java/jdk1.3.1/bin/java.exe

@rem jre for 1.4.2
@rem set JAVA=C:/Java/jdk1.4.2/bin/java.exe

@rem jre for 1.5.0
@rem set JAVA=C:/Java/jdk1.5.0/bin/java.exe

@rem jre for 1.6.0
@rem set JAVA=C:/Java/jdk1.6.0/bin/java.exe

@rem jre for 1.7.0
@rem set JAVA=C:/Java/jdk1.7.0/bin/java.exe


@rem assume default installed java version
set JAVA=java


