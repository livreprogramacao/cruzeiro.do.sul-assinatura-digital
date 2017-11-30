@rem for JDK 1.2.x assuming that you have JNDI jar files in the ../lib directory
@rem set CP=../../../lib/iaik_jce.jar;../../../lib/iaik_jce_demo.jar;../../../lib/jndi.jar;../../../lib/ldap.jar;../../../lib/providerutil.jar

@rem for JDK 1.3.x
@rem set CP=../../../lib/iaik_jce.jar;../../../lib/iaik_jce_demo.jar;

@rem for JDK 1.4 and later
set CP=../../../lib-signed/iaik_jce.jar;../../../lib/iaik_jce_demo.jar;

@rem set which Java VM to use
@rem set JAVA=C:/Java/jre1.2.2/bin/java.exe
@rem set JAVA=C:/Java/jre1.3.1/bin/java.exe
@rem set JAVA=C:/Java/jre1.4.2/bin/java.exe
@rem set JAVA=C:/Java/jre1.5.0/bin/java.exe
set JAVA=java
