#!/bin/sh

# setting classpath and jre used by the demo shell scripts

# *********************
# *     CLASSPATH     *
# *********************

#  for JDK 1.2.x assuming that you have JNDI jar files in the ../lib directory
#  CP="../../../lib/iaik_jce.jar:../../../lib/iaik_jce_demo.jar:../../../lib/jndi.jar:../../../lib/ldap.jar:../../../lib/providerutil.jar"

#  for JDK 1.3.x
#  CP="../../../lib/iaik_jce.jar:../../../lib/iaik_jce_demo.jar"

#  for JDK 1.4 and later
CP="../../../lib-signed/iaik_jce.jar:../../../lib/iaik_jce_demo.jar"

# *********************
# *      Java VM      *
# *********************


# set which Java VM to use

# JDK 1.2.2
# JAVA_HOME="/usr/lib/jvm/jdk1.2.2"

# JDK 1.3.1
# JAVA_HOME="/usr/lib/jvm/jdk1.3.1"

# 1.4.2
# JAVA_HOME="/usr/lib/jvm/jdk1.4.2"

# JDK 1.5.0
# JAVA_HOME="/usr/lib/jvm/jdk1.5.0"

# JDK 1.6.0
# JAVA_HOME="/usr/lib/jvm/jdk1.6.0"

# assume JDK 1.5.0 installed in /usr/lib/jvm/jdk1.5.0
JAVA_HOME="/usr/lib/jvm/jdk1.5.0"


# assume default installed java version
JAVA="java"
