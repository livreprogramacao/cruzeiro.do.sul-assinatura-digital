#!/bin/sh

# setting classpath and jre used by the demo shell scripts

# *********************
# *     CLASSPATH     *
# *********************

# for JDK 1.2.x or JDK 1.3.x
# CP="../../../lib/iaik_jce.jar:../../../lib/iaik_cms.jar:../../../lib/iaik_cms_demo.jar:../../../lib/activation.jar:../../../lib/mail.jar"

# for JDK 1.4 and JDK 1.4
# CP="../../../lib/signed/iaik_jce.jar:../../../lib/iaik_cms.jar:../../../lib/iaik_cms_demo.jar:../../../lib/activation.jar:../../../lib/mail.jar"

# for JDK 1.6 and later
CP="../../../lib/signed/iaik_jce.jar:../../../lib/iaik_cms.jar:../../../lib/iaik_cms_demo.jar:../../../lib/mail.jar"


# *********************
# *      Java VM      *
# *********************


# set which Java VM to use

# JDK 1.2.2
# JAVA_HOME="/usr/java/jdk1.2.2"

# JDK 1.3.1
# JAVA_HOME="/usr/java/jdk1.3.1"

# 1.4.2
# JAVA_HOME="/usr/java/jdk1.4.2"

# JDK 1.5.0
# JAVA_HOME="/usr/java/jdk1.5.0"

# JDK 1.6.0
JAVA_HOME="/usr/java/jdk1.6.0"

# JDK 1.7.0
# JAVA_HOME="/usr/java/jdk1.7.0"

# assume default installed java version
JAVA="java"





