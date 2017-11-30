This demo shows how to use the IAIK PKCS#11 provider in a java servlet.
For every servlet instance a new PKCS#11-Provider instance is registered, which has to be removed when destroying the servlet instance.

Please ensure that the required jar-files (servlet jar-files and IAIK jar-files) are in the correct classpath.
If Tomcat is used, the servlet-directory has to be specified in the server.xml of the tomcat installation directory by the following line:
<Context path="/<servletname>" reloadable="true" docBase="<pathToServlet>" workDir="<pathToServlet>\work" />