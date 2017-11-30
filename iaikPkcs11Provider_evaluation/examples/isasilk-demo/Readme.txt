These demos show how to use the IAIK PKCS#11 provider in combination with  
iSaSiLk for client authentication. For instance, the demo uses an inserted
smart card to do client authentication. It reads the client certificate from
the smart card and creates a signature on the card during SSL handshake for
client authentication.
If not already present, you must place the IAIK-SSL library file iaik_ssl.jar
in the lib directory. You can download an evaluation version from our website
http://jce.iaik.tugraz.at/sic/Download.