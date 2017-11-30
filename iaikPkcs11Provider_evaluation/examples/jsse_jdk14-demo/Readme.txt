These demos show how to use the IAIK PKCS#11 provider in combination with the 
JSSE API for client authentication. For instance, the demo uses an inserted
smart card to do client authentication. It reads the client certificate from
the smart card and creates a signature on the card during SSL handshake for
client authentication.