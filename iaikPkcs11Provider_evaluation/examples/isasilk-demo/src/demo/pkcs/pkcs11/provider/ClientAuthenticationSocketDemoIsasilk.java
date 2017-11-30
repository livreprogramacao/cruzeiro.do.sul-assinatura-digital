// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2015 Stiftung Secure Information and
//                           Communication Technologies SIC
// http://www.sic.st
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

package demo.pkcs.pkcs11.provider;

// class and interface imports
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.ssl.IaikPkcs11SecurityProviderIsasilk;
import iaik.security.provider.IAIK;
import iaik.security.ssl.CipherSuiteList;
import iaik.security.ssl.SSLClientContext;
import iaik.security.ssl.SSLSocket;
import iaik.security.ssl.SecurityProvider;
import iaik.utils.Util;

/**
 * This class shows how to use a keystore of the PKCS#11 provider to authenticate a client to a
 * server using RSA certificate and signature. The certificate will be read from the smart card and
 * the signature for client authentication is done on the card.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class ClientAuthenticationSocketDemoIsasilk {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The PKCS#11 keystore that holds the clients keys and certificates.
   */
  protected KeyStore pkcs11ClientKeystore_;

  protected String hostName_;

  protected int port_;

  protected String file_;

  protected SSLSocket sslSocket_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public ClientAuthenticationSocketDemoIsasilk(String hostName, int port, String file) {
    hostName_ = hostName;
    port_ = port;
    file_ = file;

    // special care is required during the registration of the providers
    Security.addProvider(new IAIK()); // add IAIK softweare JCE provider

    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_); // add IAIK PKCS#11 JCE provider

    // configure IAIK SSL, which operates under IAIK JSSE provider, to use PKCS#11
    // this provider uses the PKCS#11 provider when dealing with PKCS#11 keys and uses
    // the IAIK software JCE for software keys.
    IaikPkcs11SecurityProviderIsasilk iaikPkcs11SecurityProvider = new IaikPkcs11SecurityProviderIsasilk();
    iaikPkcs11SecurityProvider.setSymmetricCipherViaPkcs11(false);
    SecurityProvider.setSecurityProvider(iaikPkcs11SecurityProvider);

    System.out.println("Installed security providers providers:\n");
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      Provider provider = providers[i];
      System.out.println("Provider " + (i + 1) + ": " + provider.getName()
          + "  version: " + provider.getVersion());
    }
  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      printUsage();
      throw new Exception("missing arguments");
    }
    String hostName = args[0];
    int port = Integer.parseInt(args[1]);
    String file = args[2];

    ClientAuthenticationSocketDemoIsasilk demo = new ClientAuthenticationSocketDemoIsasilk(
        hostName, port, file);

    demo.getKeyStore();
    demo.createSocket();
    demo.connectAndGet();
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method gets the key store of the PKCS#11 provider and stores a reference at
   * <code>pkcs11ClientKeystore_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getKeyStore() throws GeneralSecurityException, IOException {
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");

    if (tokenKeyStore == null) {
      System.out
          .println("Got no key store. Ensure that the provider is properly configured and installed.");
      throw new GeneralSecurityException("Got not key store.");
    }
    tokenKeyStore.load(null, null); // this call binds the keystore to the first instance of the
                                    // IAIKPkcs11 provider
    // if you want ot bind it to a different instance, you have to provide the provider name as
    // stream
    // see the other RSASigningDemo classes for examples

    pkcs11ClientKeystore_ = tokenKeyStore;

  }

  /**
   * This creates a SSL socket and sets the context appropriately.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If creating the socket fails.
   */
  public void createSocket() throws GeneralSecurityException, IOException {
    SSLClientContext context = new SSLClientContext();

    // add all availabel client credentials
    Enumeration aliasEnumeration = pkcs11ClientKeystore_.aliases();
    while (aliasEnumeration.hasMoreElements()) {
      String alias = (String) aliasEnumeration.nextElement();
      if (pkcs11ClientKeystore_.isKeyEntry(alias)) {
        Key key = pkcs11ClientKeystore_.getKey(alias, null); // pkcs#11 cares for the PIN
        if (key instanceof PrivateKey) {
          Certificate[] certificateChain = (Certificate[]) pkcs11ClientKeystore_
              .getCertificateChain(alias);
          if (certificateChain != null && certificateChain.length < 0) {
            X509Certificate[] x509CertificateChain = Util
                .convertCertificateChain(certificateChain);
            if (certificateChain != null && certificateChain.length > 0) {
              X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
              boolean[] keyUsage = signerCertificate.getKeyUsage();
              if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature
                                                                      // or non-repudiation, but
                                                                      // also accept if none set
                context.addClientCredentials(x509CertificateChain, (PrivateKey) key);
                break;
              }
            }
          }
        }
      }
    }

    sslSocket_ = new SSLSocket(hostName_, port_, context);

    System.out.println("Enables Cipher Suites are:");
    System.out
        .println("________________________________________________________________________________");
    CipherSuiteList enabledCipherSuiteList = context.getEnabledCipherSuiteList();
    System.out.println(enabledCipherSuiteList.toString());
    System.out
        .println("________________________________________________________________________________");
    System.out.println("##########");
  }

  /**
   * Connect to the server, send the request and read the response.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If socket communication fails.
   */
  public void connectAndGet() throws GeneralSecurityException, IOException {
    // establish SSL connection
    System.out.println("##########");
    System.out.print("doing handshake... ");
    sslSocket_.startHandshake();
    System.out.println("finished");

    // send request
    String request = "GET " + file_; // + " HTTP/1.1"; add this for a HTTP version 1.1 request
    System.out.print("sending request \"");
    System.out.print(request);
    System.out.print("\"... ");

    PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
        sslSocket_.getOutputStream())));
    char[] CRLF = { 0x0D, 0x0A };
    out.print(request);
    out.print(CRLF);
    out.print(CRLF);
    out.flush();
    System.out.println("finished");

    if (out.checkError()) {
      System.out.println("SSLSocketClient: java.io.PrintWriter error");
    }

    // read response
    System.out.println("reading response");
    System.out
        .println("________________________________________________________________________________");
    BufferedReader in = new BufferedReader(new InputStreamReader(
        sslSocket_.getInputStream()));

    String inputLine;
    while ((inputLine = in.readLine()) != null) {
      System.out.println(inputLine);
    }
    System.out
        .println("________________________________________________________________________________");

    in.close();
    out.close();
    sslSocket_.close();

    System.out.println("##########");
  }

  public static void printUsage() {
    System.out.println("Usage: ClientAuthenticationSocketDemo <host> <port> <file>");
    System.out
        .println(" e.g.: ClientAuthenticationSocketDemo jcewww.iaik.tu-graz.ac.at 4433 /");
  }

}
