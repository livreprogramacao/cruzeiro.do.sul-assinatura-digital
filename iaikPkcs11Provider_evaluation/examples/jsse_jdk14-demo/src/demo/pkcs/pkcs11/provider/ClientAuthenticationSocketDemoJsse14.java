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
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PublicKey;
import iaik.security.provider.IAIK;

// exception imports
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Enumeration;

import junit.framework.Assert;
import junit.framework.AssertionFailedError;

/**
 * This class shows how to use a keystore of the PKCS#11 provider to
 * authenticate a client to a server using RSA certificate and signature.
 * The certificate will be read from the smart card and the signature for
 * client authentication is done on the card.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class ClientAuthenticationSocketDemoJsse14 {

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
	 * This empty constructor registers the new provider to the Java
	 * security system.
	 */
	public ClientAuthenticationSocketDemoJsse14(String hostName, int port, String file) {
		hostName_ = hostName;
		port_ = port;
		file_ = file;

		// special care is required during the registration of the providers
		pkcs11Provider_ = new IAIKPkcs11();
		Security.insertProviderAt(pkcs11Provider_, 2); // add IAIK PKCS#11 JCE provider, must be behind SUN but before JSSE

		Security.addProvider(new IAIK()); // add IAIK softweare JCE provider

	}

	/**
	 * This is the main method that is called by the JVM during startup.
	 * 
	 * @param args
	 *        These are the command line arguments.
	 */
	public static void main(String[] args)
	    throws Exception
	{
		if (args.length != 3) {
			printUsage();
			throw new InvalidParameterException("invalid parameter");
		}
		String hostName = args[0];
		int port = Integer.parseInt(args[1]);
		String file = args[2];

		ClientAuthenticationSocketDemoJsse14 demo = new ClientAuthenticationSocketDemoJsse14(
		    hostName, port, file);

		demo.getKeyStore();
		demo.createSocket();
		demo.connectAndGet();
		System.out.flush();
		System.err.flush();
	}

	/**
	 * This method gets the key store of the PKCS#11 provider and stores
	 * a reference at<code>pkcs11ClientKeystore_</code>.
	 * 
	 * @exception GeneralSecurityException
	 *            If anything with the provider fails.
	 * @exception IOException
	 *            If loading the key store fails.
	 */
	public void getKeyStore()
	    throws GeneralSecurityException, IOException
	{
		// with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
		// specific IAIKPkcs11 provider instance after this call, even if you specify the provider
		// at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
		// has no chance to get its own provider instance.
		KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");

		if (tokenKeyStore == null) {
			System.out
			    .println("Got no key store. Ensure that the provider is properly configured and installed.");
			throw new KeyStoreException("got no key store");
		}
		tokenKeyStore.load(new ByteArrayInputStream(pkcs11Provider_.getName().getBytes()),
		    null);
		//		tokenKeyStore.load(null, null); // this call binds the keystore to the first instance of the IAIKPkcs11 provider
		// if you want ot bind it to a different instance, you have to provide the provider name as stream
		// see the other RSASigningDemo classes for examples

		pkcs11ClientKeystore_ = tokenKeyStore;

	}

	/**
	 * This creates a SSL socket and sets the context appropriately.
	 * 
	 * @exception GeneralSecurityException
	 *            If anything with the provider fails.
	 * @exception IOException
	 *            If creating the socket fails.
	 */
	public void createSocket()
	    throws GeneralSecurityException, IOException
	{
		SSLContext sslContext = SSLContext.getInstance("TLS");
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");

		keyManagerFactory.init(pkcs11ClientKeystore_, null);

		X509TrustManager acceptAllTrustManager = new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) {
			}
		};

		sslContext.init(keyManagerFactory.getKeyManagers(),
		    new X509TrustManager[] { acceptAllTrustManager }, null);

		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

		sslSocket_ = (SSLSocket) sslSocketFactory.createSocket(hostName_, port_);

		System.out.println("##########");
		System.out.println("Supported Cipher Suites are:");
		System.out
		    .println("________________________________________________________________________________");
		String[] supportedCipherSuites = sslSocket_.getSupportedCipherSuites();
		for (int i = 0; i < supportedCipherSuites.length; i++) {
			System.out.println(supportedCipherSuites[i]);

		}
		System.out
		    .println("________________________________________________________________________________");

		System.out.println("Enables Cipher Suites are:");
		System.out
		    .println("________________________________________________________________________________");
		String[] enabledCipherSuites = sslSocket_.getEnabledCipherSuites();
		for (int i = 0; i < enabledCipherSuites.length; i++) {
			System.out.println(enabledCipherSuites[i]);

		}
		System.out
		    .println("________________________________________________________________________________");
		System.out.println("##########");

	}

	/**
	 * Connect to the server, send the request and read the response.
	 * 
	 * @exception GeneralSecurityException
	 *            If anything with the provider fails.
	 * @exception IOException
	 *            If socket communication fails.
	 */
	public void connectAndGet()
	    throws GeneralSecurityException, IOException
	{
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
		out.println(request);
		out.println();
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
