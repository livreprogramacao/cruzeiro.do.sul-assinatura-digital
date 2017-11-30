// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2013 Stiftung Secure Information and
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

package demo.keystore;

import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import demo.IAIKDemo;

/**
 * This demo shows the usage of a JCA compliant keystore. Keys and certificates
 * used for this demo are read from the IAIK-JCE sample keystore
 * ("jce.keystore") file which may be created by running the
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} program. The jce.keystore
 * file has to be located in your current working directory.
 * 
 * @version File Revision <!-- $$Revision: --> 2 <!-- $ -->
 */
public class KeyStoreDemo implements IAIKDemo {

	// private key of the keystore owner
	PrivateKey myPrivateKey_;
	// the certificate chain belonging to the private key
	X509Certificate[] myCerts_;
	// certificate of some trusted party
	X509Certificate trustedCert_;
	// alias to identify my key entry
	String myAlias_;
	// alias to identify trusted certs of other party
	String otherAlias_;

	/**
	 * Default constructor.
	 */
	public KeyStoreDemo() {
		// get the private key
		myPrivateKey_ = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		// get the certificate chain
		myCerts_ = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		// get the certificate of some trusted party
		trustedCert_ = IaikKeyStore.getCaCertificate(IaikKeyStore.DSA);
		// set aliases
		myAlias_ = "myKey";
		otherAlias_ = "trustedCerts";

	}

	/**
	 * Creates a new IAIK keystore, adds two entries and writes the keystore to
	 * the given output stream.
	 * 
	 * @param password
	 *          the (keystore and key entry) password
	 * @param os
	 *          the stream to which to write the keystore just created
	 * 
	 * @exception Exception
	 *              if some error occurs
	 */
	public void createKeyStore(char[] password, OutputStream os)
	    throws Exception
	{
		// create a new empty keystore
		System.out.println("Create new keystore...");
		KeyStore keyStore = KeyStore.getInstance("IAIKKeyStore", "IAIK");
		keyStore.load(null, null);
		// add the private key and certificates of the keystore owner
		System.out.println("Add key entry...");
		// we use the same password for key entries and keystore
		keyStore.setKeyEntry(myAlias_, myPrivateKey_, password, myCerts_);
		// add the certificate of some trusted party
		System.out.println("Add certificate entry...");
		keyStore.setCertificateEntry(otherAlias_, trustedCert_);
		// store keystore
		keyStore.store(os, password);
	}

	/**
	 * Reads the demo keystore from the given stream and parses its content.
	 * 
	 * @param password
	 *          the (keystore and key entry) password
	 * 
	 * @param is
	 *          the stream from which to read the demo keystore
	 * 
	 * @exception Exception
	 *              if an error occurs while reading/parsing the keystore
	 */
	public void readKeyStore(char[] password, InputStream is)
	    throws Exception
	{
		// load keystore
		System.out.println("Load keystore...");
		KeyStore keyStore = KeyStore.getInstance("IAIKKeyStore", "IAIK");
		keyStore.load(is, password);
		// query aliases
		System.out.println("The keystore contains the following entries:");
		Enumeration aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			System.out.println(aliases.nextElement());
		}
		// fetch key
		System.out.println("Get my private key...");
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(myAlias_, password);
		System.out.println("Key is " + privateKey.getAlgorithm() + " ("
		    + Util.getKeyLength(privateKey) + " bits)");
		// fetch certificates
		System.out.println("Get my certificates...");
		Certificate[] certChain = keyStore.getCertificateChain(myAlias_);
		System.out.println("Certificate chain is: ");
		for (int i = 0; i < certChain.length; i++) {
			System.out.println(((X509Certificate) certChain[i]).getSubjectDN());
		}
		// fetch trusted certificate
		System.out.println("Get trusted certificate...");
		X509Certificate trustedCert = (X509Certificate) keyStore.getCertificate(otherAlias_);
		System.out.println("Trusted Certificate is: ");
		System.out.println(trustedCert.getSubjectDN());
	}

	/**
	 * Starts the demo.
	 */
	public void start() {
		start(null);
	}

	/**
	 * Starts the demo.
	 * 
	 * @param fileName
	 *          the name of the file to which to write (and then from where to
	 *          read) the demo keystore; if <code>null</code> ByteArrayStreams are
	 *          used
	 */
	public void start(String fileName) {
		InputStream is = null;
		OutputStream os = null;
		char[] password = "topSecret".toCharArray();

		// creating keystore
		try {
			if (fileName == null) {
				os = new ByteArrayOutputStream();
			} else {
				os = new FileOutputStream(fileName);
			}
			createKeyStore(password, os);
		} catch (Exception ex) {
			System.out.println("KeyStore creation failed:");
			ex.printStackTrace();
			throw new RuntimeException();
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					// ignore
				}
			}
		}

		// reading from keystore
		try {
			if (fileName == null) {
				is = new ByteArrayInputStream(((ByteArrayOutputStream) os).toByteArray());
			} else {
				is = new FileInputStream(fileName);
			}
			readKeyStore(password, is);
		} catch (Exception ex) {
			System.out.println("KeyStore parsing failed:");
			ex.printStackTrace();
			throw new RuntimeException();
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Main method.
	 */
	public static void main(String[] argv) {

		Security.insertProviderAt(new IAIK(), 2);
		KeyStoreDemo demo = new KeyStoreDemo();
		if (argv.length == 0) {
			demo.start(null);
		} else if (argv.length == 1) {
			demo.start(argv[0]);
		} else {
			System.err.println("Usage: java KeyStoreDemo [<keystore file>]");
			Util.waitKey();
			System.exit(-1);
		}
		System.out.println("Ready! No errors...");
		Util.waitKey();
	}

}
