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

import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author wplatzer
 * @version File Revision <!-- $$Revision: --> 16 <!-- $ -->
 */
public class IaikKeyStore implements KeyStoreConstants {

	static Object[][] certificates = new Object[5][3];
	static PrivateKey[][] keys = new PrivateKey[5][3];
	static X509Certificate[] ca_certificates = new X509Certificate[3];
	static PrivateKey[] ca_keys = new PrivateKey[3];
	// attribute certificate issuer
	static X509Certificate[] ac_issuer_chain;
	static PrivateKey ac_issuer_key;

	public final static int RSA = 0;
	public final static int DSA = 1;
	public final static int RSAPSS = 2;
	public final static int RSAOAEP = 3;
	public final static int DH = 4;

	public final static int SZ_512 = 0;
	public final static int SZ_1024 = 1;
	public final static int SZ_2048 = 2;

	static KeyStore key_store;

	static {
		System.out.println("initializing KeyStore...");
		loadKeyStore();
		initKeyStore();
	}

	/**
	 * Loads the demo keystore from file "jce.keystore" in the current working
	 * directory.
	 */
	private static void loadKeyStore() {
		// try to locate the KeyStore
		// first check the current working directory
		File ks = new File(System.getProperty("user.dir"), KS_FILENAME);
		if (!ks.exists()) {
			System.out.println("Can't find the KeyStore in directory " + ks.getAbsolutePath());
			System.out.println("Creating KeyStore.");
			SetupKeyStore.start();
			// System.out.println("Can not find the KeyStore in directory:");
			// System.out.println(ks.getAbsolutePath());
			// System.exit(1);
		}

		// now try to create and load the KeyStore
		try {
			key_store = KeyStore.getInstance("IAIKKeyStore", "IAIK");
			InputStream is = null;

			try {
				is = new FileInputStream(ks);
				key_store.load(is, KS_PASSWORD);
			} finally {
				if (is != null) {
					try {
						is.close();
					} catch (IOException e) {
						// ignore
					}
				}
			}
		} catch (Exception ex) {
			System.out.println("Unable to load KeyStore!");
			ex.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Initializes the keystore database with certs/keys read from the keystore.
	 */
	private static void initKeyStore() {
		// RSA
		try {
			ca_certificates[RSA] = Util.convertCertificateChain(key_store
			    .getCertificateChain(CA_RSA))[0];
			ca_keys[RSA] = (PrivateKey) key_store.getKey(CA_RSA, KS_PASSWORD);

			certificates[RSA][SZ_512] = Util.convertCertificateChain(key_store
			    .getCertificateChain(RSA_512));
			keys[RSA][SZ_512] = (PrivateKey) key_store.getKey(RSA_512, KS_PASSWORD);
			certificates[RSA][SZ_1024] = Util.convertCertificateChain(key_store
			    .getCertificateChain(RSA_1024));
			keys[RSA][SZ_1024] = (PrivateKey) key_store.getKey(RSA_1024, KS_PASSWORD);
			certificates[RSA][SZ_2048] = Util.convertCertificateChain(key_store
			    .getCertificateChain(RSA_2048));
			keys[RSA][SZ_2048] = (PrivateKey) key_store.getKey(RSA_2048, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA certificates from KeyStore.");
			ex.printStackTrace();
		}
		// DSA
		try {
			ca_certificates[DSA] = Util.convertCertificateChain(key_store
			    .getCertificateChain(CA_DSA))[0];
			ca_keys[DSA] = (PrivateKey) key_store.getKey(CA_DSA, KS_PASSWORD);

			certificates[DSA][SZ_512] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DSA_512));
			keys[DSA][SZ_512] = (PrivateKey) key_store.getKey(DSA_512, KS_PASSWORD);
			certificates[DSA][SZ_1024] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DSA_1024));
			keys[DSA][SZ_1024] = (PrivateKey) key_store.getKey(DSA_1024, KS_PASSWORD);
			certificates[DSA][SZ_2048] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DSA_2048));
			keys[DSA][SZ_2048] = (PrivateKey) key_store.getKey(DSA_2048, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get DSA certificate from KeyStore.");
			ex.printStackTrace();
		}
		// DH
		try {
			certificates[DH][SZ_512] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DH_512));
			keys[DH][SZ_512] = (PrivateKey) key_store.getKey(DH_512, KS_PASSWORD);
			certificates[DH][SZ_1024] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DH_1024));
			keys[DH][SZ_1024] = (PrivateKey) key_store.getKey(DH_1024, KS_PASSWORD);
			certificates[DH][SZ_2048] = Util.convertCertificateChain(key_store
			    .getCertificateChain(DH_2048));
			keys[DH][SZ_2048] = (PrivateKey) key_store.getKey(DH_2048, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get Diffie-Hellman certificate from KeyStore.");
			ex.printStackTrace();
		}
		// attribute certificate issuer cert
		try {
			ac_issuer_chain = Util.convertCertificateChain(key_store
			    .getCertificateChain(AC_ISSUER));
			ac_issuer_key = (PrivateKey) key_store.getKey(AC_ISSUER, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get AC issuer certificate from KeyStore");
			ex.printStackTrace();
		}
		// RSA-PSS
		try {
			ca_certificates[RSAPSS] = Util.convertCertificateChain(key_store
			    .getCertificateChain(CA_RSAPSS))[0];
			ca_keys[RSAPSS] = (PrivateKey) key_store.getKey(CA_RSAPSS, KS_PASSWORD);

			certificates[RSAPSS][SZ_1024] = Util.convertCertificateChain(key_store
			    .getCertificateChain(RSAPSS_1024));
			keys[RSAPSS][SZ_1024] = (PrivateKey) key_store.getKey(RSAPSS_1024, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA-PSS certificates from KeyStore.");
			ex.printStackTrace();
		}

		// RSA-OAEP
		try {
			certificates[RSAOAEP][SZ_1024] = Util.convertCertificateChain(key_store
			    .getCertificateChain(RSAOAEP_1024));
			keys[RSAOAEP][SZ_1024] = (PrivateKey) key_store.getKey(RSAOAEP_1024, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA-OAEP certificates from KeyStore.");
			ex.printStackTrace();
		}
	}

	/**
	 * Returns the private key of a CA certificate.
	 * 
	 * @param type
	 *          {@link #RSA RSA} or {@link #DSA DSA} or {@link #DH DH}
	 * @param size
	 *          {@link #SZ_512 SZ_512} or {@link #SZ_1024 SZ_1024}
	 *          {@link #SZ_2048 SZ_2048}
	 * 
	 * @return the private key or <code>null</code> if no key is available for
	 *         requested type/size
	 * 
	 * @exception RuntimeException
	 *              if type or size is invalid
	 */
	public static PrivateKey getPrivateKey(int type, int size) {
		try {
			return keys[type][size];
		} catch (ArrayIndexOutOfBoundsException ex) {
			throw new RuntimeException("Wrong type or size!");
		}
	}

	/**
	 * Returns a demo user certificate.
	 * 
	 * @param type
	 *          {@link #RSA RSA} or {@link #DSA DSA} or {@link #DH DH}
	 * @param size
	 *          {@link #SZ_512 SZ_512} or {@link #SZ_1024 SZ_1024}
	 *          {@link #SZ_2048 SZ_2048}
	 * 
	 * @return the certificate chain or <code>null</code> if no certificate is
	 *         available for requested type/size
	 * 
	 * @exception RuntimeException
	 *              if type or size is invalid
	 */
	public static X509Certificate[] getCertificateChain(int type, int size) {
		try {
			return (X509Certificate[]) certificates[type][size];
		} catch (ArrayIndexOutOfBoundsException ex) {
			throw new RuntimeException("Wrong type or size!");
		}
	}

	/**
	 * Returns a public key belonging to demo user certificate.
	 * 
	 * @param type
	 *          {@link #RSA RSA} or {@link #DSA DSA} or {@link #DH DH}
	 * @param size
	 *          {@link #SZ_512 SZ_512} or {@link #SZ_1024 SZ_1024}
	 *          {@link #SZ_2048 SZ_2048}
	 * 
	 * @return the public key or <code>null</code> if no certificate/key is
	 *         available for requested type/size
	 * 
	 * @exception RuntimeException
	 *              if type or size is invalid
	 */
	public static PublicKey getPublicKey(int type, int size) {
		try {
			X509Certificate[] certChain = getCertificateChain(type, size);
			return (certChain == null) ? null : certChain[0].getPublicKey();
		} catch (ArrayIndexOutOfBoundsException ex) {
			throw new RuntimeException("Wrong type or size!");
		}
	}

	/**
	 * Returns the private key of a CA certificate.
	 * 
	 * @param type
	 *          {@link #RSA RSA} or {@link #DSA DSA}
	 * 
	 * @return the ca private key or <code>null</code> if no key is available for
	 *         requested type
	 * 
	 * @exception RuntimeException
	 *              if type is invalid
	 */
	public static PrivateKey getCaPrivateKey(int type) {
		try {
			return ca_keys[type];
		} catch (ArrayIndexOutOfBoundsException ex) {
			throw new RuntimeException("Wrong type or size!");
		}
	}

	/**
	 * Returns a demo CA certificate.
	 * 
	 * @param type
	 *          {@link #RSA RSA} or {@link #DSA DSA}
	 * 
	 * @return the ca certificate or <code>null</code> if no certificate is
	 *         available for the requested type
	 * 
	 * @exception RuntimeException
	 *              if type is invalid
	 */
	public static X509Certificate getCaCertificate(int type) {
		try {
			return ca_certificates[type];
		} catch (ArrayIndexOutOfBoundsException ex) {
			throw new RuntimeException("Wrong type or size!");
		}
	}

	/**
	 * Returns the demo AC issuer private key.
	 * 
	 * @return the demo AC issuer private key
	 */
	public static PrivateKey getACIssuerPrivateKey() {
		return ac_issuer_key;
	}

	/**
	 * Returns the demo certificate chain of the demo AC issuer.
	 * 
	 * @return the demo AC issuer certificate chain
	 */
	public static X509Certificate[] getACIssuerCertificateChain() {
		return ac_issuer_chain;
	}

}
