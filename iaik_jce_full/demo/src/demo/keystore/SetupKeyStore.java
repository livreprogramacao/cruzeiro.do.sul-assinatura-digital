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

import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.pkcs.pkcs1.RSAPssParameterSpec;
import iaik.security.provider.IAIK;
import iaik.security.rsa.RSAOaepKeyPairGenerator;
import iaik.security.rsa.RSAPssKeyPairGenerator;
import iaik.security.rsa.RSAPssSignature;
import iaik.x509.SimpleChainVerifier;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectAltName;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

/**
 * Creates a default KeyStore in the current working directory. These keys are
 * used by many demos included in IAIK-JCE. The aliases and the password for
 * accessing the keys and certificates can be found in
 * {@link demo.keystore.KeyStoreConstants KeyStoreConstants}.
 * 
 * @see KeyStoreConstants
 * @version File Revision <!-- $$Revision: --> 25 <!-- $ -->
 */
public class SetupKeyStore implements KeyStoreConstants {

	// the keylength of the CA certificate shall be 1024
	private final static int CA_KEYLENGTH = 1024;

	/**
	 * Whether to use default params for RSASSA-PSS keys.
	 */
	private final static boolean USE_DEFAULT_PARAMS_FOR_PSS = true;

	/**
	 * Whether to use default params for RSAES-OAEP keys.
	 */
	private final static boolean USE_DEFAULT_PARAMS_FOR_OAEP = true;

	// the key store to create
	KeyStore key_store;
	// the file where the key store shall be saved
	String keystore_file;
	// takes the existing keys from the KeyStore and only creates new certificates
	boolean create_only_certificates = true;

	// the private keys
	KeyPair ca_rsa = null;
	KeyPair ca_rsa_pss = null;
	KeyPair rsa512 = null;
	KeyPair rsa1024 = null;
	KeyPair rsa2048 = null;
	KeyPair rsapss1024 = null;
	KeyPair rsaoaep1024 = null;
	KeyPair ca_dsa = null;
	KeyPair dsa512 = null;
	KeyPair dsa1024 = null;
	KeyPair dsa2048 = null;
	KeyPair dh512 = null;
	KeyPair dh1024 = null;
	KeyPair dh2048 = null;
	KeyPair ac_issuer = null;

	// create RSA keys and certificates
	boolean create_rsa = true;
	// create RSA-PSS keys and certificates
	boolean create_rsa_pss = true;
	// create RSA-OAEP keys and certificates
	boolean create_rsa_oaep = true;
	// create DSA keys and certificates
	boolean create_dsa = true;
	// create DH keys and certificates
	boolean create_dh = true;
	// create attribute certificate issuer cert
	boolean create_ac_issuer = true;

	/**
	 * Generate a KeyPair using the specified algorithm with the given size.
	 * 
	 * @param algorithm
	 *          the algorithm to use
	 * @param bits
	 *          the length of the key (modulus) in bits
	 * 
	 * @return the KeyPair
	 * 
	 * @exception NoSuchAlgorithmException
	 *              if no KeyPairGenerator is available for the requested
	 *              algorithm
	 */
	public static KeyPair generateKeyPair(String algorithm, int bits)
	    throws NoSuchAlgorithmException
	{

		KeyPair kp = null;

		if (algorithm.equals("RSASSA-PSS")) {
			kp = generateRSAPssKeyPair(bits);
		} else if (algorithm.equals("RSAES-OAEP")) {
			kp = generateRSAOaepKeyPair(bits);
		} else {

			KeyPairGenerator generator = null;

			try {
				generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
			} catch (NoSuchProviderException ex) {
				throw new NoSuchAlgorithmException("Provider IAIK not found!");
			}

			generator.initialize(bits);
			kp = generator.generateKeyPair();
		}
		return kp;
	}

	/**
	 * Generates a RSASSA-PSS KeyPair.
	 * 
	 * @param bits
	 *          the length of the key (modulus) in bits
	 * 
	 * @return the key pair
	 * 
	 * @exception NoSuchAlgorithmException
	 *              if no KeyPairGenerator is available for the requested
	 *              algorithm
	 */
	public static KeyPair generateRSAPssKeyPair(int bits)
	    throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGen = null;

		try {
			keyGen = KeyPairGenerator.getInstance("RSASSA-PSS", "IAIK");
		} catch (NoSuchProviderException ex) {
			throw new NoSuchAlgorithmException("Provider IAIK not found!");
		}

		if (USE_DEFAULT_PARAMS_FOR_PSS) {
			// initialize key pair generator
			keyGen.initialize(bits);
		} else {
			// create PSS parameters for specifying hash, mgf algorithms and salt
			// length:
			// hash and mgf algorithm ids
			AlgorithmID hashID = (AlgorithmID) AlgorithmID.ripeMd160.clone();
			AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
			mgfID.setParameter(hashID.toASN1Object());
			int saltLength = 20;
			// hash and mgf engines
			MessageDigest hashEngine = hashID.getMessageDigestInstance();
			MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
			MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
			mgf1ParamSpec.setHashEngine(hashEngine);
			try {
				mgfEngine.setParameters(mgf1ParamSpec);
			} catch (InvalidAlgorithmParameterException ex) {
				throw new NoSuchAlgorithmException(ex.toString());
			}
			// create the RSAPssParameterSpec
			RSAPssParameterSpec pssParamSpec = new RSAPssParameterSpec(hashID, mgfID,
			    saltLength);
			// set engines
			pssParamSpec.setHashEngine(hashEngine);
			pssParamSpec.setMGFEngine(mgfEngine);

			// initialization with parameters for demonstration purposes (cast
			// required)
			((RSAPssKeyPairGenerator) keyGen).initialize(bits, pssParamSpec);
		}
		KeyPair kp = keyGen.generateKeyPair();
		return kp;
	}

	/**
	 * Generates a RSAES-OAEP KeyPair.
	 * 
	 * @param bits
	 *          the length of the key (modulus) in bits
	 * 
	 * @return the key pair
	 * 
	 * @exception NoSuchAlgorithmException
	 *              if no KeyPairGenerator is available for the requested
	 *              algorithm
	 */
	public static KeyPair generateRSAOaepKeyPair(int bits)
	    throws NoSuchAlgorithmException
	{

		KeyPairGenerator keyGen = null;

		try {
			keyGen = KeyPairGenerator.getInstance("RSAES-OAEP", "IAIK");
		} catch (NoSuchProviderException ex) {
			throw new NoSuchAlgorithmException("Provider IAIK not found!");
		}

		if (USE_DEFAULT_PARAMS_FOR_OAEP) {
			// initialize key pair generator
			keyGen.initialize(bits);
		} else {
			// create OAEP parameters for specifying hash, mgf and pSource algorithms
			AlgorithmID hashID = (AlgorithmID) AlgorithmID.ripeMd160.clone();
			AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
			mgfID.setParameter(hashID.toASN1Object());
			AlgorithmID pSourceID = (AlgorithmID) AlgorithmID.pSpecified.clone();
			pSourceID.setParameter(new OCTET_STRING());
			// hash and mgf engines
			MessageDigest hashEngine = hashID.getMessageDigestInstance();
			MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
			MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
			mgf1ParamSpec.setHashEngine(hashEngine);
			try {
				mgfEngine.setParameters(mgf1ParamSpec);
			} catch (InvalidAlgorithmParameterException ex) {
				throw new NoSuchAlgorithmException(ex.toString());
			}
			// create the RSAOaepParameterSpec
			RSAOaepParameterSpec oaepParamSpec = new RSAOaepParameterSpec(hashID, mgfID,
			    pSourceID);
			// set engines
			oaepParamSpec.setHashEngine(hashEngine);
			oaepParamSpec.setMGFEngine(mgfEngine);

			// initialization with parameters for demonstration purposes (cast
			// required)
			((RSAOaepKeyPairGenerator) keyGen).initialize(bits, oaepParamSpec);
		}
		KeyPair kp = keyGen.generateKeyPair();
		return kp;
	}

	/**
	 * Creates a certificate from the given values.
	 * 
	 * @param subject
	 *          the subject of the certificate
	 * @param publicKey
	 *          the public key to include
	 * @param issuer
	 *          the issuer of the certificate
	 * @param privateKey
	 *          the private key for signing the certificate
	 * @param algorithm
	 *          the signature algorithm to use
	 */
	public static X509Certificate createCertificate(Name subject,
	                                                PublicKey publicKey,
	                                                Name issuer,
	                                                X509Certificate issuerCert,
	                                                PrivateKey privateKey,
	                                                AlgorithmID algorithm,
	                                                V3Extension[] extensions)
	{

		// create a new certificate
		X509Certificate cert = new X509Certificate();

		try {
			// set the values
			cert.setSerialNumber(new BigInteger(20, new Random()));
			cert.setSubjectDN(subject);
			cert.setPublicKey(publicKey);
			cert.setIssuerDN(issuer);

			GregorianCalendar date = new GregorianCalendar();

			// ensure that EE certs are in the validity period of CA certs
			if (issuer.equals(subject)) {
				// not before two hours ago
				date.add(Calendar.HOUR_OF_DAY, -2);
				cert.setValidNotBefore(date.getTime());
				date.add(Calendar.MONTH, 12);
			} else {
				// not before one hour ago
				date.add(Calendar.HOUR_OF_DAY, -1);
				cert.setValidNotBefore(date.getTime());
				date.add(Calendar.MONTH, 11);
			}
			cert.setValidNotAfter(date.getTime());
			if (extensions != null) {
				for (int i = 0; i < extensions.length; i++) {
					cert.addExtension(extensions[i]);
				}
			}
			cert.addExtension(new SubjectKeyIdentifier(publicKey));
			if (issuerCert != null) {
				// EE cert
				byte[] keyID = ((SubjectKeyIdentifier) issuerCert
				    .getExtension(SubjectKeyIdentifier.oid)).get();
				cert.addExtension(new AuthorityKeyIdentifier(keyID));
			} else {
				// CA cert: ocsp signing
				ExtendedKeyUsage ekt = new ExtendedKeyUsage(ExtendedKeyUsage.ocspSigning);
				cert.addExtension(ekt);
			}
			// and sign the certificate
			cert.sign(algorithm, privateKey);
		} catch (Exception ex) {
			throw new RuntimeException("Error creating the certificate: " + ex.getMessage());
		}

		return cert;
	}

	/**
	 * Load or create a KeyStore and initialize it.
	 */
	private void initializeKeyStore(boolean useCurrentDir) {

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		String line = "";

		try {
			// default directory is the current user dir
			String keystore_dir = System.getProperty("user.dir");
			File ks = new File(keystore_dir, KS_FILENAME);

			// KeyStore does already exist
			if (ks.exists()) {
				keystore_file = ks.getAbsolutePath();
				if (create_only_certificates) {
					System.out.println("Create only new certificates from already existing keys!");
				} else {
					System.out.println("Existing KeyStore will be deleted!");
				}
				System.out.println("KeyStore: " + keystore_file);
			} else {
				// there is no KeyStore -> create also new keys
				create_only_certificates = false;

				while (true) {
					if (!useCurrentDir) {
						System.out
						    .print("Create new KeyStore in directory: " + keystore_dir + " [y]");
						line = reader.readLine();
					}
					if (line == null || line.length() == 0 || line.equals("y")) {
						ks = new File(keystore_dir, KS_FILENAME);
						keystore_file = ks.getAbsolutePath();
						System.out.println("KeyStore will be saved to: " + keystore_file);
						break;
					}
					System.out.print("Enter directory: ");
					keystore_dir = reader.readLine();
				}

			}

			// get a new KeyStore onject
			key_store = KeyStore.getInstance("IAIKKeyStore", "IAIK");

			if (create_only_certificates) {
				InputStream is = null;
				// take private keys from existing KeyStore
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
			} else {
				// create a new KeyStore
				key_store.load(null, null);
			}

		} catch (Exception ex) {
			System.out.println("Error creating new IAIK KeyStore!");
			throw new RuntimeException("Error creating new KeyStore: " + ex.getMessage());
		}
	}

	/**
	 * Save the KeyStore to disk.
	 */
	private void saveKeyStore() {
		FileOutputStream os = null;

		try {
			// write the KeyStore to disk
			os = new FileOutputStream(keystore_file);
			key_store.store(os, KS_PASSWORD);
		} catch (Exception ex) {
			System.out.println("Error saving KeyStore!");
			ex.printStackTrace();
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Add the private key and the certificate chain to the key store.
	 */
	public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias)
	    throws KeyStoreException
	{
		key_store.setKeyEntry(alias, keyPair.getPrivate(), KS_PASSWORD, chain);
	}

	/**
	 * Returns a KeyPair form the KeyStore.
	 */
	private KeyPair getKeyPair(String type)
	    throws Exception
	{
		PrivateKey privKey = (PrivateKey) key_store.getKey(type, KS_PASSWORD);
		PublicKey pubKey = key_store.getCertificateChain(type)[0].getPublicKey();
		return new KeyPair(pubKey, privKey);
	}

	/**
	 * Get all private keys from the KeyStore.
	 */
	private void getPrivateKeys() {

		// RSA
		try {
			ca_rsa = getKeyPair(CA_RSA);
			rsa512 = getKeyPair(RSA_512);
			rsa1024 = getKeyPair(RSA_1024);
			rsa2048 = getKeyPair(RSA_2048);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA keys from KeyStore.");
			ex.printStackTrace();
			create_rsa = false;
		}

		// DSA
		try {
			ca_dsa = getKeyPair(CA_DSA);
			dsa512 = getKeyPair(DSA_512);
			dsa1024 = getKeyPair(DSA_1024);
			dsa2048 = getKeyPair(DSA_2048);
		} catch (Exception ex) {
			System.out.println("Unable to get DSA keys from KeyStore.");
			ex.printStackTrace();
			create_dsa = false;
		}

		// DH
		try {
			dh512 = getKeyPair(DH_512);
			dh1024 = getKeyPair(DH_1024);
			dh2048 = getKeyPair(DH_2048);
		} catch (Exception ex) {
			System.out.println("Unable to get DH keys from KeyStore.");
			ex.printStackTrace();
			create_dh = false;
		}

		// attribute certificate issuer
		try {
			ac_issuer = getKeyPair(AC_ISSUER);
		} catch (Exception ex) {
			System.out.println("Unable to get AC issuer keys from KeyStore.");
			ex.printStackTrace();
			create_ac_issuer = false;
		}

		// RSA-PSS
		try {
			ca_rsa_pss = getKeyPair(CA_RSAPSS);
			rsapss1024 = getKeyPair(RSAPSS_1024);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA-PSS keys from KeyStore.");
			ex.printStackTrace();
			create_rsa = false;
		}

		// RSA-OAEP
		try {
			rsaoaep1024 = getKeyPair(RSAOAEP_1024);
		} catch (Exception ex) {
			System.out.println("Unable to get RSA-OAEP key from KeyStore.");
			ex.printStackTrace();
			create_rsa = false;
		}

	}

	/**
	 * Gernerates new prviate keys.
	 */
	private void generatePrivateKeys() {
		try {
			// first create the KeyPairs

			// RSA
			try {
				System.out.println("generate RSA KeyPair for CA certificate [" + CA_KEYLENGTH
				    + " bits]...");
				ca_rsa = generateKeyPair("RSA", CA_KEYLENGTH);
				System.out.println("generate RSA KeyPair for a test certificate [512 bits]...");
				rsa512 = generateKeyPair("RSA", 512);
				System.out.println("generate RSA KeyPair for a test certificate [1024 bits]...");
				rsa1024 = generateKeyPair("RSA", 1024);
				System.out.println("generate RSA KeyPair for a test certificate [2048 bits]...");
				rsa2048 = generateKeyPair("RSA", 2048);
			} catch (NoSuchAlgorithmException ex) {
				create_rsa = false;
				System.out
				    .println("No implementation for RSA! RSA certificates are not created!\n");
			}

			// DSA
			try {
				System.out.println("generate DSA KeyPair for CA certificate [" + CA_KEYLENGTH
				    + " bits]...");
				ca_dsa = generateKeyPair("DSA", CA_KEYLENGTH);
				System.out.println("generate DSA KeyPair for a test certificate [512 bits]...");
				dsa512 = generateKeyPair("DSA", 512);
				System.out
				    .println("generate DSA KeyPair for a server certificate [1024 bits]...");
				dsa1024 = generateKeyPair("DSA", 1024);
				System.out
				    .println("generate DSA KeyPair for a server certificate [2048 bits]...");
				dsa2048 = generateKeyPair("DSA", 2048);
			} catch (NoSuchAlgorithmException ex) {
				create_dsa = false;
				System.out
				    .println("No implementation for DSA! DSA certificates are not created!\n");
			}

			// DH
			try {
				System.out.println("generate DH KeyPair for a test certificate [512 bits]...");
				dh512 = generateKeyPair("DH", 512);
				System.out.println("generate DH KeyPair for a server certificate [1024 bits]...");
				dh1024 = generateKeyPair("DH", 1024);
				System.out.println("generate DH KeyPair for a server certificate [2048 bits]...");
				dh2048 = generateKeyPair("DH", 2048);
			} catch (NoSuchAlgorithmException ex) {
				create_dh = false;
				System.out
				    .println("No implementation for DH! DH certificates are not created!\n");
			}

			// attribute cert issuer
			try {
				System.out
				    .println("generate RSA KeyPair for AC issuer certificate [1024 bits]...");
				ac_issuer = generateKeyPair("RSA", 1024);
			} catch (NoSuchAlgorithmException ex) {
				create_ac_issuer = false;
				System.out
				    .println("No implementation for RSA! AC issuer certificates are not created!\n");
			}

			// RSA-PSS
			try {
				System.out.println("generate RSASSA-PSS KeyPair for CA certificate ["
				    + CA_KEYLENGTH + " bits]...");
				ca_rsa_pss = generateKeyPair("RSASSA-PSS", CA_KEYLENGTH);
				System.out
				    .println("generate RSASSA-PSS KeyPair for a test certificate [1024 bits]...");
				rsapss1024 = generateKeyPair("RSASSA-PSS", 1024);
			} catch (NoSuchAlgorithmException ex) {
				create_rsa_pss = false;
				System.out
				    .println("No implementation for RSASSA-PSS! RSA-PSS certificates are not created!\n");
			}

			// RSA-OAEP
			try {
				System.out
				    .println("generate RSAES-OAEP KeyPair for a test certificate [1024 bits]...");
				rsaoaep1024 = generateKeyPair("RSAES-OAEP", 1024);
			} catch (NoSuchAlgorithmException ex) {
				create_rsa_oaep = false;
				System.out
				    .println("No implementation for RSAES-OAEP! RSA-OAEP certificates are not created!\n");
			}

		} catch (Exception ex) {
			System.out.println("Exception: " + ex);
		}
	}

	/**
	 * Generates the certificates.
	 */
	public void generateCertificates() {

		try {

			// Now create the certificates
			Name issuer = new Name();
			issuer.addRDN(ObjectID.country, "AT");
			issuer.addRDN(ObjectID.organization, "IAIK");
			issuer.addRDN(ObjectID.organizationalUnit, "JavaSecurity");

			Name subject = new Name();
			subject.addRDN(ObjectID.country, "AT");
			subject.addRDN(ObjectID.organization, "IAIK");
			subject.addRDN(ObjectID.organizationalUnit, "JavaSecurity");

			V3Extension[] extensions = new V3Extension[3];
			extensions[0] = new BasicConstraints(true);
			extensions[1] = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign
			    | KeyUsage.digitalSignature);
			PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(null, null,
			    "This certificate may be used for demonstration purposes only.");
			PolicyInformation policyInformation = new PolicyInformation(new ObjectID(
			    "1.3.6.1.4.1.2706.2.2.1.1.1.1.1"),
			    new PolicyQualifierInfo[] { policyQualifierInfo });
			CertificatePolicies certificatePolicies = new CertificatePolicies(
			    new PolicyInformation[] { policyInformation });
			extensions[2] = certificatePolicies;

			//
			// create self signed CA certs
			//
			X509Certificate caRSA = null;
			X509Certificate caDSA = null;
			X509Certificate caRSAPss = null;
			X509Certificate[] chain = new X509Certificate[1];
			// for verifying the created certificates
			SimpleChainVerifier verifier = new SimpleChainVerifier();

			if (create_rsa) {
				issuer.addRDN(ObjectID.commonName, "IAIK RSA Test CA");
				System.out.println("create self signed RSA CA certificate...");
				caRSA = createCertificate(issuer, ca_rsa.getPublic(), issuer, null,
				    ca_rsa.getPrivate(), AlgorithmID.sha1WithRSAEncryption, extensions);
				// verify the self signed certificate
				caRSA.verify();
				// set the CA cert as trusted root
				verifier.addTrustedCertificate(caRSA);
				chain[0] = caRSA;
				addToKeyStore(ca_rsa, chain, CA_RSA);
				issuer.removeRDN(ObjectID.commonName);
			}

			if (create_dsa) {
				issuer.addRDN(ObjectID.commonName, "IAIK DSA Test CA");
				System.out.println("create self signed DSA CA certificate...");
				caDSA = createCertificate(issuer, ca_dsa.getPublic(), issuer, null,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				// verify the self signed certificate
				caDSA.verify();
				// set the CA cert as trusted root
				verifier.addTrustedCertificate(caDSA);
				chain[0] = caDSA;
				addToKeyStore(ca_dsa, chain, CA_DSA);
				issuer.removeRDN(ObjectID.commonName);
			}

			if (create_rsa_pss) {
				issuer.addRDN(ObjectID.commonName, "IAIK RSA-PSS Test CA");
				System.out.println("create self signed RSA-PSS CA certificate...");
				caRSAPss = createCertificate(issuer, ca_rsa_pss.getPublic(), issuer, null,
				    ca_rsa_pss.getPrivate(), (AlgorithmID) AlgorithmID.rsassaPss.clone(),
				    extensions);
				// verify the self signed certificate
				caRSAPss.verify();
				// set the CA cert as trusted root
				verifier.addTrustedCertificate(caRSAPss);
				chain[0] = caRSAPss;
				addToKeyStore(ca_rsa_pss, chain, CA_RSAPSS);
				issuer.removeRDN(ObjectID.commonName);
			}

			//
			// create certificates
			//
			chain = new X509Certificate[2];

			extensions = new V3Extension[4];
			extensions[0] = new BasicConstraints(false);
			extensions[1] = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
			    | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
			extensions[2] = certificatePolicies;
			// an email address for the certificates
			extensions[3] = new SubjectAltName(new GeneralNames(new GeneralName(
			    GeneralName.rfc822Name, "smimetest@iaik.tugraz.at")));

			// create a RSA certificate
			if (create_rsa) {
				issuer.addRDN(ObjectID.commonName, "IAIK RSA Test CA");
				// 512
				subject.addRDN(ObjectID.commonName, "RSA 512 bit Demo Certificate");
				System.out.println("create 512 bit RSA demo certificate...");
				chain[0] = createCertificate(subject, rsa512.getPublic(), issuer, caRSA,
				    ca_rsa.getPrivate(), AlgorithmID.sha1WithRSAEncryption, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caRSA;
				// and verify the chain
				verifier.verifyChain(chain);
				addToKeyStore(rsa512, chain, RSA_512);
				// 1024
				subject.addRDN(ObjectID.commonName, "RSA 1024 bit Demo Certificate");
				System.out.println("create 1024 bit RSA demo certificate...");
				chain[0] = createCertificate(subject, rsa1024.getPublic(), issuer, caRSA,
				    ca_rsa.getPrivate(), AlgorithmID.sha1WithRSAEncryption, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caRSA;
				verifier.verifyChain(chain);
				addToKeyStore(rsa1024, chain, RSA_1024);
				// 2048
				subject.addRDN(ObjectID.commonName, "RSA 2048 bit Demo Certificate");
				System.out.println("create 2048 bit RSA demo certificate...");
				chain[0] = createCertificate(subject, rsa2048.getPublic(), issuer, caRSA,
				    ca_rsa.getPrivate(), AlgorithmID.sha1WithRSAEncryption, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caRSA;
				verifier.verifyChain(chain);
				addToKeyStore(rsa2048, chain, RSA_2048);
				issuer.removeRDN(ObjectID.commonName);
			}

			// create a RSA-PSS certificate
			if (create_rsa_pss) {
				issuer.addRDN(ObjectID.commonName, "IAIK RSA-PSS Test CA");
				// 1024
				subject.addRDN(ObjectID.commonName, "RSA-PSS 1024 bit Demo Certificate");
				System.out.println("create 1024 bit RSA-PSS demo certificate...");
				chain[0] = createCertificate(subject, rsapss1024.getPublic(), issuer, caRSAPss,
				    ca_rsa_pss.getPrivate(), (AlgorithmID) AlgorithmID.rsassaPss.clone(),
				    extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caRSAPss;
				verifier.verifyChain(chain);
				addToKeyStore(rsapss1024, chain, RSAPSS_1024);
				issuer.removeRDN(ObjectID.commonName);
			}

			// create a RSA-OAEP certificate
			if (create_rsa_oaep) {
				issuer.addRDN(ObjectID.commonName, "IAIK RSA-PSS Test CA");
				// 1024
				subject.addRDN(ObjectID.commonName, "RSA-OAEP 1024 bit Demo Certificate");
				System.out.println("create 1024 bit RSA-OAEP demo certificate...");
				chain[0] = createCertificate(subject, rsaoaep1024.getPublic(), issuer, caRSAPss,
				    ca_rsa_pss.getPrivate(), (AlgorithmID) AlgorithmID.rsassaPss.clone(),
				    extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caRSAPss;
				verifier.verifyChain(chain);
				addToKeyStore(rsaoaep1024, chain, RSAOAEP_1024);
				issuer.removeRDN(ObjectID.commonName);
			}

			// create a DSA certificates
			if (create_dsa) {
				extensions[1] = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);

				issuer.addRDN(ObjectID.commonName, "IAIK DSA Test CA");
				// 512
				subject.addRDN(ObjectID.commonName, "DSA 512 bit Demo Certificate");
				System.out.println("create 512 bit DSA demo certificate...");
				chain[0] = createCertificate(subject, dsa512.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dsa512, chain, DSA_512);
				// 1024
				subject.addRDN(ObjectID.commonName, "DSA 1024 bit Demo Certificate");
				System.out.println("create 1024 bit DSA demo certificate...");
				chain[0] = createCertificate(subject, dsa1024.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dsa1024, chain, DSA_1024);
				// 2048
				subject.addRDN(ObjectID.commonName, "DSA 2048 bit Demo Certificate");
				System.out.println("create 2048 bit DSA demo certificate...");
				chain[0] = createCertificate(subject, dsa2048.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dsa2048, chain, DSA_2048);
				issuer.removeRDN(ObjectID.commonName);
			}

			// create a DH server certificate
			if (create_dh) {
				extensions[1] = new KeyUsage(KeyUsage.keyAgreement);

				issuer.addRDN(ObjectID.commonName, "IAIK DSA Test CA");
				// 512
				subject.addRDN(ObjectID.commonName, "DH 512 bit Demo Certificate");
				System.out.println("create 512 bit DH demo certificate...");
				chain[0] = createCertificate(subject, dh512.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dh512, chain, DH_512);
				// 1024
				subject.addRDN(ObjectID.commonName, "DH 1024 bit Demo Certificate");
				System.out.println("create 1024 bit DH demo certificate...");
				chain[0] = createCertificate(subject, dh1024.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dh1024, chain, DH_1024);
				// 2048
				subject.addRDN(ObjectID.commonName, "DH 2048 bit Demo Certificate");
				System.out.println("create 2048 bit DH demo certificate...");
				chain[0] = createCertificate(subject, dh2048.getPublic(), issuer, caDSA,
				    ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, extensions);
				subject.removeRDN(ObjectID.commonName);
				chain[1] = caDSA;
				verifier.verifyChain(chain);
				addToKeyStore(dh2048, chain, DH_2048);
				issuer.removeRDN(ObjectID.commonName);
			}

			// create a AC issuer certificate
			if (create_ac_issuer) {
				extensions = new V3Extension[2];
				extensions[0] = new KeyUsage(KeyUsage.digitalSignature);
				extensions[1] = certificatePolicies;

				issuer.addRDN(ObjectID.commonName, "IAIK RSA Test CA");
				// 1024
				subject.addRDN(ObjectID.commonName, "IAIK AC Issuer Demo Certificate");
				System.out.println("create AC issuer demo certificate...");
				chain[0] = createCertificate(subject, ac_issuer.getPublic(), issuer, caRSA,
				    ca_rsa.getPrivate(), AlgorithmID.sha1WithRSAEncryption, extensions);
				addToKeyStore(ac_issuer, chain, AC_ISSUER);
			}

			System.out.println("\nCertificates created!");

		} catch (Exception ex) {
			System.out.println("Exception: " + ex);
		}
	}

	/**
	 * Starts the certificate generation.
	 * 
	 * @param useCurrentDir
	 *          whether to use the current working directory
	 */
	public static void start(boolean useCurrentDir) {
		RSAPssSignature.setValidateAgainstPssKeyParameters(true);
		SetupKeyStore suks = new SetupKeyStore();
		suks.initializeKeyStore(useCurrentDir);
		if (suks.create_only_certificates) {
			suks.getPrivateKeys();
		} else {
			suks.generatePrivateKeys();
		}
		suks.generateCertificates();
		suks.saveKeyStore();
	}

	/**
	 * Creates the test certificates.
	 */
	public static void start() {
		start(false);
	}

	/**
	 * Main method.
	 */
	public static void main(String arg[])
	    throws IOException
	{

		Security.insertProviderAt(new IAIK(), 2);
		start();
		System.in.read();
	}
}
