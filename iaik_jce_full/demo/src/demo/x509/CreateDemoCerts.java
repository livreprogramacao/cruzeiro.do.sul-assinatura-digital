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

package demo.x509;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Vector;

import demo.IAIKDemo;
import demo.util.DemoUtil;

import iaik.asn1.ASN1;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.utils.KeyAndCertificate;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.netscape.NetscapeCertType;

/**
 * Creates certificate chains for some demo applications and writes them -
 * together with the actual subject's private key - into several <i>.PEM</i>
 * (Base64 encoded DER format) files. Creates some test certificate chains and
 * writes them into <i>.PEM</i> files.
 * <p>
 * This class creates a - if not already existing - "test" sub-directory of the
 * current working directory for writing the PEM encoded test certificate chains
 * to it. Each chain is stored together with the private key belonging to the
 * subject's certificate, which is located at index 0 of the chain.
 * <p>
 * This class creates two CA certificates and four user certificates. The CA
 * certificate chains only hold the corresponding CA certificates, whereas the
 * user certificate chains contain the user (subject) certificate at index 0 and
 * the CA certificate at index 1. The private key giving a <code>
 * KeyAndCertificate</code> structure together with the actual certificate
 * chain, in any case belongs to the certificate at index 0. All generated keys
 * have a modulus length of 1024 bits. Since the keys actually are generated
 * during program execution, running this class will take a certain amount of
 * time.
 * <p>
 * The following certificates (and keys) are created and saved to files:
 * <ul>
 * <li>A Self-signed RSA certificate; saved to "test/caRSA.PEM"
 * <li>A Self-signed RSA certificate; saved to "test/caDSA.PEM"
 * <li>Two RSA/RSA user certificates; saved to "userRSAcert1.PEM" and
 * "userRSAcert2.PEM"
 * <li>A DSA/DSA user certificate; saved to "userDSAcert.PEM"
 * <li>A DH/DSA user certificate; saved to "userDHcert.PEM"
 * </ul>
 * 
 * @version File Revision <!-- $$Revision: --> 24 <!-- $ -->
 */
public class CreateDemoCerts implements IAIKDemo {

	/**
	 * Creates files in PEM (Base64 encoded DER) format
	 */
	// final static int format = ASN1.PEM;
	private final static int format = ASN1.DER;
	private final static int key_length = 512;
	private final static boolean use_extensions = true;

	/**
	 * Saves the private key and the certificate chain into one file.
	 * 
	 * @param keyPair
	 *          the keyPair from which to get the private key to be written to the
	 *          specified file
	 * @param chain
	 *          the chain of X509 certificates to be written to the specified file
	 * @param fileName
	 *          the name of the file to which private key and certificates shall
	 *          be written
	 * 
	 * @exception IOException
	 *              if an error occurs when writing to the file
	 */
	public void saveKeyAndCert(KeyPair keyPair, X509Certificate[] chain, String fileName)
	    throws IOException
	{

		fileName = fileName + (format == ASN1.DER ? ".der" : ".pem");

		System.out.println("save private key and certificate chain to file " + fileName
		    + "...");
		new KeyAndCertificate(keyPair.getPrivate(), chain).saveTo(fileName, format);
	}

	/**
	 * Generates a Key pair for the requested public key algorithm.
	 * 
	 * @param algorithm
	 *          the public key algorithm
	 * @param bits
	 *          the length of the key (modulus) in bits
	 * 
	 * @return the KeyPair
	 * 
	 * @exception NoSuchAlgorithmException
	 *              if the requested algorithm is not implemented
	 */
	public KeyPair generateKeyPair(String algorithm, int bits)
	    throws Exception
	{

		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
		generator.initialize(bits);
		KeyPair kp = generator.generateKeyPair();

		return kp;
	}

	/**
	 * Verifies a chain of certificates where the user certificate is stored at
	 * index 0. The self-signed top level certificate is verified using its
	 * inherent public key. Any other certificate of the chain is verified by
	 * means of the public key derived from the issuing certificate which is
	 * located one index higher in the chain.
	 * <p>
	 * certs[0] = user certificate. certs[x] = self signed CA certificate
	 * 
	 * @param certs
	 *          the certificate chain to verify
	 */
	public void verifyCertificateChain(X509Certificate[] certs)
	    throws Exception
	{

		int anz = certs.length;

		verifyCertificate(certs[anz - 1], null);
		for (int i = anz - 1; i > 0; i--)
			verifyCertificate(certs[i - 1], certs[i]);

		System.out.println("Verify certificate chain OK!");
	}

	/**
	 * Verifies the digital signature of a certificate.
	 * 
	 * @param userCert
	 *          the certificate to verify
	 * @param caCert
	 *          the certificate of the CA which has issued the userCert or
	 *          <code>null</code> if the userCert is a self signed certificate
	 */
	public void verifyCertificate(X509Certificate userCert, X509Certificate caCert)
	    throws Exception
	{
		if (caCert == null) userCert.verify(); // self signed
		else userCert.verify(caCert.getPublicKey());
	}

	/**
	 * Creates a test certificate according to the X.509 Notation.
	 * <p>
	 * Depending on the subject ID either a self-signed CA certificate will be
	 * created or a user certificate.
	 * 
	 * @param subject
	 *          the user demanding the certificate (may be the certification
	 *          authority itself)
	 * @param pk
	 *          the subject's public key to be certified
	 * @param issuer
	 *          the certification authority that issues the certificate
	 * @param sk
	 *          the issuer's private key for signing the certificate
	 * @param algorithm
	 *          the ID of the signature algorithm
	 * @param serialNumber
	 *          the issuer-specific serial number of the certificate
	 * 
	 * @exception CertificateException
	 *              if the certificate cannot be created
	 * 
	 * @return the certificate just created
	 */
	public X509Certificate createCertificate(Name subject,
	                                         PublicKey pk,
	                                         Name issuer,
	                                         PrivateKey sk,
	                                         AlgorithmID algorithm,
	                                         int serialNumber,
	                                         V3Extension[] extensions)
	    throws Exception
	{

		X509Certificate cert = new X509Certificate();

		cert.setSerialNumber(BigInteger.valueOf(serialNumber));
		cert.setSubjectDN(subject);
		cert.setPublicKey(pk);
		cert.setIssuerDN(issuer);

		GregorianCalendar date = new GregorianCalendar();
		date.add(Calendar.DATE, -1);
		cert.setValidNotBefore(date.getTime()); // not before yesterday

		date.add(Calendar.MONTH, 6);
		cert.setValidNotAfter(date.getTime());

		if (extensions != null) {
			for (int i = 0; i < extensions.length; i++)
				cert.addExtension(extensions[i]);
		}
		cert.sign(algorithm, sk);

		return cert;
	}

	/**
	 * Creates some test certificate chains and writes them into <i>.PEM</i>
	 * files.
	 * <p>
	 * This method creates a - if not already existing - "test" sub-directory of
	 * the current working directory for writing the PEM encoded test certificate
	 * chains to it. Each chain is stored together with the private key belonging
	 * to the subject's certificate, which is located at index 0 of the chain.
	 * <p>
	 * This method creates two CA certificates and four user certificates. The CA
	 * certificate chains only hold the corresponding CA certificates, whereas the
	 * user certificate chains contain the user (subject) certificate at index 0
	 * and the CA certificate at index 1. The private key giving a <code>
	 * KeyAndCertificate</code> structure together with the actual certificate
	 * chain, in any case belongs to the certificate at index 0. All generated
	 * keys have a modulus length of 1024 bits.
	 * <p>
	 * The following certificates (and keys) are created and saved to files:
	 * <ul>
	 * <li>A Self-signed RSA certificate; saved to "test/caRSA.PEM"
	 * <li>A Self-signed RSA certificate; saved to "test/caDSA.PEM"
	 * <li>Two RSA/RSA user certificates; saved to "userRSAcert1.PEM" and
	 * "userRSAcert2.PEM"
	 * <li>A DSA/DSA user certificate; saved to "userDSAcert.PEM"
	 * <li>A DH/DSA user certificate; saved to "userDHcert.PEM"
	 * </ul>
	 * 
	 */
	public void start() {

		try {
			boolean create_rsa = true;
			boolean create_dsa = true;
			boolean create_dh = true;

			// create a test directory
			File file = new File("test");

			if (!file.exists()) {
				file.mkdir();
			}

			// First create the private keys
			KeyPair caRSA = null;
			KeyPair caDSA = null;
			KeyPair user1Key = null;
			KeyPair user2Key = null;
			KeyPair user3Key = null;
			KeyPair user4Key = null;

			try {
				System.out.println("generate RSA KeyPair for CA certificate [" + key_length
				    + " bits]...");
				caRSA = generateKeyPair("RSA", key_length);
			} catch (NoSuchAlgorithmException ex) {
				System.out.println("No implementation for RSA! Can't create RSA certificates!\n");
				create_rsa = false;
			}

			try {
				System.out.println("generate DSA KeyPair for CA certificate [" + key_length
				    + " bits]...");
				caDSA = generateKeyPair("DSA", key_length);
			} catch (NoSuchAlgorithmException ex) {
				System.out.println("No implementation for DSA! Can't create DSA certificates!");
				create_dsa = false;
			}

			if (create_rsa) {
				System.out.println("generate RSA KeyPair for user1 [" + key_length + " bits]...");
				user1Key = generateKeyPair("RSA", key_length);

				System.out.println("generate RSA KeyPair for user2 [" + key_length + " bits]...");
				user2Key = generateKeyPair("RSA", key_length);
			}

			if (create_dsa) {
				System.out.println("generate DSA KeyPair for user3 certificate [" + key_length
				    + " bits]...");
				user3Key = generateKeyPair("DSA", key_length);
			}

			try {
				System.out.println("generate DH KeyPair for user4 certificate [" + key_length
				    + " bits]...");
				user4Key = generateKeyPair("DH", key_length);
			} catch (NoSuchAlgorithmException ex) {
				System.out.println("No implementation for DH! Can't create DH certificates!");
				create_dh = false;
			}

			// Now create the certificates

			Name issuer = new Name();
			issuer.addRDN(ObjectID.country, "AT");
			issuer.addRDN(ObjectID.organization, "TU Graz");
			issuer.addRDN(ObjectID.organizationalUnit, "IAIK");
			issuer.addRDN(ObjectID.commonName, "IAIK Test Certification Authority");

			Name userSubject = new Name();
			userSubject.addRDN(ObjectID.country, "AT");
			userSubject.addRDN(ObjectID.organization, "TU Graz");
			userSubject.addRDN(ObjectID.organizationalUnit, "IAIK");

			// create self signed CA cert
			X509Certificate caRSACert = null;
			X509Certificate caDSACert = null;
			X509Certificate[] chain = new X509Certificate[1];

			Vector extensions = new Vector();

			if (create_rsa) {
				System.out.println("create self signed CA certificate...");

				extensions.removeAllElements();
				extensions.addElement(new NetscapeCertType(NetscapeCertType.SSL_CA
				    | NetscapeCertType.S_MIME_CA));
				extensions.addElement(new BasicConstraints(true, 1));
				extensions.addElement(new KeyUsage(KeyUsage.digitalSignature
				    | KeyUsage.keyCertSign | KeyUsage.cRLSign));

				caRSACert = createCertificate(issuer, caRSA.getPublic(), issuer,
				    caRSA.getPrivate(), AlgorithmID.sha1WithRSAEncryption, 1, toArray(extensions));
				chain[0] = caRSACert;
				saveKeyAndCert(caRSA, chain, "test/caRSA");
			}

			if (create_dsa) {
				System.out.println("create self signed DSA certificate...");
				caDSACert = createCertificate(issuer, caDSA.getPublic(), issuer,
				    caDSA.getPrivate(), AlgorithmID.dsaWithSHA, 2, toArray(extensions));
				chain[0] = caDSACert;
				saveKeyAndCert(caDSA, chain, "test/caDSA");
			}

			// create user certificates

			chain = new X509Certificate[2];
			chain[1] = caRSACert;

			if (create_rsa) {
				userSubject.addRDN(ObjectID.commonName, "User1 - RSA/RSA");
				System.out.println("create User1 certificate [RSA/RSA]...");

				extensions.removeAllElements();
				extensions.addElement(new NetscapeCertType(NetscapeCertType.SSL_CLIENT
				    | NetscapeCertType.S_MIME));
				extensions.addElement(new BasicConstraints(false));
				extensions.addElement(new KeyUsage(KeyUsage.digitalSignature
				    | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment
				    | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));

				chain[0] = createCertificate(userSubject, user1Key.getPublic(), issuer,
				    caRSA.getPrivate(), AlgorithmID.sha1WithRSAEncryption, 3, toArray(extensions));
				userSubject.removeRDN(ObjectID.commonName);
				verifyCertificateChain(chain);
				saveKeyAndCert(user1Key, chain, "test/userRSAcert1");

				userSubject.addRDN(ObjectID.commonName, "User2 - RSA/RSA");
				System.out.println("create User2 certificate [RSA/RSA]...");
				chain[0] = createCertificate(userSubject, user2Key.getPublic(), issuer,
				    caRSA.getPrivate(), AlgorithmID.sha1WithRSAEncryption, 4, toArray(extensions));
				userSubject.removeRDN(ObjectID.commonName);
				verifyCertificateChain(chain);
				saveKeyAndCert(user2Key, chain, "test/userRSAcert2");
			}

			if (create_dsa) {
				chain[1] = caDSACert;
				userSubject.addRDN(ObjectID.commonName, "User3 - DSA/DSA");
				System.out.println("create User3 certificate [DSA/DSA]...");
				chain[0] = createCertificate(userSubject, user3Key.getPublic(), issuer,
				    caDSA.getPrivate(), AlgorithmID.dsaWithSHA, 5, toArray(extensions));
				userSubject.removeRDN(ObjectID.commonName);
				verifyCertificateChain(chain);
				saveKeyAndCert(user3Key, chain, "test/userDSAcert");
			}

			if (create_dh) {
				chain[1] = caDSACert;
				userSubject.addRDN(ObjectID.commonName, "User4 - DH/DSA");
				System.out.println("create User4 certificate [DH/DSA]...");
				chain[0] = createCertificate(userSubject, user4Key.getPublic(), issuer,
				    caDSA.getPrivate(), AlgorithmID.dsaWithSHA, 6, toArray(extensions));
				verifyCertificateChain(chain);
				saveKeyAndCert(user4Key, chain, "test/userDHcert");
			}

			System.out.println("\nDemo certificates created.");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	private V3Extension[] toArray(Vector v) {
		if (use_extensions) {
			V3Extension[] extensions = new V3Extension[v.size()];
			v.copyInto(extensions);
			return extensions;
		}
		return null;
	}

	/**
	 * Starts the certificate creation process.
	 * 
	 * @exception I
	 *              /O Exception an I/O error may occurs when writing to files
	 */
	public static void main(String arg[])
	    throws IOException
	{

		DemoUtil.initDemos();

		(new CreateDemoCerts()).start();
		System.in.read();
	}
}
