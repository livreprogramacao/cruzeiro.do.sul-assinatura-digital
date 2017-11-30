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

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.GregorianCalendar;

import demo.IAIKDemo;
import demo.util.DemoUtil;

/**
 * This class tests the implementation of creating and verifying certificates
 * based on the X509 notation.
 * <p>
 * 
 * @version File Revision <!-- $$Revision: --> 21 <!-- $ -->
 */
public class X509 implements IAIKDemo {

	/**
	 * Generates a Key Pair for the specified public-key algorithm.
	 *
	 * @param algorithm the name of the public-key algorithm
	 * @param bits the length of the key (modulus) in bits
	 * @return the KeyPair
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
	 * Verifies a certificate.
	 * If the <i>caCert</i> parameter is not specified a self signed certificate
	 * will be verified; otherwise a signed certificate will be verified
	 * by using the public key of the issuer.
	 *
	 * @param userCert the certificate to be verified
	 * @param caCert the certificate used for verifying the userCert
	 * 
	 * @exception if an error occurs
	 */
	public void verifyCertificate(X509Certificate userCert, X509Certificate caCert)
	    throws Exception
	{

		if (caCert == null) userCert.verify(); // self signed
		else userCert.verify(caCert.getPublicKey());
	}

	/**
	 * Creates a certificate according to the X.509 Notation.
	 * <p>
	 * Depending on the subject ID either a self-signed CA certificate will
	 * be created or a user certificate. If the <code>extensions</code> parameter
	 * is set to <code>true</code>, <code>SubjectKeyIdentifier</code>, <code>KeyUsage</code>,
	 * and <code>BasicConstraints</code> extensions will be added to the new certificate.
	 *
	 * @param subject the user demanding the certificate (may be the certification authority itself)
	 * @param pk the subject's public key to be certified
	 * @param issuer the certification authority that issues the certificate
	 * @param sk the issuer's private key for signing the certificate
	 * @param algorithm the ID of the signature algorithm
	 * @param extensions a boolean value indicating if there are any extending informations
	 *
	 * @return the certificate just created
	 */
	public X509Certificate createCertificate(Name subject,
	                                         PublicKey pk,
	                                         Name issuer,
	                                         PrivateKey sk,
	                                         AlgorithmID algorithm,
	                                         boolean extensions)
	    throws Exception
	{

		byte[] id = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

		X509Certificate cert = new X509Certificate();

		cert.setSerialNumber(BigInteger.valueOf(0x1234L));
		cert.setSubjectDN(subject);
		cert.setPublicKey(pk);
		cert.setIssuerDN(issuer);

		GregorianCalendar date = new GregorianCalendar();
		cert.setValidNotBefore(date.getTime()); // not before now

		date.add(Calendar.MONTH, 6);
		cert.setValidNotAfter(date.getTime());

		if (extensions) { // add some v3 extensions
			SubjectKeyIdentifier ski = new SubjectKeyIdentifier(id);
			cert.addExtension(ski);

			BasicConstraints bc = new BasicConstraints(true, 1);
			bc.setCritical(true);
			cert.addExtension(bc);

			KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign
			    | KeyUsage.cRLSign);
			cert.addExtension(ku);
		}
		// sign the certificate
		cert.sign(algorithm, sk);
		// and return the new cert
		return cert;
	}

	/**
	 * Tests the certificate creation and verification process.
	 * <P>
	 * The method goes to the following steps:
	 * <ul>
	 * <li> Generating a CA key pair for self signed certificate
	 * <li> Generating a user key pair for signed certifications
	 * <li> Creating a self-signed CA certificate certifying the CA's public key with
	 *      the CA's private key
	 * <li> Creating a user certificate certifying the user's public key pair with
	 *      the CA's private key
	 * <li> Verifying the two certificates just created
	 * </ul>
	 */
	public void testRSACertificates()
	    throws Exception
	{

		System.out.println("test RSA certificates...\n");

		System.out.println("generate CA KeyPair for self signed certificate...");
		KeyPair caKeyPair = generateKeyPair("RSA", 1024);

		System.out.println("generate user KeyPair for signed certificate...");
		KeyPair user = generateKeyPair("RSA", 1024);

		Name issuer = new Name();
		issuer.addRDN(ObjectID.country, "AT");
		issuer.addRDN(ObjectID.organization, "TU Graz");
		issuer.addRDN(ObjectID.organizationalUnit, "IAIK");
		issuer.addRDN(ObjectID.commonName, "IAIK Test CA");

		Name subject = new Name();
		subject.addRDN(ObjectID.country, "AT");
		subject.addRDN(ObjectID.organization, "IAIK");
		subject.addRDN(ObjectID.emailAddress, "user@iaik.tugraz.at");
		subject.addRDN(ObjectID.commonName, "Test User");

		System.out.println("create self signed CA certificate ...");
		X509Certificate caCert = createCertificate(issuer, caKeyPair.getPublic(), issuer,
		    caKeyPair.getPrivate(), AlgorithmID.sha1WithRSAEncryption, false);

		System.out.println("create user certificate ...");
		X509Certificate userCert = createCertificate(subject, user.getPublic(), issuer,
		    caKeyPair.getPrivate(), AlgorithmID.sha1WithRSAEncryption, false);

		System.out.print("verify self signed certificate: ");
		verifyCertificate(caCert, null);
		System.out.print("verify signed certificate: ");
		verifyCertificate(userCert, caCert);
	}

	/**
	 * Tests the certificate creation and verification process implementation using
	 * the <i>dsaWithSHA</i> signature algorithm.
	 * <P>
	 * The method goes to the following steps:
	 * <ul>
	 * <li> Generating a CA key pair for self signed certificate
	 * <li> Generating a user key pair for signed certifications
	 * <li> Creating a self-signed CA certificate certifying the CA's public key with
	 *      the CA's private key
	 * <li> Creating a user certificate certifying the user's public key pair with
	 *      the CA's private key
	 * <li> Verifying the two certificates just created
	 * </ul>
	 */
	public void testDSACertificates()
	    throws Exception
	{

		System.out.println("test DSA certificates...\n");

		System.out.println("generate CA KeyPair for self signed certificate...");
		KeyPair caKeyPair = generateKeyPair("DSA", 512);

		System.out.println("generate user KeyPair for signed certificate...");
		KeyPair user = generateKeyPair("DSA", 512);

		Name issuer = new Name();
		issuer.addRDN(ObjectID.country, "AT");
		issuer.addRDN(ObjectID.organization, "TU Graz");
		issuer.addRDN(ObjectID.organizationalUnit, "IAIK");
		issuer.addRDN(ObjectID.commonName, "IAIK Test CA");

		Name subject = new Name();
		subject.addRDN(ObjectID.country, "AT");
		subject.addRDN(ObjectID.organization, "IAIK");
		subject.addRDN(ObjectID.emailAddress, "user@iaik.tu-graz.ac.at");
		subject.addRDN(ObjectID.commonName, "Test User");

		System.out.println("create self signed CA certificate...");
		X509Certificate caCert = createCertificate(issuer, caKeyPair.getPublic(), issuer,
		    caKeyPair.getPrivate(), AlgorithmID.dsaWithSHA, true);

		System.out.println("create user certificate...");
		X509Certificate userCert = createCertificate(subject, user.getPublic(), issuer,
		    caKeyPair.getPrivate(), AlgorithmID.dsaWithSHA, true);

		System.out.print("verify self signed certificate: ");
		verifyCertificate(caCert, null);
		System.out.print("verify signed certificate: ");
		verifyCertificate(userCert, caCert);
	}

	/**
	 * Tests the certificate creation and verification process implementation.
	 */
	public void start() {

		try {
			testRSACertificates();
			testDSACertificates();
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs certificate creation and verification tests.
	 *
	 * @exception IOException if an I/O Error occurs
	 */
	public static void main(String arg[])
	    throws IOException
	{

		DemoUtil.initDemos();
		(new X509()).start();
		System.in.read();
	}
}
