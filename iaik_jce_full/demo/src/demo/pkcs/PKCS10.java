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

package demo.pkcs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.pkcs.pkcs9.ExtensionRequest;
import iaik.security.rsa.RSAPrivateKey;
import iaik.x509.extensions.KeyUsage;

/**
 * This class tests the implementation of a PKCS#10 CertificateRequest.
 * @version File Revision <!-- $$Revision: --> 21 <!-- $ -->
 */
public class PKCS10 implements IAIKDemo {

	AlgorithmID signatureAlgorithm;

	public PKCS10() {
		signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;
	}

	/**
	 * Create a PKCS#10 certificate request, sign it and parse it back in!
	 */
	public void start() {

		// get the private key from the KeyStore
		RSAPrivateKey privateKey = (RSAPrivateKey) IaikKeyStore.getPrivateKey(
		    IaikKeyStore.RSA, IaikKeyStore.SZ_1024);

		// create a new Name
		Name subject = new Name();
		subject.addRDN(ObjectID.country, "AT");
		subject.addRDN(ObjectID.locality, "Graz");
		subject.addRDN(ObjectID.organization, "TU Graz");
		subject.addRDN(ObjectID.organizationalUnit, "IAIK");
		subject.addRDN(ObjectID.commonName, "PKCS#10 Test");

		try {
			// new CertificateRequest
			CertificateRequest request = new CertificateRequest(privateKey.getPublicKey(),
			    subject);
			// and define some attributes
			Attribute[] attributes = new Attribute[2];
			// add a ExtensionRequest attribute for KeyUsage digitalSignature and nonRepudiation
			KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature
			    | KeyUsage.nonRepudiation);
			ExtensionRequest extensionRequest = new ExtensionRequest();
			extensionRequest.addExtension(keyUsage);
			attributes[0] = new Attribute(extensionRequest);
			// and an challenge password
			ChallengePassword challengePassword = new ChallengePassword("myPassword");
			attributes[1] = new Attribute(challengePassword);
			// now set the attributes
			request.setAttributes(attributes);
			// sign the request
			request.sign(signatureAlgorithm, privateKey);
			System.out.println("Request generated:");
			System.out.println(request);
			System.out.println();
			// write the DER encoded Request to an OutputStream
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			request.writeTo(os);

			// Read the Request again
			ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
			request = new CertificateRequest(is);
			// and verify it
			boolean ok = request.verify();
			if (ok) {
				System.out.println("CertificateRequest verify ok.");
			} else {
				throw new RuntimeException("CertificateRequest verify error.");
			}
			// look for an ExtensionRequest attribute:
			extensionRequest = (ExtensionRequest) request
			    .getAttributeValue(ExtensionRequest.oid);
			if (extensionRequest != null) {
				// we know that KeyUsage is included
				keyUsage = (KeyUsage) extensionRequest.getExtension(KeyUsage.oid);
				System.out
				    .println("Certificate request contains an ExtensionRequest for KeyUsage: "
				        + keyUsage);
			}

			// look for a ChallengePassword attribute
			challengePassword = (ChallengePassword) request
			    .getAttributeValue(ChallengePassword.oid);
			if (challengePassword != null) {
				System.out.println("Certificate request contains a challenge password: \""
				    + challengePassword.getPassword() + "\".");
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs certificate creation and verification tests.
	 *
	 * @exception Exception if an error occurs
	 */
	public static void main(String arg[])
	    throws Exception
	{

		DemoUtil.initDemos();

		(new PKCS10()).start();
		System.in.read();
	}
}
