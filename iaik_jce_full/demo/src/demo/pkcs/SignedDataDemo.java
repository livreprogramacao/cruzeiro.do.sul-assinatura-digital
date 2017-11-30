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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.x509.X509Certificate;

/**
 * This class creates a new SignedData object and adds a new signer
 * to the existing SignedData.
 * @version File Revision <!-- $$Revision: --> 19 <!-- $ -->
 */
public class SignedDataDemo implements IAIKDemo {

	String testMessage;

	public SignedDataDemo() {
		testMessage = "This is a test of the PKCS#7 implementation!";
	}

	public void start() {

		try {
			// output stream for storing the signed data
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			// create a new SignedData
			create(os, testMessage, IaikKeyStore.SZ_1024);
			// verify it
			verify(new ByteArrayInputStream(os.toByteArray()));
			// add another signer
			os = add(new ByteArrayInputStream(os.toByteArray()), IaikKeyStore.SZ_2048);
			// and verify it again
			verify(new ByteArrayInputStream(os.toByteArray()));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Verifies a given SignedData object which is read from the given input stream.
	 *
	 * @param is an input stream holding the SignedData object
	 */
	private void verify(InputStream is)
	    throws Exception
	{

		System.out.println("\nVerify the SignedData...");
		// read the SignedData from the given input stream
		SignedData signedData = new SignedData(is);
		// get the content
		byte[] content = signedData.getContent();
		// and show it
		System.out.println("Content of SignedData: " + new String(content));

		// print the certificates included
		System.out.println("Certificates included:");
		X509Certificate[] certs = signedData.getCertificates();
		try {
			for (int i = 0; i < certs.length; i++)
				System.out.println(certs[i]);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		// print the signers included
		System.out.println("Signers included:");
		SignerInfo[] signerInfos = signedData.getSignerInfos();

		for (int i = 0; i < signerInfos.length; i++) {
			X509Certificate cert = signedData.verify(i);
			System.out.println("Signer: " + cert.getSubjectDN());
			System.out.println(signerInfos[i].toString(true));
		}
	}

	/**
	 * Creates a new SignedData object.
	 *
	 * @param os the output stream where the created object shall be written to
	 * @param message the content for the SignedData
	 * @param size specifies which private key/certificate to use from the KeyStore
	 */
	private void create(OutputStream os, String message, int size)
	    throws Exception
	{

		System.out.println("\nCreate a new SignedData with content: " + message);
		// get the certificate chain from the KeyStore
		X509Certificate[] certificates = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
		    size);
		// create the SignedData
		SignedData signedData = new SignedData(message.getBytes(), SignedDataStream.IMPLICIT);
		// set the certificates
		signedData.setCertificates(certificates);
		// add a signer
		addSigner(signedData, size);
		// and write it to the given output stream
		signedData.writeTo(os);
		os.close();
	}

	/**
	 * Adds a new Signer to a given SignedData.
	 *
	 * @param is the input stream holding the existing SignedData object
	 * @param size specifies which private key/certificate to use from the KeyStore
	 */
	private ByteArrayOutputStream add(InputStream is, int size)
	    throws Exception
	{

		System.out.println("Adding a signature to an existing SignedData...");
		// read the existing SignedData from the given InputStream
		SignedData signedData = new SignedData(is);
		// print the content
		byte[] content = signedData.getContent();
		System.out.println("Existing content is: " + new String(content));

		// add another signer
		addSigner(signedData, size);

		// create a new output stream and save it
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		signedData.writeTo(os);

		is.close();
		os.close();

		// return the output stream which contains the new SignedData
		return os;
	}

	/**
	 * Adds the new signer.
	 *
	 * @param signedData the SignedData where the new signer shall be added
	 * @param size specifies which private key/certificate to use from the KeyStore
	 */
	private void addSigner(SignedData signedData, int size)
	    throws Exception
	{

		// get new certificate and private key
		X509Certificate cert = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, size)[0];
		PrivateKey privateKey = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, size);

		// add to the existing list of certificates
		X509Certificate[] certs = signedData.getCertificates();
		X509Certificate[] newCerts = new X509Certificate[certs.length + 1];
		System.arraycopy(certs, 0, newCerts, 0, certs.length);
		newCerts[certs.length] = cert;
		// set the new certificate list
		signedData.setCertificates(newCerts);

		// create a new SignerInfo
		SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(cert),
		    AlgorithmID.ripeMd160, privateKey);
		// define some attributes
		Attribute[] attributes = {
		    new Attribute(ObjectID.contentType, new ASN1Object[] { ObjectID.pkcs7_data }),
		    new Attribute(ObjectID.signingTime,
		        new ASN1Object[] { new ChoiceOfTime().toASN1Object() }) };
		// set the attributes
		signerInfo.setAuthenticatedAttributes(attributes);
		// and add the new signer
		signedData.addSignerInfo(signerInfo);
	}

	/**
	 * Starts the PKCS#7 content type implementation tests.
	 *
	 * @exception IOException
	 *            if an I/O error occurs when reading required keys
	 *            and certificates from files
	 */
	public static void main(String argv[])
	    throws IOException
	{

		DemoUtil.initDemos();
		(new SignedDataDemo()).start();

		System.in.read();
	}
}
