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

import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivateKey;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class shows the sequential combination of the SignedData and EnvelopedData
 * stream implementations.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupKeyStore program.
 * <p>
 * This class tests the following <a href =
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-7/>PKCS#7</a>
 * content type implementations:
 * @version File Revision <!-- $$Revision: --> 18 <!-- $ -->
 */
public class TestSignedAndEnvelopedDataStream implements IAIKDemo {

	// certificate of user 1
	X509Certificate user1;
	// private key of user 1
	PrivateKey user1_pk;
	// certificate of user 2
	X509Certificate user2;
	// private key of user 2
	PrivateKey user2_pk;
	// a certificate chain containing the user certs + CA
	X509Certificate[] certificates;

	/**
	 * Setup the demo certificate chains.
	 *
	 * Keys and certificate are retrieved from the demo KeyStore.
	 *
	 * @exception IOException if an file read error occurs
	 */
	public TestSignedAndEnvelopedDataStream() {
		// add all certificates to the list
		X509Certificate[] certs = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
		    IaikKeyStore.SZ_1024);
		user1 = certs[0];
		user1_pk = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		user2 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_2048)[0];
		user2_pk = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_2048);
		certificates = new X509Certificate[certs.length + 1];
		System.arraycopy(certs, 0, certificates, 0, certs.length);
		certificates[certs.length] = user2;
	}

	public void testSignedAndEnvelopedDataStream(byte[] message)
	    throws Exception
	{
		// repository for the signed and enveloped message
		byte[] signed_enveloped_message;
		// the InputStream containing the data to sign and encrypt
		InputStream is = new BufferedInputStream(new ByteArrayInputStream(message));
		// the OutputStream where the data shall be written to
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OutputStream os = new BufferedOutputStream(out);

		// create an implicit signed message (signature contains message)
		SignedDataStream signed = new SignedDataStream(is, SignedDataStream.IMPLICIT);

		// these certificates are sent within the signature
		signed.setCertificates(certificates);

		// add one signer
		// cert at index 0 is the user certificate
		IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

		// create a new SignerInfo
		SignerInfo signer_info = new SignerInfo(issuer, AlgorithmID.sha, user1_pk);
		// create some authenticated attributes
		// the message digest attribute is automatically added
		Attribute[] attributes = new Attribute[2];
		// content type is data
		attributes[0] = new Attribute(ObjectID.contentType,
		    new ASN1Object[] { ObjectID.pkcs7_data });
		// signing time is now
		attributes[1] = new Attribute(ObjectID.signingTime,
		    new ASN1Object[] { new ChoiceOfTime().toASN1Object() });
		// set the attributes
		signer_info.setAuthenticatedAttributes(attributes);
		// finish the creation of SignerInfo by calling method addSigner
		signed.addSignerInfo(signer_info);

		// we have to sign and encrypt => connect 2 streams
		PipedOutputStream piped_out = new PipedOutputStream();
		PipedInputStream piped_in = new PipedInputStream(piped_out);
		// a new Thread between the 2 streams
		Writer writer = new Writer(signed, piped_out);
		writer.start();

		// encrypt with DES/CBC
		EnvelopedDataStream enveloped = new EnvelopedDataStream(piped_in, AlgorithmID.des_CBC);
		// add recipients where the symmetric key is encrypted with RSA
		// create the recipient infos
		RecipientInfo[] recipients = new RecipientInfo[2];
		// user1 is the first receiver
		recipients[0] = new RecipientInfo(user1, AlgorithmID.rsaEncryption);
		// user2 is the second receiver
		recipients[1] = new RecipientInfo(user2, AlgorithmID.rsaEncryption);

		// specify the recipients of the encrypted message
		enveloped.setRecipientInfos(recipients);

		// encrypt and write the data to the output stream
		enveloped.writeTo(os, 2048);
		// finished
		os.close();
		is.close();
		// get the signed and encrypted message from the ByteArrayOutputStream
		signed_enveloped_message = out.toByteArray();
		System.out.println("Message created, now doing the parsing...");
		// and now decrypt the data and verify the signature
		is = new BufferedInputStream(new ByteArrayInputStream(signed_enveloped_message));
		enveloped = new EnvelopedDataStream(is);
		// use this private key to decrypt the symmetric key of recipient 0
		enveloped.setupCipher(user1_pk, 0);
		// get the InputStream with the decrypted data
		InputStream data_dec = enveloped.getInputStream();
		System.out.println("Message decrypted!");
		// read the signed data from the decrypted InputStream
		signed = new SignedDataStream(data_dec);
		// get the InputStream with the signed, plain data
		InputStream data = signed.getInputStream();

		// reset our output stream
		out.reset();
		// write the decrypted and verified data to 'out'
		os = new BufferedOutputStream(out);
		// use the StreamCopier to copy the data
		Util.copyStream(data, os, null);
		os.close();
		out.close();
		is.close();
		data_dec.close();

		// now verify the signature of the one and only signer and print the certificate of the signer
		X509Certificate cert = signed.verify(0);
		System.out.println("Signature OK from: " + cert.getSubjectDN());

		System.out.println("Received message: \"" + new String(out.toByteArray()) + "\"");
	}

	/**
	 * Starts the test.
	 */
	public void start() {
		// the test message
		String m = "This demo message will be signed and/or encrypted.";
		System.out.println("Test message: \"" + m + "\"");
		System.out.println();
		byte[] message = m.getBytes();

		try {
			testSignedAndEnvelopedDataStream(message);
		} catch (Exception ex) {
			ex.printStackTrace();

			throw new RuntimeException();
		}
	}

	/**
	 * Starts the PKCS#7 content type implementation tests.
	 *
	 * @exception IOException
	 *            if an I/O error occurs when reading required keys
	 *            and certificates from files
	 */
	public static void main(String argv[])
	    throws Exception
	{

		DemoUtil.initDemos();

		(new TestSignedAndEnvelopedDataStream()).start();
		System.in.read();
	}

	/**
	 * Inner class for copying data between the 2 streams.
	 */
	static class Writer extends Thread {

		SignedDataStream signed;
		OutputStream os;
		Exception exception;

		public Writer(SignedDataStream signed, OutputStream os) {
			super("Writer");
			this.signed = signed;
			this.os = os;
		}

		/**
		 * Writes the SMimeSigned to the OutputStream.
		 */
		public void run() {
			try {
				signed.writeTo(os, 2048);
				os.close();
			} catch (Exception ex) {
				exception = ex;
				System.out.println("Writer exception: " + exception);
			}
		}

		/**
		 * Returns a possible exception.
		 */
		public Exception getException() {
			return exception;
		}
	}

}
