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

import iaik.asn1.INTEGER;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.SEQUENCE;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs7.ContentInfoStream;
import iaik.pkcs.pkcs7.EncryptedContentInfoStream;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.security.random.SecRandom;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class demonstrates the EnvelopedDataStream/EncryptedContentInfoStream
 * usages for algorithms that require a specific parameter handling.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupKeyStore program.
 * <p>
 * The following algorithms are demonstrated:
 * <ul>
 * <li>ARCFOUR: Variable-key-size stream cipher; no parameters to be sent
 * <li>RC2_CBC: Variable-key-size block cipher; parameters as used by S/MIME:
 * rc2ParameterVersion and IV; encoded as SEQUENCE:
 * 
 * <pre>
 *               RC2-CBC parameter ::=  SEQUENCE {
 *                 rc2ParameterVersion  INTEGER,
 *                 iv                   OCTET STRING (8)}
 * 
 *               For the effective-key-bits of 40, 64, and 128, the
 *                rc2ParameterVersion values are 160, 120, 58 respectively.
 * </pre>
 * 
 * <li>CAST5_CBC: Feistel type block cipher with key sizes of 40-128 bit in 8
 * bit increments; parameters (RFC 2144):
 * 
 * <pre>
 *               Parameters ::=  SEQUENCE {
 *                 iv         OCTET STRING DEFAULT 0,
 *                 keyLength  INTEGER }
 * 
 * </pre>
 * 
 * </ul>
 * This class shows how an EncryptedContentInfo is explicit created for
 * encrypting the content and supplying it to an EnvelopedDataStream object.
 * 
 * @version File Revision <!-- $$Revision: --> 19 <!-- $ -->
 */
public class TestEncryptedContentInfo implements IAIKDemo {

	// certificate of user 1
	X509Certificate user1;
	// private key of user 1
	PrivateKey user1_pk;
	// certificate of user 2
	X509Certificate user2;
	// private key of user 2
	PrivateKey user2_pk;
	// secure random number generator
	SecureRandom random;

	/**
	 * Setup the demo certificate chains.
	 * 
	 * Keys and certificate are retrieved from the demo KeyStore.
	 * 
	 * @exception IOException
	 *              if a file read error occurs
	 */
	public TestEncryptedContentInfo() {
		// add all certificates to the list
		X509Certificate[] certs = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
		    IaikKeyStore.SZ_1024);
		user1 = certs[0];
		user1_pk = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		user2 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_2048)[0];
		user2_pk = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_2048);

		random = SecRandom.getDefault();
	}

	/**
	 * Creates a PKCS#7 <code>EnvelopedDataStream</code> message.
	 * <p>
	 * The enveloped-data content type consists of encrypted content of any type
	 * and encrypted content-encryption keys for one or more recipients. The
	 * combination of encrypted content and encrypted content-encryption key for a
	 * recipient is a "digital envelope" for that recipient. Any type of content
	 * can be enveloped for any number of recipients in parallel.
	 * 
	 * @param message
	 *          the message to be enveloped, as byte representation
	 * @param contentEA
	 *          the content encryption algorithm
	 * @param keyLength
	 *          the key length for the symmetric key
	 * @return the DER encoding of the <code>EnvelopedData</code> object just
	 *         created
	 * @exception PKCSException
	 *              if the <code>EnvelopedData</code> object cannot be created
	 */
	public byte[] createEnvelopedDataStream(byte[] message,
	                                        AlgorithmID contentEA,
	                                        int keyLength)
	    throws Exception
	{

		ByteArrayInputStream is = new ByteArrayInputStream(message);

		AlgorithmParameterSpec params = null;
		KeyGenerator key_gen = null;
		SecretKey secretKey = null;

		// create iv
		byte[] iv = new byte[8];
		random.nextBytes(iv);

		if (contentEA.equals(AlgorithmID.rc2_CBC)) {
			key_gen = KeyGenerator.getInstance("RC2", "IAIK");
			int rc2_param = 58;
			switch (keyLength) {
			case 40:
				rc2_param = 160;
				break;
			case 64:
				rc2_param = 120;
				break;
			default: // 128
				rc2_param = 58;
				keyLength = 128;
			}
			// create the parameters (SEQUENCE) to be sent
			SEQUENCE parameter = new SEQUENCE();
			parameter.addComponent(new INTEGER(rc2_param));
			parameter.addComponent(new OCTET_STRING(iv));
			contentEA.setParameter(parameter);
			params = new RC2ParameterSpec(keyLength, iv);
		} else if (contentEA.equals(AlgorithmID.arcfour)) {
			key_gen = KeyGenerator.getInstance("ARCFOUR", "IAIK");
			// no params for ARCFOUR
		} else if (contentEA.equals(AlgorithmID.cast5_CBC)) {
			key_gen = KeyGenerator.getInstance("CAST5", "IAIK");
			SEQUENCE parameter = new SEQUENCE();
			parameter.addComponent(new OCTET_STRING(iv));
			parameter.addComponent(new INTEGER(keyLength));
			contentEA.setParameter(parameter);
			params = new IvParameterSpec(iv);

		} else {
			throw new Exception("Algorithm " + contentEA + " not supportted for this test!");
		}

		key_gen.init(keyLength);
		// generate a new key
		secretKey = key_gen.generateKey();

		// create the EncryptedContentInfo for the content to be encrypted
		EncryptedContentInfoStream eci = new EncryptedContentInfoStream(ObjectID.pkcs7_data,
		    is);
		// setup the cipher for encryption
		eci.setupCipher(contentEA, secretKey, params);

		// create the recipient infos
		RecipientInfo[] recipients = new RecipientInfo[2];
		// user1 is the first receiver
		recipients[0] = new RecipientInfo(user1, AlgorithmID.rsaEncryption);
		// encrypt the secret key for recipient 1
		recipients[0].encryptKey(secretKey);
		// user2 is the second receiver
		recipients[1] = new RecipientInfo(user2, AlgorithmID.rsaEncryption);
		// encrypt the secret key for recipient 2
		recipients[1].encryptKey(secretKey);
		// now create the EnvelopedDataStream
		EnvelopedDataStream enveloped_data = new EnvelopedDataStream(recipients, eci);
		// return the EnvelopedData wraped into a ContentInfo where the content is
		// encoded
		// with block size 2048
		enveloped_data.setBlockSize(2048);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		// wrap into ContentInfo
		ContentInfoStream cis = new ContentInfoStream(enveloped_data);
		cis.writeTo(os);
		byte[] enc = os.toByteArray();
		return enc;

	}

	/**
	 * Decrypts the encrypted content of the given <code>EnvelopedData</code>
	 * object for the specified recipient and returns the decrypted (= original)
	 * message.
	 * 
	 * @param encoding
	 *          the <code>EnvelopedData</code> object as DER encoded byte array
	 * @param privateKey
	 *          the private key to decrypt the message
	 * @param recipientInfoIndex
	 *          the index into the <code>RecipientInfo</code> array to which the
	 *          specified private key belongs
	 * 
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 */
	public byte[] getEnvelopedDataStream(byte[] encoding,
	                                     PrivateKey privateKey,
	                                     int recipientInfoIndex)
	    throws Exception
	{

		// create the EnvelopedData object from a DER encoded byte array
		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(encoding);
		ContentInfoStream cis = new ContentInfoStream(is);
		EnvelopedDataStream enveloped_data = (EnvelopedDataStream) cis.getContent();

		AlgorithmParameterSpec params = null;
		// get the recipient infos
		RecipientInfo[] recipients = enveloped_data.getRecipientInfos();

		System.out
		    .println("\nThis message can be decrypted by the owners of the following certificates:");

		for (int i = 0; i < recipients.length; i++) {
			System.out.println("Recipient: " + (i + 1));
			System.out.print(recipients[i].getIssuerAndSerialNumber());
		}
		// decrypt symmetric content encryption key, e.g.:
		SecretKey secretKey = recipients[recipientInfoIndex].decryptKey(user1_pk);

		// get the ECI from the enveloped data:
		EncryptedContentInfoStream eci = (EncryptedContentInfoStream) enveloped_data
		    .getEncryptedContentInfo();
		// get the content encryption algorithm:
		AlgorithmID contentEA = eci.getContentEncryptionAlgorithm();
		System.out.println("Content Encryption Algorithm: " + contentEA);
		if (contentEA.equals(AlgorithmID.rc2_CBC)) {
			// get the parameters as SEQUENCE
			SEQUENCE seq = (SEQUENCE) contentEA.getParameter();
			// create an RC2ParameterSpec:
			int rc2ParameterVersion = ((java.math.BigInteger) seq.getComponentAt(0).getValue())
			    .intValue();
			int effective_key_bits = 32;
			switch (rc2ParameterVersion) {
			case 160:
				effective_key_bits = 40;
				break;
			case 120:
				effective_key_bits = 64;
				break;
			case 58:
				effective_key_bits = 128;
				break;
			default:
				throw new Exception("Invalid rc2ParameterVersion " + rc2ParameterVersion + "!");

			}
			// the iv is the second component
			OCTET_STRING oct = (OCTET_STRING) seq.getComponentAt(1);
			byte[] iv = (byte[]) oct.getValue();
			params = new RC2ParameterSpec(effective_key_bits, iv);

		} else if (contentEA.equals(AlgorithmID.rc5_CBC)) {
			OCTET_STRING oct = (OCTET_STRING) contentEA.getParameter();
			// create an IvParameterSpec:
			params = new IvParameterSpec((byte[]) oct.getValue());
		} else if (contentEA.equals(AlgorithmID.arcfour)) {
			// nothing to do: params already null
			// params = null;
		} else if (contentEA.equals(AlgorithmID.cast5_CBC)) {
			// get the parameters as SEQUENCE
			SEQUENCE seq = (SEQUENCE) contentEA.getParameter();
			// the iv is the first component
			OCTET_STRING oct = (OCTET_STRING) seq.getComponentAt(0);
			params = new IvParameterSpec((byte[]) oct.getValue());
		} else {
			throw new Exception("Algorithm " + contentEA + " not supportted for this test!");
		}

		// now setup the cipher with previously decrypted recipient key and params
		eci.setupCipher(secretKey, params);
		// get and read the data thereby actually performing the decryption
		InputStream data_is = eci.getInputStream();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Util.copyStream(data_is, baos, null);
		byte[] decrypted = baos.toByteArray();
		return decrypted;

	}

	/**
	 * Starts the test.
	 */
	public void start() {
		// the test message
		String m = "This is the test message.";
		System.out.println("Test message: \"" + m + "\"");
		System.out.println();
		byte[] message = m.getBytes();

		try {
			byte[] data;
			byte[] received_message = null;

			// the stream implementation
			//
			// test PKCS#7 EnvelopedDataStream
			//

			// ARCFOUR
			System.out.println("\nEnvelopedDataStream demo for algorithm ARCFOUR [create]:\n");
			data = createEnvelopedDataStream(message, AlgorithmID.arcfour, 128);
			// transmit data
			System.out.println("\nEnvelopedDataStream demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedDataStream(data, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

			// RC2
			System.out.println("\nEnvelopedDataStream demo for algorithm RC2 [create]:\n");
			data = createEnvelopedDataStream(message, AlgorithmID.rc2_CBC, 128);
			// transmit data
			System.out.println("\nEnvelopedDataStream demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedDataStream(data, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

			// CAST5_CBC
			System.out
			    .println("\nEnvelopedDataStream demo for algorithm CAST5_CBC [create]:\n");
			data = createEnvelopedDataStream(message, AlgorithmID.cast5_CBC, 128);
			// transmit data
			System.out.println("\nEnvelopedDataStream demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedDataStream(data, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the PKCS#7 content type implementation tests.
	 * 
	 * @exception IOException
	 *              if an I/O error occurs when reading required keys and
	 *              certificates from files
	 */
	public static void main(String argv[])
	    throws Exception
	{

		DemoUtil.initDemos();

		(new TestEncryptedContentInfo()).start();
		System.in.read();
	}
}
