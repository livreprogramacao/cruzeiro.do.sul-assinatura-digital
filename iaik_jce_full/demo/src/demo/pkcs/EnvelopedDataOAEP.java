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

package demo.pkcs;

import iaik.asn1.OCTET_STRING;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.pkcs.pkcs7.ContentInfo;
import iaik.pkcs.pkcs7.ContentInfoStream;
import iaik.pkcs.pkcs7.EncryptedContentInfo;
import iaik.pkcs.pkcs7.EncryptedContentInfoStream;
import iaik.pkcs.pkcs7.EnvelopedData;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidParameterSpecException;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class uses an {@link iaik.pkcs.pkcs7.RSACipherProvider
 * RSACipherProvider} for en/decrypting the content encryption key of an
 * EnvelopedData with RSA in OAEP mode. 
 * <p>
 * This class contains demos for both, stream and non-stream based implementation
 * of the EnvelopedData type. The stream based demo explicitly creates and sets the OAEP
 * parameters for the key encryption algorithm id of the RecipientInfo. The
 * non-stream based version specifies the OAEP parameters by JCA cipher transformation
 * string, lets the Cipher generate the parameters and gets and sets them for
 * the key encryption algorithm id (see {@link RSACipherProviderOAEP RSACipherProviderOAEP}. 
 * <p>
 * 
 * All keys and certificates are read from a keystore created by the
 * SetupKeyStore program.
 * 
 * @version File Revision <!-- $$Revision: --> 10 <!-- $ -->
 */
public class EnvelopedDataOAEP implements IAIKDemo {

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
	// algorithmID for RSA OAEP
	AlgorithmID rsaEncryptionOAEP;

	/**
	 * Setup the demo certificate chains.
	 * 
	 * Keys and certificate are retrieved from the demo KeyStore.
	 * 
	 * @exception IOException
	 *              if a file read error occurs
	 */
	public EnvelopedDataOAEP() {
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
		rsaEncryptionOAEP = (AlgorithmID)AlgorithmID.rsaesOAEP.clone();
	}

	/**
	 * Creates a PKCS#7 <code>EnvelopedDataStream</code> message.
	 * 
	 * @param message
	 *          the message to be enveloped, as byte representation
	 * @return the DER encoded ContentInfo containing the EnvelopedData object
	 *         just created,
	 * 
	 * @exception PKCSException
	 *              if the <code>EnvelopedData</code> object cannot be created
	 */
	public byte[] createEnvelopedDataStream(byte[] message)
	    throws PKCSException, IOException
	{

		EnvelopedDataStream enveloped_data;

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);
		// create a new EnvelopedData object encrypted with TripleDES CBC
		try {
			enveloped_data = new EnvelopedDataStream(is, AlgorithmID.aes128_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for AES128-CBC.");
		}

		try {
			// create the recipient infos
			RecipientInfo[] recipients = new RecipientInfo[2];
			// user1 is the first receiver
			AlgorithmID oaepID = (AlgorithmID) rsaEncryptionOAEP.clone();
			// include OAEP parameters in AlgorithmID
			setOAEPParameters(oaepID);
			recipients[0] = new RecipientInfo(user1, oaepID);
			recipients[0].setRSACipherProvider(new RSACipherProviderOAEP(recipients[0]));
			// user2 is the second receiver
			oaepID = (AlgorithmID) rsaEncryptionOAEP.clone();
			// include OAEP parameters in AlgorithmID
			setOAEPParameters(oaepID);
			recipients[1] = new RecipientInfo(user2, oaepID);
			recipients[1].setRSACipherProvider(new RSACipherProviderOAEP(recipients[1]));

			// specify the recipients of the encrypted message
			enveloped_data.setRecipientInfos(recipients);
		} catch (NoSuchAlgorithmException ex) {
			// ignore
		}

		// return the EnvelopedData as DER encoded byte array with block size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		enveloped_data.setBlockSize(2048);
		ContentInfoStream cis = new ContentInfoStream(enveloped_data);
		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Decrypts the encrypted content of the given EnvelopedData object for the
	 * specified recipient and returns the decrypted (= original) message.
	 * 
	 * @param encoding
	 *          the DER encoded ContentInfo containing an EnvelopedData object
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
	    throws PKCSException, IOException
	{

		// create the EnvelopedData object from a DER encoded byte array
		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(encoding);
		ContentInfoStream cis = new ContentInfoStream(is);
		EnvelopedDataStream enveloped_data = (EnvelopedDataStream) cis.getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfoStream eci = (EncryptedContentInfoStream) enveloped_data
		    .getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		System.out
		    .println("\nThis message can be decrypted by the owners of the following certificates:");
		RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
		for (int i = 0; i < recipients.length; i++) {
			System.out.println("Recipient: " + (i + 1));
			System.out.print(recipients[i].getIssuerAndSerialNumber());
			// set the RSA cipher provider for using RSA with OAEP padding
			recipients[i].setRSACipherProvider(new RSACipherProviderOAEP(recipients[i]));
		}

		// decrypt the message
		try {
			enveloped_data.setupCipher(privateKey, recipientInfoIndex);
			InputStream decrypted = enveloped_data.getInputStream();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			Util.copyStream(decrypted, os, null);
			return os.toByteArray();

		} catch (InvalidKeyException ex) {
			System.out.println("Private key error: " + ex.getMessage());
			return null;
		} catch (NoSuchAlgorithmException ex) {
			System.out.println("Content encryption algorithm not implemented: "
			    + ex.getMessage());
			return null;
		}
	}

	/**
	 * Creates a PKCS#7 <code>EnvelopedData</code> message.
	 * 
	 * @param message
	 *          the message to be enveloped, as byte representation
	 * @return a DER encoded ContentInfo holding the EnvelopedData object just
	 *         created
	 * @exception PKCSException
	 *              if the <code>EnvelopedData</code> object cannot be created
	 */
	public byte[] createEnvelopedData(byte[] message)
	    throws PKCSException
	{

		EnvelopedData enveloped_data;

		// create a new EnvelopedData object encrypted with TripleDES CBC
		try {
			enveloped_data = new EnvelopedData(message, AlgorithmID.aes128_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for AES128-CBC.");
		}

		try {
			// create the recipient infos
			RecipientInfo[] recipients = new RecipientInfo[2];
			// user1 is the first receiver
			AlgorithmID oaepID = (AlgorithmID) rsaEncryptionOAEP.clone();
			recipients[0] = new RecipientInfo(user1, oaepID);
			// set the RSA cipher provider for using RSA with OAEP padding (let Cipher calculate OAEP parameters)
			recipients[0].setRSACipherProvider(new RSACipherProviderOAEP("RSA/ECB/OAEPWithSHA256AndMGF1Padding", recipients[0]));
			// user2 is the second receiver
			oaepID = (AlgorithmID) rsaEncryptionOAEP.clone();
			recipients[1] = new RecipientInfo(user2, oaepID);
      // set the RSA cipher provider for using RSA with OAEP padding (let Cipher calculate OAEP parameters)
			recipients[1].setRSACipherProvider(new RSACipherProviderOAEP("RSA/ECB/OAEPWithSHA256AndMGF1Padding", recipients[1]));
			// specify the recipients of the encrypted message
			enveloped_data.setRecipientInfos(recipients);
		} catch (NoSuchAlgorithmException ex) {
			// ignore
		}
		ContentInfo ci = new ContentInfo(enveloped_data);
		// return the EnvelopedData as DER encoded byte array
		return ci.toByteArray();
	}

	/**
	 * Decrypts the encrypted content of the given <code>EnvelopedData</code>
	 * object for the specified recipient and returns the decrypted (= original)
	 * message.
	 * 
	 * @param encoding
	 *          the ContentInfo encoding holding an EnvelopedData
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
	public byte[] getEnvelopedData(byte[] encoding,
	                               PrivateKey privateKey,
	                               int recipientInfoIndex)
	    throws PKCSException, IOException
	{

		ContentInfo ci = new ContentInfo(new ByteArrayInputStream(encoding));
		EnvelopedData enveloped_data = (EnvelopedData) ci.getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfo eci = (EncryptedContentInfo) enveloped_data
		    .getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		System.out
		    .println("\nThis message can be decrypted by the owners of the following certificates:");
		RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
		for (int i = 0; i < recipients.length; i++) {
			System.out.println("Recipient: " + (i + 1));
			System.out.print(recipients[i].getIssuerAndSerialNumber());
			// set the RSA cipher provider for using RSA with OAEP padding
			recipients[i].setRSACipherProvider(new RSACipherProviderOAEP(recipients[i]));
		}

		// decrypt the message
		try {
			enveloped_data.setupCipher(privateKey, recipientInfoIndex);
			return enveloped_data.getContent();

		} catch (InvalidKeyException ex) {
			System.out.println("Private key error: " + ex.getMessage());
			return null;
		} catch (NoSuchAlgorithmException ex) {
			System.out.println("Content encryption algorithm not implemented: "
			    + ex.getMessage());
			return null;
		}
	}

	/**
	 * Tests the PKCS#7 content type implementations <code>EnvelopedData</code>,
	 * <code>SignedData</code>, and <code>SignedAndEnvelopedData</code>. An
	 * additional <i>SignedAndEncryptedData</i> test sequentially combines signed
	 * and enveloped data, which should be prefered to the
	 * <code>SignedAndEnvelopedData</code> content type.
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
			System.out.println("Stream implementation demos");
			System.out.println("===========================");

			// the stream implementation
			//
			// test PKCS#7 EnvelopedDataStream
			//
			System.out.println("\nEnvelopedDataStream demo [create]:\n");
			data = createEnvelopedDataStream(message);
			// transmit data
			System.out.println("\nEnvelopedDataStream demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedDataStream(data, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

			// the non-stream implementation
			System.out.println("\nNon-stream implementation demos");
			System.out.println("===============================");

			//
			// test PKCS#7 EnvelopedData
			//
			System.out.println("\nEnvelopedData demo [create]:\n");
			data = createEnvelopedData(message);
			// transmit data
			System.out.println("\nEnvelopedData demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedData(data, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

			System.out.println("Ready!");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Sets OAEP algorithm parameters for the given AlgorithmID.
	 * 
	 * @param oaepID
	 *          the OAEP algorithm id for which to set OAEP parameters
	 * 
	 * @exception PKCSException
	 *              if an error occurs when setting the parameters
	 */
	private static void setOAEPParameters(AlgorithmID oaepID)
	    throws PKCSException
	{
		
		  AlgorithmID hashID = (AlgorithmID)AlgorithmID.sha256.clone();
	    AlgorithmID mgfID = (AlgorithmID)AlgorithmID.mgf1.clone();
	    AlgorithmID pSourceID = (AlgorithmID)AlgorithmID.pSpecified.clone();
	    // empty label
	    byte[] label = { };
    
      mgfID.setParameter(hashID.toASN1Object());
      pSourceID.setParameter(new OCTET_STRING(label));
      // hash and mgf engines
      MessageDigest hashEngine = null;
      MaskGenerationAlgorithm mgfEngine = null;
      try {
        hashEngine = hashID.getMessageDigestInstance();
        mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
        MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
        mgf1ParamSpec.setHashEngine(hashEngine);
        mgfEngine.setParameters(mgf1ParamSpec);
      } catch (NoSuchAlgorithmException ex) {
        throw new PKCSException(ex.toString());
      } catch (InvalidAlgorithmParameterException ex) {
        throw new PKCSException("Cannot init MGF engine: " + ex.toString());
      }
      // create the RSAOaepParameterSpec
      RSAOaepParameterSpec oaepParamSpec = new RSAOaepParameterSpec(hashID,
          mgfID, pSourceID);
      // set engines
      oaepParamSpec.setHashEngine(hashEngine);
      oaepParamSpec.setMGFEngine(mgfEngine);
  
      AlgorithmParameters oaepParams = null;
      try {
        oaepParams = AlgorithmParameters.getInstance(
            "RSAES-OAEP", "IAIK");
        oaepParams.init(oaepParamSpec);
      } catch (NoSuchAlgorithmException ex) {
        throw new PKCSException(
            "RSA-OAEP implementation of provider IAIK not available!");
      } catch (NoSuchProviderException ex) {
        throw new PKCSException(
            "RSA-OAEP implementation of provider IAIK not available!");
      } catch (InvalidParameterSpecException ex) {
        throw new PKCSException("Cannot init OAEP params: " + ex.getMessage());
      }
      
      oaepID.setAlgorithmParameters(oaepParams);
   
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

		(new EnvelopedDataOAEP()).start();
		System.in.read();
	}
}
