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
import iaik.asn1.CodingException;
import iaik.asn1.DerCoder;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs7.ContentInfo;
import iaik.pkcs.pkcs7.ContentInfoStream;
import iaik.pkcs.pkcs7.Data;
import iaik.pkcs.pkcs7.DataStream;
import iaik.pkcs.pkcs7.DigestedData;
import iaik.pkcs.pkcs7.DigestedDataStream;
import iaik.pkcs.pkcs7.EncryptedContentInfo;
import iaik.pkcs.pkcs7.EncryptedContentInfoStream;
import iaik.pkcs.pkcs7.EncryptedData;
import iaik.pkcs.pkcs7.EncryptedDataStream;
import iaik.pkcs.pkcs7.EnvelopedData;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.pkcs.pkcs7.SignedAndEnvelopedData;
import iaik.pkcs.pkcs7.SignedAndEnvelopedDataStream;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class shows some PKCS#7 examples and uses the stream interface for
 * processing large amounts of data.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupKeyStore program.
 * <p>
 * This class tests the following PKCS#7 content type implementations:
 * <p>
 * <ul>
 * <li>EnvelopedData
 * <li>SignedData including the message
 * <li>SignedData without message
 * <li>SignedAndEnvelopedData
 * </ul>
 * <p>
 * Additionally, a <i>SignedAndEncryptedData</i> test is performed, which is a
 * sequential combination of signed and enveloped data and should be prefered to
 * the <code>SignedAndEnvelopedData</code> content type.
 * <p>
 * All sub-tests use the same proceeding: A test message is properly processed
 * to give the requested content type object, which subsequently is DER encoded
 * to be "sent" to some recipient, who parses it for the inherent structures.
 * 
 * @version File Revision <!-- $$Revision: --> 26 <!-- $ -->
 */
public class PKCS7Demo implements IAIKDemo {

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
	 */
	public PKCS7Demo() {
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

	/**
	 * Creates a PKCS#7 <code>Data</code> object.
	 * <p>
	 * 
	 * @param message
	 *          the message to be sent, as byte representation
	 * @return the DER encoding ContentInfo containing the <code>Data</code>
	 *         object just created
	 * @exception PKCSException
	 *              if the <code>Data</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createDataStream(byte[] message)
	    throws PKCSException, IOException
	{

		System.out.println("Create a new Data message:");

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);

		// create a new Data object which includes the data
		DataStream data = new DataStream(is, 2048);

		ContentInfoStream cis = new ContentInfoStream(data);
		// return the ContentInfo as BER encoded byte array where Data is encoded
		// with block size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Parses a PKCS#7 <code>Data</code> object.
	 * 
	 * @param data
	 *          the DER encoded ContentInfo holding the <code>Data</code>
	 * 
	 * @return the inherent message as byte array, or <code>null</code> if there
	 *         is no message included into the supplied <code>data</code> object
	 * @exception IOException
	 *              if an IOException occurs
	 * @exception PKCSException
	 *              if an parsing exception occurs
	 */
	public byte[] getDataStream(byte[] data)
	    throws PKCSException, IOException
	{

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(data);
		ContentInfoStream cis = new ContentInfoStream(is);
		System.out.println("This ContentInfo holds content of type "
		    + cis.getContentType().getName());
		// create the Data object
		DataStream dataStream = (DataStream) cis.getContent();

		// get an InputStream for reading the signed content
		InputStream content = dataStream.getInputStream();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		Util.copyStream(content, os, null);

		return os.toByteArray();
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
	 * @return the DER encoded ContentInfo containing the EnvelopedData object
	 *         just created
	 * 
	 * @exception PKCSException
	 *              if the <code>EnvelopedData</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createEnvelopedDataStream(byte[] message)
	    throws PKCSException, IOException
	{

		EnvelopedDataStream enveloped_data;

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);
		// create a new EnvelopedData object encrypted with TripleDES CBC
		try {
			enveloped_data = new EnvelopedDataStream(is, AlgorithmID.des_EDE3_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for Triple-DES-CBC.");
		}

		try {
			// create the recipient infos
			RecipientInfo[] recipients = new RecipientInfo[2];
			// user1 is the first receiver
			recipients[0] = new RecipientInfo(user1, AlgorithmID.rsaEncryption);
			// user2 is the second receiver
			recipients[1] = new RecipientInfo(user2, AlgorithmID.rsaEncryption);

			// specify the recipients of the encrypted message
			enveloped_data.setRecipientInfos(recipients);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException(ex.toString());
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
	 * @exception IOException
	 *              if an I/O error occurs
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
		}

		// decrypt the message
		try {
			enveloped_data.setupCipher(privateKey, recipientInfoIndex);
			InputStream decrypted = enveloped_data.getInputStream();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			Util.copyStream(decrypted, os, null);

			return os.toByteArray();

		} catch (InvalidKeyException ex) {
			throw new PKCSException("Private key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}
	}

	/**
	 * Creates a PKCS#7 <code>SignedData</code> object.
	 * <p>
	 * The signed-data content type consists of content of any type and encrypted
	 * message digests of the content for zero or more signers. The encrypted
	 * digest for a signer is a "digital signature" on the content for that
	 * signer. Any type of content can be signed by any number of signers in
	 * parallel. Furthermore, the syntax has a degenerate case in which there are
	 * no signers on the content. The degenerate case provides a means for
	 * disseminating certificates and certificate-revocation lists.
	 * 
	 * @param message
	 *          the message to be signed, as byte representation
	 * @return the DER encoding of the ContentInfo holding the
	 *         <code>SignedData</code> object just created
	 * @exception PKCSException
	 *              if the <code>SignedData</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createSignedDataStream(byte[] message, int mode)
	    throws PKCSException, IOException
	{

		System.out.println("Create a new message signed by user 1:");

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);
		// create a new SignedData object which includes the data
		SignedDataStream signed_data = new SignedDataStream(is, mode);
		// SignedData shall include the certificate chain for verifying
		signed_data.setCertificates(certificates);

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
		try {
			signed_data.addSignerInfo(signer_info);

			// another SignerInfo without authenticated attributes and RIPEMD160 as
			// hash algorithm
			signer_info = new SignerInfo(new IssuerAndSerialNumber(user2),
			    AlgorithmID.ripeMd160, user2_pk);
			// the message digest itself is protected
			signed_data.addSignerInfo(signer_info);

		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for signature algorithm: "
			    + ex.getMessage());
		}
		// ensure block encoding
		signed_data.setBlockSize(2048);

		// write the data through SignedData to any out-of-band place
		if (mode == SignedDataStream.EXPLICIT) {
			InputStream data_is = signed_data.getInputStream();
			byte[] buf = new byte[1024];
			while (data_is.read(buf) > 0) {
				// skip data
			}
		}

		// create the ContentInfo
		ContentInfoStream cis = new ContentInfoStream(signed_data);
		// return the SignedData as BER encoded byte array with block size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Parses a PKCS#7 <code>SignedData</code> object and verifies the signatures
	 * for all participated signers.
	 * 
	 * @param signedData
	 *          the ContentInfo with inherent SignedData, as DER encoded byte
	 *          array
	 * @param message
	 *          the message which was transmitted out-of-band (explicit signed)
	 * 
	 * @return the inherent message as byte array, or <code>null</code> if there
	 *         is no message included into the supplied <code>SignedData</code>
	 *         object
	 * @exception PKCSException
	 *              if any signature does not verify
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getSignedDataStream(byte[] signedData, byte[] message)
	    throws PKCSException, IOException
	{

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(signedData);
		// create the ContentInfo object
		ContentInfoStream cis = new ContentInfoStream(is);
		System.out.println("This ContentInfo holds content of type "
		    + cis.getContentType().getName());
		SignedDataStream signed_data = null;

		if (message == null) {
			// implicitly signed; get the content
			signed_data = (SignedDataStream) cis.getContent();
		} else {
			// explicitly signed; set the data stream for digesting the message
			AlgorithmID[] algIDs = { AlgorithmID.sha1, AlgorithmID.ripeMd160 };
			signed_data = new SignedDataStream(new ByteArrayInputStream(message), algIDs);

		}

		// get an InputStream for reading the signed content
		InputStream data = signed_data.getInputStream();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		Util.copyStream(data, os, null);

		if (message != null) {
			// if explicitly signed read now the DER encoded object
			// an explicit S/MIME signed message also consists of message|signature
			signed_data.decode(cis.getContentInputStream());
		}

		System.out.println("SignedData contains the following signer information:");
		SignerInfo[] signer_infos = signed_data.getSignerInfos();

		for (int i = 0; i < signer_infos.length; i++) {
			try {
				// verify the signed data using the SignerInfo at index i
				X509Certificate signer_cert = signed_data.verify(i);
				// if the signature is OK the certificate of the signer is returned
				System.out.println("Signature OK from signer: " + signer_cert.getSubjectDN());
				Attribute signingTime = signer_infos[i]
				    .getAuthenticatedAttribute(ObjectID.signingTime);
				if (signingTime != null) {
					ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
					System.out.println("This message has been signed at " + cot.getDate());
				}
				Attribute contentType = signer_infos[i]
				    .getAuthenticatedAttribute(ObjectID.contentType);
				if (contentType != null) {
					System.out.println("The content has PKCS#7 content type "
					    + contentType.getValue()[0]);
				}

			} catch (SignatureException ex) {
				// if the signature is not OK a SignatureException is thrown
				System.err.println("Signature ERROR from signer: "
				    + signed_data.getCertificate(signer_infos[i].getIssuerAndSerialNumber())
				        .getSubjectDN());
				throw new PKCSException(ex.toString());
			} catch (CodingException ex) {
				System.err.println("Attribute decoding error: " + ex.getMessage());
				throw new PKCSException(ex.toString());
			}
		}
		// now check alternative signature verification
		System.out
		    .println("Now check the signature assuming that no certs have been included:");
		try {
			SignerInfo signer_info = signed_data.verify(user1);
			// if the signature is OK the certificate of the signer is returned
			System.out.println("Signature OK from signer: "
			    + signed_data.getCertificate(signer_info.getIssuerAndSerialNumber())
			        .getSubjectDN());

		} catch (SignatureException ex) {
			// if the signature is not OK a SignatureException is thrown
			System.err.println("Signature ERROR from signer: " + user1.getSubjectDN());
			throw new PKCSException(ex.toString());
		}

		try {
			SignerInfo signer_info = signed_data.verify(user2);
			// if the signature is OK the certificate of the signer is returned
			System.out.println("Signature OK from signer: "
			    + signed_data.getCertificate(signer_info.getIssuerAndSerialNumber())
			        .getSubjectDN());

		} catch (SignatureException ex) {
			// if the signature is not OK a SignatureException is thrown
			System.err.println("Signature ERROR from signer: " + user2.getSubjectDN());
			throw new PKCSException(ex.toString());
		}

		return os.toByteArray();
	}

	/**
	 * Creates a PKCS#7 <code>SignedAndEnvelopedData</code> object for one
	 * recipient signed by one signer.
	 * <p>
	 * The signed-and-enveloped-data content type consists of encrypted content of
	 * any type, encrypted content-encryption keys for one or more recipients, and
	 * doubly encrypted message digests for one or more signers. The "double
	 * encryption" consists of an encryption with a signer's private key followed
	 * by an encryption with the content-encryption key.
	 * <p>
	 * The combination of encrypted content and encrypted content-encryption key
	 * for a recipient is a "digital envelope" for that recipient. The recovered
	 * singly encrypted message digest for a signer is a "digital signature" on
	 * the recovered content for that signer. Any type of content can be enveloped
	 * for any number of recipients and signed by any number of signers in
	 * parallel.
	 * 
	 * @param message
	 *          the message to be signed and enveloped, as byte representation
	 * @return the DER encoded ContentInfo containing the SignedAndEnvelopedData
	 *         object just created
	 * @exception PKCSException
	 *              if the <code>SignedAndEnvelopedData</code> object cannot be
	 *              created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createSignedAndEnvelopedDataStream(byte[] message)
	    throws PKCSException, IOException
	{

		System.out.println("Create a new message signed by user1 encrypted for user2:");

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);
		// create a new SignedAndEnvelopedData object which includes the data
		SignedAndEnvelopedDataStream signed_and_enveloped_data = null;
		try {
			signed_and_enveloped_data = new SignedAndEnvelopedDataStream(is,
			    AlgorithmID.des_EDE3_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for Triple-DES-CBC.");
		}

		// SignedData shall include the certificate chain for verifying
		signed_and_enveloped_data.setCertificates(certificates);

		// cert at index 0 is the user certificate
		IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

		// create a new SignerInfo
		SignerInfo signer_info = new SignerInfo(issuer, AlgorithmID.sha, user1_pk);
		try {
			// finish the creation of SignerInfo by calling method addSigner
			signed_and_enveloped_data.addSignerInfo(signer_info);

			// create the recipient info
			RecipientInfo recipient = new RecipientInfo(user2, AlgorithmID.rsaEncryption);
			// specify the recipients of the encrypted message
			signed_and_enveloped_data.addRecipientInfo(recipient);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation foralgorithm: " + ex.getMessage());
		}
		signed_and_enveloped_data.setBlockSize(2048);

		// return the SignedAndEnvelopedData as DER encoded byte array with block
		// size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ContentInfoStream cis = new ContentInfoStream(signed_and_enveloped_data);
		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Decrypts the encrypted content of the given <code>SignedAndEnvelopedData
	 * </code>object and returns the decrypted (= original) message.
	 * <p>
	 * The <code>SignedAndEnvelopedData</code> is given as DER encoded byte array
	 * holding an encrypted message for one recipient, signed by one signer. This
	 * method recovers and returns the original message for the recipient and
	 * verifies the signature of the signer.
	 * 
	 * @param encoding
	 *          the DER encoded ContentInfo containing a SignedAndEnvelopedData
	 *          object
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getSignedAndEnvelopedDataStream(byte[] encoding)
	    throws PKCSException, IOException
	{

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(encoding);
		ContentInfoStream cis = new ContentInfoStream(is);
		// create the SignedData object from a DER encoded InputStream
		SignedAndEnvelopedDataStream signed_and_enveloped_data = (SignedAndEnvelopedDataStream) cis
		    .getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfoStream eci = signed_and_enveloped_data.getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		System.out.println("\nThis message can be decrypted by the following recipients:");
		RecipientInfo[] recipients = signed_and_enveloped_data.getRecipientInfos();
		for (int i = 0; i < recipients.length; i++) {
			System.out.println("Recipient: " + (i + 1));
			System.out.print(recipients[i].getIssuerAndSerialNumber());
		}

		// user2 can decrypt the data
		// ATTENTION: this method also decrypts the encrypted message digest
		// you have first to call decrypt if you want to verify the signature
		ByteArrayOutputStream os;
		try {
			signed_and_enveloped_data.setupCipher(user2_pk, 0);
			InputStream decrypted = signed_and_enveloped_data.getInputStream();
			os = new ByteArrayOutputStream();
			Util.copyStream(decrypted, os, null);
		} catch (InvalidKeyException ex) {
			throw new PKCSException("Private key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}

		System.out
		    .println("\nSignedAndEnvelopedData contains the following signer information:");
		SignerInfo[] signer_infos = signed_and_enveloped_data.getSignerInfos();

		for (int i = 0; i < signer_infos.length; i++) {
			try {
				// verify the signed data using the SignerInfo at index i
				X509Certificate signer_cert = signed_and_enveloped_data.verify(i);
				// if the signature is OK the certificate of the signer is returned
				System.out.println("Signature OK from signer: " + signer_cert.getSubjectDN());
			} catch (SignatureException ex) {
				// if the signature is not OK a SignatureException is thrown
				System.err.println("Signature ERROR from signer: "
				    + signed_and_enveloped_data.getCertificate(
				        signer_infos[i].getIssuerAndSerialNumber()).getSubjectDN());
				throw new PKCSException(ex.toString());
			}
		}

		return os.toByteArray();
	}

	/**
	 * Creates a <i>SignedAndEncrypted</i> (i.e. sequential combination of <code>
	 * SignedData</code> and <code>EnvelopedData</code>) object as suggested in
	 * the <a href = http://www.rsasecurity.com/rsalabs/pkcs/pkcs-7/> PKCS#7</a>
	 * specification.
	 * <p>
	 * <b>PKCS#7 specification:</b>
	 * <p>
	 * <i>Note. The signed-and-enveloped-data content type provides cryptographic
	 * enhancements similar to those resulting from the sequential combination of
	 * signed-data and enveloped-data content types. However, since the
	 * signed-and-enveloped-data content type does not have authenticated or
	 * unauthenticated attributes, nor does it provide enveloping of signer
	 * information other than the signature, the sequential combination of
	 * signed-data and enveloped-data content types is generally preferable to the
	 * SignedAndEnvelopedData content type, except when compatibility with the
	 * ENCRYPTED process type in Privacy-Enhanced Mail is intended. </i>
	 * 
	 * @param message
	 *          the message to be signed and encrypted, as byte representation
	 * @return the DER encoded ContentInfo holding the the signed and encrypted
	 *         message object just created
	 * @exception PKCSException
	 *              if the the <code>SignedData</code> or
	 *              <code>EnvelopedData</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createSignedAndEncryptedDataStream(byte[] message)
	    throws PKCSException, IOException
	{

		System.out.println("Create a new message signed by user1 encrypted for user2:");

		byte[] signed = createSignedDataStream(message, SignedDataStream.IMPLICIT);
		return createEnvelopedDataStream(signed);
	}

	/**
	 * Recovers the original message and verifies the signature.
	 * 
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getSignedAndEncryptedDataStream(byte[] in)
	    throws PKCSException, IOException
	{

		// user2 means index 2 (hardcoded for this demo)
		byte[] signed = getEnvelopedDataStream(in, user2_pk, 1);
		return getSignedDataStream(signed, null);
	}

	/**
	 * Creates a PKCS#7 <code>DigestedData</code> object.
	 * <p>
	 * 
	 * @param message
	 *          the message to be digested, as byte representation
	 * @return the DER encoded ContentInfo containing the DigestedData object just
	 *         created
	 * @exception PKCSException
	 *              if the <code>DigestedData</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createDigestedDataStream(byte[] message, int mode)
	    throws PKCSException, IOException
	{

		System.out.println("Create a new message to be digested:");

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);

		// create a new DigestedData object which includes the data
		DigestedDataStream digested_data = null;

		digested_data = new DigestedDataStream(is, AlgorithmID.ripeMd160, mode);
		digested_data.setBlockSize(2048);

		// write the data through DigestedData to any out-of-band place
		if (mode == DigestedDataStream.EXPLICIT) {
			InputStream data_is = digested_data.getInputStream();
			byte[] buf = new byte[1024];
			while (data_is.read(buf) > 0) {
				// skip data
			}
		}

		// return the DigestedData as DER encoded byte array with block size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ContentInfoStream cis = new ContentInfoStream(digested_data);
		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Parses a PKCS#7 <code>DigestedData</code> object and verifies the hash.
	 * 
	 * @param digestedData
	 *          the DER encoded ContentInfo holding a DigestedData object
	 * @param message
	 *          the message which was transmitted out-of-band
	 * 
	 * @return the inherent message as byte array, or <code>null</code> if there
	 *         is no message included into the supplied <code>DigestedData</code>
	 *         object
	 * @exception PKCSException
	 *              if any signature does not verify
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getDigestedDataStream(byte[] digestedData, byte[] message)
	    throws PKCSException, IOException
	{

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(digestedData);
		// create the DigestedData object
		DigestedDataStream digested_data = null;
		// create the ContentInfo
		ContentInfoStream cis = new ContentInfoStream(is);
		if (message == null) {
			// implicitly; simply get the content from the ContentInfo
			digested_data = (DigestedDataStream) cis.getContent();
		} else {
			digested_data = new DigestedDataStream(new ByteArrayInputStream(message),
			    AlgorithmID.ripeMd160);

		}

		// get an InputStream for reading the signed content
		InputStream data = digested_data.getInputStream();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		Util.copyStream(data, os, null);

		if (message != null) {
			// in explicit mode now do the decoding
			digested_data.decode(cis.getContentInputStream());
		}

		if (digested_data.verify()) {
			System.out.println("Hash ok!");
		} else {
			System.out.println("Hash verification failed!");
		}

		return os.toByteArray();
	}

	/**
	 * Creates a PKCS#7 <code>EncryptedDataStream</code> message.
	 * <p>
	 * The supplied content is PBE-encrypted using the specified password.
	 * 
	 * @param message
	 *          the message to be encrypted, as byte representation
	 * @param pbeAlgorithm
	 *          the PBE algorithm to be used
	 * @param password
	 *          the password
	 * @return the DER encoding of the ContentInfo holding the
	 *         <code>EncryptedData</code> object just created
	 * @exception PKCSException
	 *              if the <code>EncryptedData</code> object cannot be created
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] createEncryptedDataStream(byte[] message,
	                                        AlgorithmID pbeAlgorithm,
	                                        char[] password)
	    throws PKCSException, IOException
	{

		EncryptedDataStream encrypted_data;

		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(message);
		// create a new EnvelopedData object encrypted with TripleDES CBC
		try {
			encrypted_data = new EncryptedDataStream(is, 2048);
			encrypted_data.setupCipher(pbeAlgorithm, password);
		} catch (InvalidKeyException ex) {
			throw new PKCSException("Key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}

		// return the EnvelopedDate as DER encoded byte array with block size 2048
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ContentInfoStream cis = new ContentInfoStream(encrypted_data);
		cis.writeTo(os);
		return os.toByteArray();
	}

	/**
	 * Decrypts the PBE-encrypted content of the given <code>EncryptedData</code>
	 * object using the specified password and returns the decrypted (= original)
	 * message.
	 * 
	 * @param encoding
	 *          the DER encoded ContentInfo holding an <code>EncryptedData</code>
	 *          object
	 * @param password
	 *          the password to decrypt the message
	 * 
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getEncryptedDataStream(byte[] encoding, char[] password)
	    throws PKCSException, IOException
	{

		// create the EncryptedData object from a DER encoded byte array
		// we are testing the stream interface
		ByteArrayInputStream is = new ByteArrayInputStream(encoding);
		// create the ContentInfo
		ContentInfoStream cis = new ContentInfoStream(is);

		EncryptedDataStream encrypted_data = (EncryptedDataStream) cis.getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfoStream eci = (EncryptedContentInfoStream) encrypted_data
		    .getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		// decrypt the message
		try {
			encrypted_data.setupCipher(password);
			InputStream decrypted = encrypted_data.getInputStream();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			Util.copyStream(decrypted, os, null);

			return os.toByteArray();

		} catch (InvalidKeyException ex) {
			throw new PKCSException("Key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.toString());
		} catch (InvalidAlgorithmParameterException ex) {
			throw new PKCSException("Invalid Parameters: " + ex.toString());
		} catch (InvalidParameterSpecException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}
	}

	/**
	 * Creates a PKCS#7 <code>Data</code> object.
	 * <p>
	 * 
	 * @param message
	 *          the message to be sent, as byte representation
	 * @return the ASN.1 representation of the ContentInfo holding the
	 *         <code>Data</code> object just created
	 * @exception PKCSException
	 *              if the <code>Data</code> object cannot be created
	 */
	public ASN1Object createData(byte[] message)
	    throws PKCSException
	{

		System.out.println("Create a new Data message:");

		// create a new DigestedData object which includes the data
		Data data = new Data(message);
		ContentInfo ci = new ContentInfo(data);
		// return the ASN.1 representation
		return ci.toASN1Object();
	}

	/**
	 * Parses a PKCS#7 <code>Data</code> object.
	 * 
	 * @param asn1Object
	 *          the ContentInfo holding with inherent <code>Data</code>, as ASN.1
	 *          object
	 * 
	 * @return the inherent message as byte array, or <code>null</code> if there
	 *         is no message included into the supplied <code>data</code> object
	 * @exception IOException
	 *              if an IOException occurs
	 * @exception PKCSException
	 *              if an parsing exception occurs
	 */
	public byte[] getData(ASN1Object asn1Object)
	    throws PKCSException, IOException
	{

		// create the ContentInfo
		ContentInfo ci = new ContentInfo(asn1Object);
		System.out.println("This ContentInfo holds content of type "
		    + ci.getContentType().getName());
		// create the Data object
		// Data data = (Data)ci.getContent();
		Data data = new Data(ci.getContentInputStream());

		// get and return the content
		return data.getData();
	}

	/**
	 * Creates a PKCS#7 <code>EnvelopedData</code> message.
	 * <p>
	 * The enveloped-data content type consists of encrypted content of any type
	 * and encrypted content-encryption keys for one or more recipients. The
	 * combination of encrypted content and encrypted content-encryption key for a
	 * recipient is a "digital envelope" for that recipient. Any type of content
	 * can be enveloped for any number of recipients in parallel.
	 * 
	 * @param message
	 *          the message to be enveloped, as byte representation
	 * @return a DER encoded ContentInfo holding the EnvelopedData object just
	 *         created
	 * @exception PKCSException
	 *              if the <code>EnvelopedData</code> object cannot be created
	 */
	public ASN1Object createEnvelopedData(byte[] message)
	    throws PKCSException
	{

		EnvelopedData enveloped_data;

		// create a new EnvelopedData object encrypted with TripleDES CBC
		try {
			enveloped_data = new EnvelopedData(message, AlgorithmID.des_EDE3_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for Triple-DES-CBC.");
		}

		try {
			// create the recipient infos
			RecipientInfo[] recipients = new RecipientInfo[2];
			// user1 is the first receiver
			recipients[0] = new RecipientInfo(user1, AlgorithmID.rsaEncryption);
			// user2 is the second receiver
			recipients[1] = new RecipientInfo(user2, AlgorithmID.rsaEncryption);

			// specify the recipients of the encrypted message
			enveloped_data.setRecipientInfos(recipients);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException(ex.toString());
		}
		ContentInfo ci = new ContentInfo(enveloped_data);
		// return the EnvelopedData as DER encoded byte array
		return ci.toASN1Object();
	}

	/**
	 * Decrypts the encrypted content of the given <code>EnvelopedData</code>
	 * object for the specified recipient and returns the decrypted (= original)
	 * message.
	 * 
	 * @param obj
	 *          the ContentInfo holding an EnvelopedData, as ASN.1 object
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
	public byte[] getEnvelopedData(ASN1Object obj,
	                               PrivateKey privateKey,
	                               int recipientInfoIndex)
	    throws PKCSException
	{

		ContentInfo ci = new ContentInfo(obj);
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
		}

		// decrypt the message
		try {
			enveloped_data.setupCipher(privateKey, recipientInfoIndex);
			/*
			 * InputStream decrypted = enveloped_data.getInputStream();
			 * ByteArrayOutputStream os = new ByteArrayOutputStream(); StreamCopier sc
			 * = new StreamCopier(decrypted, os); sc.copyStream(); return
			 * os.toByteArray();
			 */
			return enveloped_data.getContent();

		} catch (InvalidKeyException ex) {
			throw new PKCSException("Private key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}
	}

	/**
	 * Creates a PKCS#7 <code>SignedData</code> object.
	 * <p>
	 * The signed-data content type consists of content of any type and encrypted
	 * message digests of the content for zero or more signers. The encrypted
	 * digest for a signer is a "digital signature" on the content for that
	 * signer. Any type of content can be signed by any number of signers in
	 * parallel. Furthermore, the syntax has a degenerate case in which there are
	 * no signers on the content. The degenerate case provides a means for
	 * disseminating certificates and certificate-revocation lists.
	 * 
	 * @param message
	 *          the message to be signed, as byte representation
	 * @return the DER encoding of the ContentInfo holding the
	 *         <code>SignedData</code> object just created
	 * @exception PKCSException
	 *              if the <code>SignedData</code> object cannot be created
	 */
	public ASN1Object createSignedData(byte[] message, int mode)
	    throws PKCSException
	{

		System.out.println("Create a new message signed by user 1:");

		// create a new SignedData object which includes the data
		SignedData signed_data = new SignedData(message, mode);
		// SignedData shall include the certificate chain for verifying
		signed_data.setCertificates(certificates);

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
		try {
			signed_data.addSignerInfo(signer_info);

			// another SignerInfo without authenticated attributes and RIPEMD160 as
			// hash algorithm
			signer_info = new SignerInfo(new IssuerAndSerialNumber(user2),
			    AlgorithmID.ripeMd160, user2_pk);
			// the message digest itself is protected
			signed_data.addSignerInfo(signer_info);

		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for signature algorithm: "
			    + ex.getMessage());
		}

		ContentInfo ci = new ContentInfo(signed_data);
		return ci.toASN1Object();
	}

	/**
	 * Parses a PKCS#7 <code>SignedData</code> object and verifies the signatures
	 * for all participated signers.
	 * 
	 * @param obj
	 *          the ContentInfo with inherent <code>SignedData</code> object, in
	 *          ASN.1 representation
	 * @param message
	 *          the the message which was transmitted out-of-band (explicit
	 *          signed)
	 * 
	 * @return the inherent message as byte array, or <code>null</code> if there
	 *         is no message included into the supplied <code>SignedData</code>
	 *         object
	 * @exception PKCSException
	 *              if any signature does not verify
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getSignedData(ASN1Object obj, byte[] message)
	    throws PKCSException, IOException
	{

		// create a content info from the ASN.1 object
		ContentInfo ci = new ContentInfo(obj);
		System.out.println("This ContentInfo holds content of type "
		    + ci.getContentType().getName());

		SignedData signed_data = null;
		if (message == null) {
			// in implicit mode we simply can get the content:
			signed_data = (SignedData) ci.getContent();
		} else {
			// explicitly signed; set the data for digesting the message
			AlgorithmID[] algIDs = { AlgorithmID.sha1, AlgorithmID.ripeMd160 };
			try {
				signed_data = new SignedData(message, algIDs);
				// now explicit decode the DER encoded signedData obtained from the
				// contentInfo:
				signed_data.decode(ci.getContentInputStream());
			} catch (NoSuchAlgorithmException ex) {
				throw new PKCSException(ex.getMessage());
			}
		}

		System.out.println("SignedData contains the following signer information:");
		SignerInfo[] signer_infos = signed_data.getSignerInfos();

		for (int i = 0; i < signer_infos.length; i++) {
			try {
				// verify the signed data using the SignerInfo at index i
				X509Certificate signer_cert = signed_data.verify(i);
				// if the signature is OK the certificate of the signer is returned
				System.out.println("Signature OK from signer: " + signer_cert.getSubjectDN());
				Attribute signingTime = signer_infos[i]
				    .getAuthenticatedAttribute(ObjectID.signingTime);
				if (signingTime != null) {
					ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
					System.out.println("This message has been signed at " + cot.getDate());
				}
				Attribute contentType = signer_infos[i]
				    .getAuthenticatedAttribute(ObjectID.contentType);
				if (contentType != null) {
					System.out.println("The content has PKCS#7 content type "
					    + contentType.getValue()[0]);
				}
			} catch (SignatureException ex) {
				// if the signature is not OK a SignatureException is thrown
				System.err.println("Signature ERROR from signer: "
				    + signed_data.getCertificate(signer_infos[i].getIssuerAndSerialNumber())
				        .getSubjectDN());
				throw new PKCSException(ex.toString());
			} catch (CodingException ex) {
				System.err.println("Attribute decoding error: " + ex.getMessage());
				throw new PKCSException(ex.toString());
			}
		}

		// now check alternative signature verification
		System.out
		    .println("Now check the signature assuming that no certs have been included:");
		try {
			SignerInfo signer_info = signed_data.verify(user1);
			// if the signature is OK the certificate of the signer is returned
			System.out.println("Signature OK from signer: "
			    + signed_data.getCertificate(signer_info.getIssuerAndSerialNumber())
			        .getSubjectDN());

		} catch (SignatureException ex) {
			// if the signature is not OK a SignatureException is thrown
			System.err.println("Signature ERROR from signer: " + user1.getSubjectDN());
			throw new PKCSException(ex.toString());
		}

		try {
			SignerInfo signer_info = signed_data.verify(user2);
			// if the signature is OK the certificate of the signer is returned
			System.out.println("Signature OK from signer: "
			    + signed_data.getCertificate(signer_info.getIssuerAndSerialNumber())
			        .getSubjectDN());

		} catch (SignatureException ex) {
			// if the signature is not OK a SignatureException is thrown
			System.err.println("Signature ERROR from signer: " + user2.getSubjectDN());
			throw new PKCSException(ex.toString());
		}

		return signed_data.getContent();
	}

	/**
	 * Creates a PKCS#7 <code>SignedAndEnvelopedData</code> object for one
	 * recipient signed by one signer.
	 * <p>
	 * The signed-and-enveloped-data content type consists of encrypted content of
	 * any type, encrypted content-encryption keys for one or more recipients, and
	 * doubly encrypted message digests for one or more signers. The "double
	 * encryption" consists of an encryption with a signer's private key followed
	 * by an encryption with the content-encryption key.
	 * <p>
	 * The combination of encrypted content and encrypted content-encryption key
	 * for a recipient is a "digital envelope" for that recipient. The recovered
	 * singly encrypted message digest for a signer is a "digital signature" on
	 * the recovered content for that signer. Any type of content can be enveloped
	 * for any number of recipients and signed by any number of signers in
	 * parallel.
	 * 
	 * @param message
	 *          the message to be signed and enveloped, as byte representation
	 * @return the DER encoded ContentInfo holding the SignedAndEnvelopedData
	 *         object just created
	 * @exception PKCSException
	 *              if the <code>SignedAndEnvelopedData</code> object cannot be
	 *              created
	 */
	public ASN1Object createSignedAndEnvelopedData(byte[] message)
	    throws PKCSException
	{

		System.out.println("Create a new message signed by user1 encrypted for user2:");

		// create a new SignedAndEnvelopedData object which includes the data
		SignedAndEnvelopedData signed_and_enveloped_data = null;
		try {
			signed_and_enveloped_data = new SignedAndEnvelopedData(message,
			    AlgorithmID.des_EDE3_CBC);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation for Triple-DES-CBC.");
		}

		// SignedData shall include the certificate chain for verifying
		signed_and_enveloped_data.setCertificates(certificates);

		// cert at index 0 is the user certificate
		IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

		// create a new SignerInfo
		SignerInfo signer_info = new SignerInfo(issuer, AlgorithmID.sha, user1_pk);
		try {
			// finish the creation of SignerInfo by calling method addSigner
			signed_and_enveloped_data.addSignerInfo(signer_info);

			// create the recipient info
			RecipientInfo recipient = new RecipientInfo(user2, AlgorithmID.rsaEncryption);
			// specify the recipients of the encrypted message
			signed_and_enveloped_data.addRecipientInfo(recipient);
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("No implementation foralgorithm: " + ex.getMessage());
		}

		ContentInfo ci = new ContentInfo(signed_and_enveloped_data);
		return ci.toASN1Object();
	}

	/**
	 * Decrypts the encrypted content of the given <code>SignedAndEnvelopedData
	 * </code>object and returns the decrypted (= original) message.
	 * <p>
	 * The <code>SignedAndEnvelopedData</code> is given as DER encoded byte array
	 * hoding an encrypted message for one recipient, signed by one signer. This
	 * method recovers and returns the original message for the recipient and
	 * verifies the signature of the signer.
	 * 
	 * @param obj
	 *          the ContentInfo holding a SignedAndEnvelopedData object, in ASN.1
	 *          representation
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 */
	public byte[] getSignedAndEnvelopedData(ASN1Object obj)
	    throws PKCSException
	{

		ContentInfo ci = new ContentInfo(obj);
		// create the SignedData object from a DER encoded InputStream
		SignedAndEnvelopedData signed_and_enveloped_data = (SignedAndEnvelopedData) ci
		    .getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfo eci = signed_and_enveloped_data.getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		System.out.println("\nThis message can be decrypted by the following recipients:");
		RecipientInfo[] recipients = signed_and_enveloped_data.getRecipientInfos();
		for (int i = 0; i < recipients.length; i++) {
			System.out.println("Recipient: " + (i + 1));
			System.out.print(recipients[i].getIssuerAndSerialNumber());
		}

		// user2 can decrypt the data
		// ATTENTION: this method also decrypts the encrypted message digest
		// you have first to call decrypt if you want to verify the signature
		byte[] content = null;
		try {
			signed_and_enveloped_data.setupCipher(user2_pk, 0);
			content = signed_and_enveloped_data.getContent();
		} catch (InvalidKeyException ex) {
			throw new PKCSException("Private key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}

		System.out
		    .println("\nSignedAndEnvelopedData contains the following signer information:");
		SignerInfo[] signer_infos = signed_and_enveloped_data.getSignerInfos();

		for (int i = 0; i < signer_infos.length; i++) {
			try {
				// verify the signed data using the SignerInfo at index i
				X509Certificate signer_cert = signed_and_enveloped_data.verify(i);
				// if the signature is OK the certificate of the signer is returned
				System.out.println("Signature OK from signer: " + signer_cert.getSubjectDN());
			} catch (SignatureException ex) {
				// if the signature is not OK a SignatureException is thrown
				System.err.println("Signature ERROR from signer: "
				    + signed_and_enveloped_data.getCertificate(
				        signer_infos[i].getIssuerAndSerialNumber()).getSubjectDN());
				throw new PKCSException(ex.toString());
			}
		}

		return content;
	}

	/**
	 * Creates a <i>SignedAndEncrypted</i> (i.e. sequential combination of <code>
	 * SignedData</code> and <code>EnvelopedData</code>) object as suggested in
	 * the <a href = http://www.rsasecurity.com/rsalabs/pkcs/pkcs-7/> PKCS#7</a>
	 * specification.
	 * <p>
	 * <b>PKCS#7 specification:</b>
	 * <p>
	 * <i>Note. The signed-and-enveloped-data content type provides cryptographic
	 * enhancements similar to those resulting from the sequential combination of
	 * signed-data and enveloped-data content types. However, since the
	 * signed-and-enveloped-data content type does not have authenticated or
	 * unauthenticated attributes, nor does it provide enveloping of signer
	 * information other than the signature, the sequential combination of
	 * signed-data and enveloped-data content types is generally preferable to the
	 * SignedAndEnvelopedData content type, except when compatibility with the
	 * ENCRYPTED process type in Privacy-Enhanced Mail is intended. </i>
	 * 
	 * @param message
	 *          the message to be signed and encrypted, as byte representation
	 * @return the DER encoded ContentInfo holding the signed and encrypted
	 *         message object just created
	 * @exception PKCSException
	 *              if the the <code>SignedData</code> or
	 *              <code>EnvelopedData</code> object cannot be created
	 */
	public ASN1Object createSignedAndEncryptedData(byte[] message)
	    throws PKCSException
	{

		System.out.println("Create a new message signed by user1 encrypted for user2:");

		ASN1Object signed = createSignedData(message, SignedDataStream.IMPLICIT);
		return createEnvelopedData(DerCoder.encode(signed));
	}

	/**
	 * Recovers the original message and verifies the signature.
	 * 
	 * @param obj
	 *          the ContentInfo holding a SignedAndEnryptedData object, in ASN.1
	 *          representation
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getSignedAndEncryptedData(ASN1Object obj)
	    throws PKCSException, IOException
	{

		// user2 means index 2 (hardcoded for this demo)
		byte[] signed = getEnvelopedData(obj, user2_pk, 1);
		try {
			return getSignedData(DerCoder.decode(signed), null);
		} catch (CodingException ex) {
			throw new PKCSException(ex.getMessage());
		}
	}

	/**
	 * Creates a PKCS#7 <code>DigestedData</code> object.
	 * <p>
	 * 
	 * @param message
	 *          the message to be digested, as byte representation
	 * @return the <code>DigestedData</code> wrapped in a ContentInfo, as
	 *         ASN1Object
	 * @exception Exception
	 *              if the <code>DigestedData</code> object cannot be created
	 */
	public ASN1Object createDigestedData(byte[] message)
	    throws Exception
	{

		System.out.println("Create a new message to be digested:");

		// compute the message digest:
		java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA",
		    "IAIK");
		md.update(message);
		byte[] digest_ = md.digest();
		// create a DigestedData object and supply content and message digest:
		DigestedData digestedData = new DigestedData(new Data(message), AlgorithmID.sha,
		    digest_);
		// prepare the DigestedData structure just created for transmission by
		// transforming it
		// into an ASN1Object or immediately DER encoding it:
		ContentInfo ci = new ContentInfo(digestedData);

		return ci.toASN1Object();

	}

	/**
	 * Parses a PKCS#7 <code>DigestedData</code> object and verifies the hash.
	 * 
	 * @param asn1Obj
	 *          the ContentInfo holding a DigestedData object, in ASN.1
	 *          representation
	 * 
	 * @return the inherent message as byte array
	 * @exception PKCSException
	 *              if any signature does not verify
	 */
	public byte[] getDigestedData(ASN1Object asn1Obj)
	    throws PKCSException, NoSuchAlgorithmException
	{

		// create a content info from the ASN.1 object
		ContentInfo contentInfo = new ContentInfo(asn1Obj);
		System.out.println("This ContentInfo holds content of type "
		    + contentInfo.getContentType().getName());

		// get the DigestedData:
		DigestedData digestedData = (DigestedData) contentInfo.getContent();
		// get the content and the inherent message:
		ContentInfo ci = (ContentInfo) digestedData.getContentInfo();
		Data data = (Data) ci.getContent();
		byte[] message = data.getData();
		// compute the digest from the obtained message:
		java.security.MessageDigest md = digestedData.getDigestAlgorithm()
		    .getMessageDigestInstance();
		md.update(message);
		byte[] message_digest = md.digest();
		// get the digest from the received DigestedData and compare it against the
		// message digest just computed:
		byte[] digest = digestedData.getDigest();
		if (iaik.utils.CryptoUtils.secureEqualsBlock(digest, message_digest)) {
			System.out.println("Digest verification successfully completed!");
		}
		return message;

	}

	/**
	 * Creates a PKCS#7 <code>DigestedData</code> object.
	 * <p>
	 * 
	 * @param message
	 *          the message to be digested, as byte representation
	 * @return the <code>DigestedData</code> wrapped into a ContentInfo, as ASN.1
	 *         object
	 * @exception PKCSException
	 *              if the <code>DigestedData</code> object cannot be created
	 */
	public ASN1Object createDigestedData(byte[] message, int mode)
	    throws PKCSException
	{

		System.out.println("Create a new digested message:");

		// create a new DigestedData object which includes the data
		DigestedData digested_data = new DigestedData(message, AlgorithmID.sha, mode);
		ContentInfo ci = new ContentInfo(digested_data);
		return ci.toASN1Object();
	}

	/**
	 * Parses a PKCS#7 <code>DigestedData</code> object and verifies the hash
	 * value.
	 * 
	 * @param obj
	 *          the ContentInfo holding a <code>DigestedData</code>, as ASN.1
	 *          object
	 * @param message
	 *          the message which was transmitted out-of-band (explicit digested)
	 * 
	 * @return the message
	 * @exception PKCSException
	 *              if some parsing exception occurs
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public byte[] getDigestedData(ASN1Object obj, byte[] message)
	    throws PKCSException, IOException
	{

		// create a content info from the ASN.1 object
		ContentInfo ci = new ContentInfo(obj);
		System.out.println("This ContentInfo holds content of type "
		    + ci.getContentType().getName());

		DigestedData digested_data = null;
		if (message == null) {
			// in implicit mode we simply can get the content:
			digested_data = (DigestedData) ci.getContent();
		} else {

			try {
				digested_data = new DigestedData(message, AlgorithmID.sha);
				// now explicit decode the DER encoded signedData obtained from the
				// contentInfo:
				digested_data.decode(ci.getContentInputStream());
			} catch (NoSuchAlgorithmException ex) {
				throw new PKCSException(ex.getMessage());
			}
		}

		// now verify the digest
		if (digested_data.verify()) {
			System.out.println("Hash ok!");
		} else {
			System.out.println("Hash verification failed!");
		}

		return digested_data.getContent();
	}

	/**
	 * Creates a PKCS#7 <code>EncryptedData</code> message.
	 * <p>
	 * The supplied content is PBE-encrypted using the specified password.
	 * 
	 * @param message
	 *          the message to be encrypted, as byte representation
	 * @param pbeAlgorithm
	 *          the PBE algorithm to be used
	 * @param password
	 *          the password
	 * @return the <code>EncryptedData</code> object wrapped into a ContentInfo,
	 *         as ASN1Object
	 * @exception PKCSException
	 *              if the <code>EncryptedData</code> object cannot be created
	 */
	public ASN1Object createEncryptedData(byte[] message,
	                                      AlgorithmID pbeAlgorithm,
	                                      char[] password)
	    throws PKCSException
	{

		EncryptedData encrypted_data;

		try {
			encrypted_data = new EncryptedData(message);
			// encrypt the message
			encrypted_data.setupCipher(pbeAlgorithm, password);
		} catch (InvalidKeyException ex) {
			throw new PKCSException("Key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		}
		// create the ContentInfo
		ContentInfo ci = new ContentInfo(encrypted_data);
		return ci.toASN1Object();

	}

	/**
	 * Decrypts the PBE-encrypted content of the given <code>EncryptedData</code>
	 * object using the specified password and returns the decrypted (= original)
	 * message.
	 * 
	 * @param asn1Object
	 *          a ContentInfo-ASN1Object holding the <code>EncryptedData</code>
	 *          object
	 * @param password
	 *          the password to decrypt the message
	 * 
	 * @return the recovered message, as byte array
	 * @exception PKCSException
	 *              if the message cannot be recovered
	 */
	public byte[] getEncryptedData(ASN1Object asn1Object, char[] password)
	    throws PKCSException
	{

		// create a content info from the ASN.1 object
		ContentInfo ci = new ContentInfo(asn1Object);
		System.out.println("This ContentInfo holds content of type "
		    + ci.getContentType().getName());

		// get the EncryptedData
		EncryptedData encrypted_data = (EncryptedData) ci.getContent();

		System.out.println("Information about the encrypted data:");
		EncryptedContentInfo eci = (EncryptedContentInfo) encrypted_data
		    .getEncryptedContentInfo();
		System.out.println("Content type: " + eci.getContentType().getName());
		System.out.println("Content encryption algorithm: "
		    + eci.getContentEncryptionAlgorithm().getName());

		// decrypt the message
		try {
			encrypted_data.setupCipher(password);
			return encrypted_data.getContent();

		} catch (InvalidKeyException ex) {
			throw new PKCSException("Key error: " + ex.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.getMessage());
		} catch (InvalidAlgorithmParameterException ex) {
			throw new PKCSException("Invalid Parameters: " + ex.toString());
		} catch (InvalidParameterSpecException ex) {
			throw new PKCSException("Content encryption algorithm not implemented: "
			    + ex.toString());
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
			// test PKCS#7 DataStream
			//
			System.out.println("\nDataStream demo [create]:\n");
			data = createDataStream(message);
			// transmit data
			System.out.println("\nDataStream demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getDataStream(data);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

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

			//
			// test PKCS#7 Implicit SignedDataStream
			//
			System.out.println("\nImplicit SignedDataStream demo [create]:\n");
			data = createSignedDataStream(message, SignedDataStream.IMPLICIT);
			// transmit data
			System.out.println("\nImplicit SignedDataStream demo [parse]:\n");
			received_message = getSignedDataStream(data, null);
			System.out.print("\nSigned content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Explicit SignedDataStream
			//
			System.out.println("\nExplicit SignedDataStream demo [create]:\n");
			data = createSignedDataStream(message, SignedDataStream.EXPLICIT);
			// transmit data
			System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
			received_message = getSignedDataStream(data, message);
			System.out.print("\nSigned content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 SignedAndEnvelopedDataStream
			//
			System.out.println("\nSignedAndEnvelopedDataStream demo [create]:\n");
			data = createSignedAndEnvelopedDataStream(message);
			// transmit data
			System.out.println("\nSignedAndEnvelopedDataStream demo [parse]:\n");
			received_message = getSignedAndEnvelopedDataStream(data);
			System.out.print("\nSignedAndEnvelopedStream content: ");
			if (received_message != null) System.out.println(new String(received_message));

			//
			// test PKCS#7 SignedAndEncryptedDataStream
			//
			System.out.println("\nSignedAndEncryptedDataStream demo [create]:\n");
			data = createSignedAndEncryptedDataStream(message);
			// transmit data
			System.out.println("\nSignedAndEncryptedDataStream demo [parse]:\n");
			received_message = getSignedAndEncryptedDataStream(data);
			System.out.print("\nSignedAndEncrypted content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Implicit DigestedDataStream
			//
			System.out.println("\nImplicit DigestedDataStream demo [create]:\n");
			data = createDigestedDataStream(message, DigestedDataStream.IMPLICIT);
			// transmit data
			System.out.println("\nImplicit DigestedDataStream demo [parse]:\n");
			received_message = getDigestedDataStream(data, null);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Explicit DigestedDataStream
			//
			System.out.println("\nExplicit DigestedDataStream demo [create]:\n");
			data = createDigestedDataStream(message, DigestedDataStream.EXPLICIT);
			// transmit data
			System.out.println("\nExplicit DigestedDataStream demo [parse]:\n");
			received_message = getDigestedDataStream(data, message);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 EncryptedDataStream
			//
			System.out.println("\nEncryptedDataStream demo [create]:\n");
			data = createEncryptedDataStream(message,
			    AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC, "password".toCharArray());
			// transmit data
			System.out.println("\nEncryptedDataStream demo [parse]:\n");
			received_message = getEncryptedDataStream(data, "password".toCharArray());
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			// the non-stream implementation
			System.out.println("\nNon-stream implementation demos");
			System.out.println("===============================");
			//
			// test PKCS#7 Data
			//
			ASN1Object obj = null;

			System.out.println("\nData demo [create]:\n");
			obj = createData(message);
			// transmit data
			System.out.println("\nData demo [parse]:\n");

			received_message = getData(obj);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 EnvelopedData
			//
			obj = null;
			System.out.println("\nEnvelopedData demo [create]:\n");
			obj = createEnvelopedData(message);
			// transmit data
			System.out.println("\nEnvelopedData demo [parse]:\n");
			// user1 means index 0 (hardcoded for this demo)
			received_message = getEnvelopedData(obj, user1_pk, 0);
			System.out.print("\nDecrypted content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Implicit SignedData
			//
			System.out.println("\nImplicit SignedData demo [create]:\n");
			obj = createSignedData(message, SignedDataStream.IMPLICIT);
			// transmit data
			System.out.println("\nImplicit SignedData demo [parse]:\n");
			received_message = getSignedData(obj, null);
			System.out.print("\nSigned content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Explicit SignedData
			//
			System.out.println("\nExplicit SignedData demo [create]:\n");
			obj = createSignedData(message, SignedDataStream.EXPLICIT);
			// transmit data
			System.out.println("\nExplicit SignedData demo [parse]:\n");
			received_message = getSignedData(obj, message);
			System.out.print("\nSigned content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 SignedAndEnvelopedData
			//
			System.out.println("\nSignedAndEnvelopedData demo [create]:\n");
			obj = createSignedAndEnvelopedData(message);
			// transmit data
			System.out.println("\nSignedAndEnvelopedData demo [parse]:\n");
			received_message = getSignedAndEnvelopedData(obj);
			System.out.print("\nSignedAndEnvelopedData content: ");
			if (received_message != null) System.out.println(new String(received_message));

			//
			// test PKCS#7 SignedAndEncryptedData
			//
			System.out.println("\nSignedAndEncryptedData demo [create]:\n");
			obj = createSignedAndEncryptedData(message);
			// transmit data
			System.out.println("\nSignedAndEncryptedData demo [parse]:\n");
			received_message = getSignedAndEncryptedData(obj);
			System.out.print("\nSignedAndEncrypted content: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 DigestedData
			//
			System.out.println("\nDigestedData demo [create]:\n");
			obj = createDigestedData(message);
			// transmit data
			System.out.println("\nDigestedData demo [parse]:\n");
			received_message = getDigestedData(obj);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));
			System.out.println("Ready!");

			//
			// test PKCS#7 Implicit DigestedData
			//
			System.out.println("\nImplicit DigestedData demo [create]:\n");
			obj = createDigestedData(message, DigestedDataStream.IMPLICIT);
			// transmit data
			System.out.println("\nImplicit DigestedData demo [parse]:\n");
			received_message = getDigestedData(obj, null);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 Explicit DigestedData
			//
			System.out.println("\nExplicit DigestedData demo [create]:\n");
			obj = createDigestedData(message, DigestedDataStream.EXPLICIT);
			// transmit data
			System.out.println("\nExplicit DigestedData demo [parse]:\n");
			received_message = getDigestedData(obj, message);
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			//
			// test PKCS#7 EncryptedData
			//
			System.out.println("\nEncryptedData demo [create]:\n");
			obj = createEncryptedData(message, AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC,
			    "password".toCharArray());
			// transmit data
			System.out.println("\nEncryptedData demo [parse]:\n");
			received_message = getEncryptedData(obj, "password".toCharArray());
			System.out.print("\nContent: ");
			System.out.println(new String(received_message));

			System.out.println("Ready!");

		} catch (Exception ex) {
			ex.printStackTrace();
			Util.waitKey();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the PKCS#7 content type implementation tests.
	 */
	public static void main(String argv[]) {

		DemoUtil.initDemos();

		(new PKCS7Demo()).start();
		Util.waitKey();
	}
}
