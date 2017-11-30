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

import iaik.asn1.ASN;
import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.SEQUENCE;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs1.RSAOaepPSourceParameterSpec;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.pkcs.pkcs7.RSACipherProvider;
import iaik.pkcs.pkcs7.RecipientInfo;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;

/**
 * A RSA cipher provider that uses OEAP padding.
 * @version File Revision <!-- $$Revision: --> 6 <!-- $ -->
 */
public class RSACipherProviderOAEP extends RSACipherProvider {
  
  
  private String transformation_;
  /**
   * The RecipientInfo to be used; if set.
   */
  RecipientInfo recipient_;

	/**
	 * Default constructor.
	 */
	public RSACipherProviderOAEP() {
		super();
	}
	
	/**
   * Creates a RSACipherProvider for the given recipient and OAEP cipher transformation string.
   * The OAEP transformation String may specify hash algorithm and mask generation function to use,
   * e.g.:
   * <pre>
   * X509Certificate recipientCert = ...;
   * AlgorithmID oaepID = (AlgorithmID) rsaEncryptionOAEP.clone();
   * RecipientInfo recipient = new RecipientInfo(recipientCert, oaepID);
   * // set the RSA cipher provider for using RSA with OAEP padding (let Cipher calculate OAEP parameters)
   * recipient.setRSACipherProvider(new RSACipherProviderOAEP("RSA/ECB/OAEPWithSHA256AndMGF1Padding", recipient));
   * ... 
   * </pre>
   * 
   * @param transformation the RSA-OAEP cipher transformation String
   * @param recipient the recipient
   */
  public RSACipherProviderOAEP(String transformation, RecipientInfo recipient) {
    super();
    transformation_ = transformation;
    recipient_ = recipient;
  }
	
	/**
   * Creates a RSACipherProvider for the given recipient.
   * 
   * @param recipient the recipient
   */
  public RSACipherProviderOAEP(RecipientInfo recipient) {
    super();
    recipient_ = recipient;
  }

	/**
	 * Creates a new RSACipherProvider for the given RSA cipher en/decryption providers.
	 * 
	 * @param cipherEncryptProvider the name of the crypto provider to be used for RSA encryption
	 * @param cipherDecryptProvider the name of the crypto provider to be used for RSA decryption
	 * 
	 */
	public RSACipherProviderOAEP(String cipherEncryptProvider, String cipherDecryptProvider)
	{
		super(cipherEncryptProvider, cipherDecryptProvider);
	}

	/**
	 * En/deciphers the given data using RSA with OAEP padding.
	 * 
	 * @param mode the cipher mode, either ENCRYPT (1) or DECRYPT (2)
	 * @param key the key to be used
	 * @param data the data to be en/deciphered:
	 *        <ul>
	 *            <li>for RecipientInfo cek encryption: the raw content encryption key
	 *            <li>for RecipientInfo cek decryption: the encrypted content encryption key
	 *        </ul>
	 * 
	 * @return the en/deciphered data:
	 *         <ul>
	 *            <li>for RecipientInfo cek encryption: the encrypted content encryption key
	 *            <li>for RecipientInfo cek decryption: the raw (decrypted) content encryption key
	 *        </ul>
	 *
	 * @exception NoSuchProviderException if any of the crypto providers of this RSACipherProvider is not suitable
	 *                                    for requested operation
	 * @exception NoSuchAlgorithmException if RSA ciphering is not supported
	 * @exception InvalidKeyException if the supplied key is invalid
	 * @exception GeneralSecurityException if a general security problem occurs
	 */
	protected byte[] cipher(int mode, Key key, byte[] data)
	    throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
	    GeneralSecurityException
	{
	  AlgorithmParameters params = null;
	  AlgorithmID keyEncAlg = null;
    if (recipient_ != null) {
      keyEncAlg = recipient_.getKeyEncryptionAlgorithm();
      ASN1Object asn1Params = keyEncAlg.getParameter(); 
      if ((asn1Params != null) && (!asn1Params.isA(ASN.NULL))) {
        params = keyEncAlg.getAlgorithmParameters(null, "IAIK");
      }  
    }
    String transformation = (transformation_ != null) ? transformation_ : "RSA/ECB/OAEP"; 
    Cipher rsa = Cipher.getInstance(transformation);
    rsa.init(mode, key, params);
    byte[] result = rsa.doFinal(data);
    if ((mode == Cipher.ENCRYPT_MODE) && (keyEncAlg != null) && (params == null)) {
      params = rsa.getParameters();
      if (params != null) {
        keyEncAlg.setAlgorithmParameters(params);
      }
    }
    return result;
	}
	
	
}
