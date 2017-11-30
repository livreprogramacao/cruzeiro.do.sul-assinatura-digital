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

package demo.cipher;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs5.PBES2ParameterSpec;
import iaik.pkcs.pkcs5.PBKDF2KeyAndParameterSpec;
import iaik.security.cipher.PBEKey;
import iaik.security.provider.IAIK;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import demo.IAIKDemo;

/**
 * Demonstrates the usage of the PKCS#5 PBES2 password based encryption scheme
 * using the PKCS#5 PBKDF2 key derivation function to derive the cipher key from
 * the password.
 * <p>
 * This demo contains three tests, all using the same algorithm suite (PBKDF2
 * with HMAC/SHA256 for key derivation and AES for data encryption), but different
 * proceedings.
 * <br>
 * The {@link #testPBES2WithHmacSHA256AndAES first} test directly uses the 
 * PBES2WithHmacSHA256AndAES Cipher engine and therefore does not require any
 * parameter initialization for encryption. 
 * <br>
 * The {@link #testPBES2 second} test uses the general PBES2
 * Cipher engine and is initialized with a PBES2ParameterSpec specifying the
 * encryption scheme (AES), PBKDF2 pseudo random function (HMAC/SHA256), salt, iteration
 * count and derived key length. 
 * <br>
 * The {@link #testPBKDF2 third} test uses the PBKDF2 KeyGenerator
 * (initialized with a PBKDF2KeyAndParameterSpec) to derive the cipher key from the
 * password and then an AES Cipher engine to encrypt the data with the derived key. 
 * 
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class PBES2 implements IAIKDemo {

	// data to be encrypted
	byte[] data;
	// ensure padding
	private final static int BUF_SIZE = 879;

	/**
	 * Default constructor.
	 */
	public PBES2() {
		data = new byte[BUF_SIZE];
		Random rnd = new Random();
		rnd.nextBytes(data);
	}
	
	/**
   * Uses the PBES2WithHmacSHA256AndAES Cipher engine to derive a 
   * cipher key from a password and encrypt/decrypt the data with the
   * derived key.
   * 
   * @param data
   *          the data to be encrypted
   * @param pbeKey 
   *          the password PBEKey
   * 
   * @return <code>true</code> if en/decryption is succeeds, <code>false</code>
   *         if it fails
   * 
   * @throws Exception
   *           if an error occurs
   */
  public boolean testPBES2WithHmacSHA256AndAES(byte[] data, PBEKey pbeKey)
      throws Exception
  {

    // get the cipher
    Cipher c = Cipher.getInstance("PBES2WithHmacSHA256AndAES", "IAIK");

    // initialize it with PBEKey
    c.init(Cipher.ENCRYPT_MODE, pbeKey);

    // encrypt the data
    byte[] encrypted = c.doFinal(data);
    // get the Cipher params
    AlgorithmParameters params = c.getParameters();

    // now decrypt
    c = Cipher.getInstance("PBES2WithHmacSHA256AndAES", "IAIK");
    // initialize the cipher again for decrypting and use
    // the generated AlgorithmParameters with the same key
    c.init(Cipher.DECRYPT_MODE, pbeKey, params, null);
    // decrypt the data
    byte[] decrypted = c.doFinal(encrypted);

    // and compare the result against the original data
    if (CryptoUtils.equalsBlock(data, decrypted)) {
      System.out.println("PBES2WithHmacSHA256AndAES Test o.k.");
      return true;
    }

    System.out.println("PBES2WithHmacSHA256AndAES Test: ERROR!!!");
    return false;
  }
	
  /**
   * Uses the PBES2 Cipher engine to derive cipher key from a password 
   * and encrypt/decrypt the data with the derived key.
   * 
   * @param data
   *          the data to be encrypted
   * @param pbeKey 
   *          the password PBEKey
   * 
   * @return <code>true</code> if en/decryption is succeeds, <code>false</code>
   *         if it fails
   * 
   * @throws Exception
   *           if an error occurs
   */
  public boolean testPBES2(byte[] data, PBEKey pbeKey)
      throws Exception
  {

    // iteration count
    int iterationCount = 2000;
    // salt
    byte[] salt = new byte[32];
    SecureRandom secRandom = SecRandom.getDefault();
    secRandom.nextBytes(salt);
    
    // pseudo random function
    AlgorithmID prf = (AlgorithmID)AlgorithmID.hMAC_SHA256.clone();
    // encryption scheme
    AlgorithmID encryptionScheme = (AlgorithmID)AlgorithmID.aes128_CBC.clone();
    int aesKeyLength = 16;
    
    PBES2ParameterSpec pbes2ParameterSpec = 
        new PBES2ParameterSpec(salt, iterationCount, aesKeyLength, encryptionScheme);
    pbes2ParameterSpec.setPrf(prf);

    // get the PBES2 cipher
    Cipher c = Cipher.getInstance("PBES2", "IAIK");

    // initialize it with the generated PbeKey and parameters
    c.init(Cipher.ENCRYPT_MODE, pbeKey, pbes2ParameterSpec);

    // encrypt the data
    byte[] encrypted = c.doFinal(data);
    // get the cipher params
    AlgorithmParameters params = c.getParameters();

    // now decrypt
    c = Cipher.getInstance("PBES2", "IAIK");
    // initialize the cipher again for decrypting and use
    // the generated AlgorithmParameters with the same key
    c.init(Cipher.DECRYPT_MODE, pbeKey, params);
    // decrypt the data
    byte[] decrypted = c.doFinal(encrypted);

    // and compare the result against the original data
    if (CryptoUtils.equalsBlock(data, decrypted)) {
      System.out.println("PBES2 Test o.k.");
      return true;
    }

    System.out.println("PBES2 Test: ERROR!!!");
    return false;
  }
  
  /**
   * Uses the AES Cipher engine and the PBKDF2 KeyGenerator to derive a 
   * cipher key from a password and encrypt/decrypt the data with the
   * derived key.
   * 
   * @param data
   *          the data to be encrypted
   * @param pbeKey 
   *          the password PBEKey
   * 
   * @return <code>true</code> if en/decryption is succeeds, <code>false</code>
   *         if it fails
   * 
   * @throws Exception
   *           if an error occurs
   */
  public boolean testPBKDF2(byte[] data, PBEKey pbeKey)
      throws Exception
  {

    // secure random
    SecureRandom secRandom = SecRandom.getDefault();

    // iteration count
    int iterationCount = 2000;
    // salt
    byte[] salt = new byte[32];
    secRandom.nextBytes(salt);
    int cipherKeyLength = 16;
    String cipherKeyName = "AES";
    
    // pseudo random function
    AlgorithmID prf = (AlgorithmID)AlgorithmID.hMAC_SHA256.clone();

    // derive key from password
    SecretKey sk = deriveKey(pbeKey, salt, iterationCount, cipherKeyLength, prf, cipherKeyName);

    // get the cipher
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "IAIK");

    // initialize it with the generated SecretKey
    c.init(Cipher.ENCRYPT_MODE, sk);

    // encrypt the data
    byte[] encrypted = c.doFinal(data);
    // get iv generated by the cipher
    byte[] iv = c.getIV();

    // now decrypt
    c = Cipher.getInstance("AES/CBC/PKCS5Padding", "IAIK");
    // initialize the cipher again for decrypting and use
    // the generated AlgorithmParameters with the same key
    c.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv), null);
    // decrypt the data
    byte[] decrypted = c.doFinal(encrypted);

    // and compare the result against the original data
    if (CryptoUtils.equalsBlock(data, decrypted)) {
      System.out.println("PBKDF2 Test o.k.");
      return true;
    }

    System.out.println("PBKDF2 Test: ERROR!!!");
    return false;
  }


	/**
	 * Starts the test.
	 */
	public void start() {
		// the password (only used for demo, not suitable for practice)
		char[] password = { 't', 'o', 'p', 'S', 'e', 'c', 'r', 'e', 't' };
	  
		try {
  		// create a KeySpec from our password
	    PBEKeySpec keySpec = new PBEKeySpec(password);
	    // use the "PKCS#5" or "PBE" SecretKeyFactory to convert the password
	    SecretKeyFactory kf = SecretKeyFactory.getInstance("PKCS#5", "IAIK");
	    // create an appropriate PbeKey
	    PBEKey pbeKey = (PBEKey)kf.generateSecret(keySpec);
	    
	    // all following tests use the same algorithm(s)
		  
			// test PBES2WithHmacSHA256AndAES cipher
			testPBES2WithHmacSHA256AndAES(data, pbeKey);
	    // test general PBES2 cipher with AES ans HMAC/SHA256
      testPBES2(data, pbeKey);
      // test explicit PBKDF2 key derivation and subsequent encryption with AES cipher
      testPBKDF2(data, pbeKey);
      
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		} finally {
			// clear password
			for (int i = 0; i < password.length; i++) {
				password[i] = (char) 0;
			}
			password = null;
		}
	}

	/**
	 * Uses the PBKDF2 key derivation function to derive a key from the given
	 * password.
	 * 
	 * @param pbeKey
	 *          the PBEKey providing the encoded password to be used
	 * @param salt
	 *          the salt value for the key derivation function
	 * @param iterationCount
	 *          the iteration count value for the key derivation function
	 * @param keyLen
	 *          the length of the key to be derived from the password
	 * @param prf the pseudo random MAC function to be used by the key derivation
	 *            function PBKDF2         
	 * @param keyName
	 *          the (algorithm) name of the derived key
	 * 
	 * @return the derived key
	 * 
	 * @exception if
	 *              an error occurs when generating the key
	 */
	public SecretKey deriveKey(PBEKey pbeKey,
	                           byte[] salt,
	                           int iterationCount,
	                           int keyLen,
	                           AlgorithmID prf,
	                           String keyName)
	    throws Exception
	{

    SecretKey cipherKey = null;
	  PBKDF2KeyAndParameterSpec parameterSpec = null;
		// encode password
		byte[] pwd = pbeKey.getEncoded();
		try {
		  
			// initialize PBKDF2
			KeyGenerator kg = KeyGenerator.getInstance("PBKDF2", "IAIK");
			parameterSpec = new PBKDF2KeyAndParameterSpec(pwd, salt, iterationCount, keyLen);
			parameterSpec.setPrf(prf);
			kg.init(parameterSpec, null);
			cipherKey = kg.generateKey();
			// use SecretKeyFactory to set the right key format
			SecretKeySpec spec = new SecretKeySpec(cipherKey.getEncoded(), keyName);
      try {
        SecretKeyFactory kf = SecretKeyFactory.getInstance(keyName, "IAIK");
        cipherKey = kf.generateSecret(spec);
      } catch (Exception e) {
        throw new InvalidKeyException("Error creating cipher key: " + e.toString());
      }

		} finally {
			if (pwd != null) {
				// clear pwd
				for (int i = 0; i < pwd.length; i++) {
					pwd[i] = 0;
				}
				pwd = null;
			}
		}
		return cipherKey;
	}
	
	/**
   * Performs some demos for PKCS#5 PBES2 Password Based Encryption.
   */
  public static void main(String arg[]) {
    Security.insertProviderAt(new IAIK(), 2);
    (new PBES2()).start();
    iaik.utils.Util.waitKey();
  }

}
