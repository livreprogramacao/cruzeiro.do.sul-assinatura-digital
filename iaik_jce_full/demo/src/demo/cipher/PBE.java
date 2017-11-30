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

import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;

import java.security.AlgorithmParameters;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import demo.IAIKDemo;

/**
 * Demonstrates the usage of the PKCS#5 PBES1 password based encryption scheme
 * as used by PBE ciphers described in PKCS#5 and PKCS#12.
 * 
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class PBE implements IAIKDemo {

	// data to be encrypted
	byte[] data;
	// ensure padding
	private final static int BUF_SIZE = 879;

	/**
	 * Default constructor.
	 */
	public PBE() {
		data = new byte[BUF_SIZE];
		Random rnd = new Random();
		rnd.nextBytes(data);
	}

	/**
	 * Uses the given PBE cipher to PBE encrypt/decrypt the data with the given
	 * password.
	 * 
	 * @param algorithm
	 *          the PBE algorithm to be used
	 * @param secretKeyFactory
	 *          the secret key factory to be used for generating a key from the
	 *          password
	 * @param data
	 *          the data to be encrypted
	 * @param password
	 *          the password to be used
	 * 
	 * @return <code>true</code> if en/decryption is succeeds, <code>false</code>
	 *         if it fails
	 * 
	 * @throws Exception
	 *           if an error occurs
	 */
	public boolean testCipher(String algorithm,
	                          String secretKeyFactory,
	                          byte[] data,
	                          char[] password)
	    throws Exception
	{

		// create a KeySpec from our password
		PBEKeySpec keySpec = new PBEKeySpec(password);
		// use the "PKCS#5" or "PBE" SecretKeyFactory to convert the password
		SecretKeyFactory kf = SecretKeyFactory.getInstance(secretKeyFactory, "IAIK");
		// create an appropriate SecretKey
		SecretKey sk = kf.generateSecret(keySpec);

		// get the cipher
		Cipher c = Cipher.getInstance(algorithm, "IAIK");

		// initialize it with the generated SecretKey
		c.init(Cipher.ENCRYPT_MODE, sk);

		// encrypt the data
		byte[] encrypted = c.doFinal(data);
		// since we specified no AlgorithmParameters random values were generated
		// get this random salt and iteration count
		AlgorithmParameters params = c.getParameters();

		// now decrypt
		c = Cipher.getInstance(algorithm, "IAIK");
		// initialize the cipher again for decrypting and use
		// the generated AlgorithmParameters with the same key
		c.init(Cipher.DECRYPT_MODE, sk, params, null);
		// decrypt the data
		byte[] decrypted = c.doFinal(encrypted);

		// and compare the result against the original data
		if (CryptoUtils.equalsBlock(data, decrypted)) {
			System.out.println(algorithm + ": Test o.k.");
			return true;
		}

		System.out.println(algorithm + ": ERROR!!!");
		return false;
	}


	/**
	 * Starts the test.
	 */
	public void start() {
		// the password (only used for demo, not suitable for practice)
		char[] password = { 't', 'o', 'p', 'S', 'e', 'c', 'r', 'e', 't' };
		try {
			// test cipher defined in PKCS#5
			testCipher("PbeWithMD5AndDES_CBC", "PKCS#5", data, password);
			// the same again with aliases (names defined by Sun)
			testCipher("PBEWithMD5AndDES", "PBE", data, password);

			// test ciphers defined in PKCS#12
			testCipher("PbeWithSHAAnd40BitRC2_CBC", "PKCS#12", data, password);
			testCipher("PbeWithSHAAnd3_KeyTripleDES_CBC", "PKCS#12", data, password);

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		} finally {
			// clear password
			for (int i = 0; i < password.length; i++) {
				password[i] = (char) 0;
			}
		}
	}

	/**
	 * Performs some tests for Password Based Encryption ciphers.
	 */
	public static void main(String arg[]) {
		Security.insertProviderAt(new IAIK(), 2);
		(new PBE()).start();
		iaik.utils.Util.waitKey();
	}

}
