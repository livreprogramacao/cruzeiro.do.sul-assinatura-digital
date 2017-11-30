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
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import demo.IAIKDemo;

/**
 * This class provides a framework for cipher self-tests.
 * 
 * @version File Revision <!-- $$Revision: --> 17 <!-- $ -->
 */

public class CipherAlgorithm implements IAIKDemo {

	/*
	 * Encrypt given plaindata with given algorithm, mode, key and IV
	 */
	protected byte[] encrypt(String algorithm,
	                         String opmode,
	                         SecretKey key,
	                         byte[] iv,
	                         byte[] plainData)
	    throws Exception
	{

		String mode = algorithm + "/" + opmode + "/PKCS5Padding";
		System.out.println("Encrypt with " + mode + " ...");

		Cipher cipher = Cipher.getInstance(mode, "IAIK");
		if (opmode.equals("ECB")) cipher.init(Cipher.ENCRYPT_MODE, key);
		else cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] ciphertext = cipher.doFinal(plainData);

		return ciphertext;
	}

	/*
	 * Decrypt given ciphertext with given algorithm, mode, key and IV
	 */
	protected byte[] decrypt(String algorithm,
	                         String opmode,
	                         SecretKey key,
	                         byte[] iv,
	                         byte[] ciphertext)
	    throws Exception
	{

		String mode = algorithm + "/" + opmode + "/PKCS5Padding";
		System.out.println("Decryt with " + mode + " ...");

		Cipher cipher = Cipher.getInstance(mode, "IAIK");
		if (opmode.equals("ECB")) cipher.init(Cipher.DECRYPT_MODE, key);
		else cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

		byte[] decryptedtext = cipher.doFinal(ciphertext);
		return decryptedtext;
	}

	/*
	 * Check whether plaindata and decrypted data are equal
	 */
	protected boolean check(String algorithm,
	                        String opmode,
	                        SecretKey key,
	                        byte[] iv,
	                        byte[] plaintext,
	                        byte[] ciphertext)
	    throws Exception
	{
		String mode = algorithm + "/" + opmode + "/PKCS5Padding";

		Cipher cipher = Cipher.getInstance(mode, "IAIK");
		if (opmode.equals("ECB")) cipher.init(Cipher.DECRYPT_MODE, key);
		else cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plaintext, decryptedtext)) {
			System.out.println("Data incorrect!");
			System.out.print("decryptedtext       : " + Util.toString(ciphertext));
			System.out.print("not equal plaintext:  " + Util.toString(plaintext));
			System.out.println();
			return false;
		}

		System.out.println("Plaintext:                   " + new String(plaintext));
		System.out.println("equals decrypted ciphertext: " + new String(decryptedtext));
		return true;
	}

	/*
	 * carry out encryption, decryption and check
	 */
	public void start() {

		// specify algorithm and mode to use
		String algorithm = "AES";
		String opmode = "CBC";

		try {
			boolean ok = true;

			// generating key
			KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, "IAIK");
			SecretKey key = keyGenerator.generateKey();

			// generate plaintext
			byte[] plaintext = "My important secret message".getBytes("ASCII");

			// generate IV
			Cipher cipher = Cipher.getInstance(algorithm + "/" + opmode + "/PKCS5Padding",
			    "IAIK");
			SecureRandom random = SecRandom.getDefault();
			byte[] iv = new byte[cipher.getBlockSize()];
			random.nextBytes(iv);

			// encrypt
			System.out.println("Encryption: ");
			byte[] ciphertext = encrypt(algorithm, opmode, key, iv, plaintext);
			System.out.println("Encrypted data: " + Util.toString(ciphertext));
			System.out.println();

			// decrypt
			System.out.println("Decryption: ");
			byte[] cleartext = decrypt(algorithm, opmode, key, iv, ciphertext);
			System.out.println("Decrypted data: " + new String(cleartext));
			System.out.println();

			// check
			System.out.println("Check ciphertext: ");
			ok = check(algorithm, opmode, key, iv, plaintext, ciphertext);
			System.out.println();

			if (ok) System.out.println("Cipher " + algorithm + " OK! No ERRORS found!\n");
			else throw new RuntimeException("Cipher " + algorithm
			    + " NOT OK! There were ERRORS!!!");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	public static void main(String arg[]) {
		Security.insertProviderAt(new IAIK(), 2);
		(new CipherAlgorithm()).start();
		iaik.utils.Util.waitKey();
	}
}
