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

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import demo.IAIKDemo;

/**
 * Simple Cipher Demo.
 * <p>
 * Shows how to use a <code>Cipher</code> engine for en/decrypting
 * some data.
 *
 * @version File Revision <!-- $$Revision: --> 5 <!-- $ -->
 */
public class CipherDemo implements IAIKDemo {

	/**
	 * Default constructor.
	 */
	public CipherDemo() {
	}

	public void start() {
		try {
			// the data to be encrypted
			byte[] data = "Hello Secure World!".getBytes("ASCII");

			// generate key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "IAIK");
			SecretKey secretKey = keyGen.generateKey();
			// get Cipher and init it for encryption
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IAIK");
			aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			// encrypt data
			byte[] cipherText = aesCipher.doFinal(data);
			// get the initialization vector from the cipher
			byte[] ivBytes = aesCipher.getIV();
			IvParameterSpec iv = new IvParameterSpec(ivBytes);

			// raw key material (usually the key will be securely stored/transmitted)
			byte[] keyBytes = secretKey.getEncoded();
			// create a SecretKeySpec from key material
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
			// get Cipher and init it for decryption
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IAIK");
			aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
			byte[] plainText = aesCipher.doFinal(cipherText);

			if (CryptoUtils.equalsBlock(data, plainText)) {
				System.out.println("En/decryption Test successful.");
			} else {
				System.err.println("Test FAILED!");
				throw new RuntimeException(
				    "Error: Decrypted data does not match to original one!");
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Main Method.
	 */
	public static void main(String[] args) {
		Security.insertProviderAt(new IAIK(), 2);
		(new CipherDemo()).start();
		System.out.println("finished.");
		//DemoUtil.waitKey();
	}
}
