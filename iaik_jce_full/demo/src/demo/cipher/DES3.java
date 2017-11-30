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

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import demo.IAIKDemo;

import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;

/**
 * Demonstration for <i>Key-Generation</i>, <i>Encrypting</i> and <i>Decrypting</i> messages
 * with 3-DES Algorithm.
 * Chosen mode: <i>CBC</i>
 * Key size: used size for 3DES is 192 bit
 * <p>
 *
 * @version File Revision <!-- $$Revision: --> 1 <!-- $ -->
 */
public class DES3 implements IAIKDemo {

	/**
	 * Processes 3-DES in CBC mode
	 * Key and plain data are given in this function.
	 */
	public boolean processCBC()
	    throws Exception
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("3DES", "IAIK");
		SecretKey key = keyGenerator.generateKey();

		byte[] plain_data = "My important secret message".getBytes("ASCII");

		System.out.println("Doing 3DES CBC...");
		System.out.println("Plain message data: " + new String(plain_data));

		Cipher cipher = Cipher.getInstance("3DES/CBC/PKCS5Padding", "IAIK");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plain_data);
		byte[] iv = cipher.getIV();
		System.out.println("Encrypted data: " + iaik.utils.Util.toString(ciphertext));

		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_data, decryptedtext)) {
			System.out.println("Decryption error!");
			return false;
		}

		System.out.println("Decrypted data: " + new String(decryptedtext));

		return true;
	}

	/**
	 * Starts encryption and decryption method and catches possible exceptions.
	 */

	public void start() {

		try {
			boolean ok = processCBC();

			if (ok) {
				System.out.println("3DES Encryption successful!\n");
			} else {
				throw new RuntimeException("ERRORS during encryption with 3DES!!!");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs the 3DES demo.
	 */
	public static void main(String arg[]) {

		try {
			Security.insertProviderAt(new IAIK(), 2);
			(new DES3()).start();
		} catch (Throwable e) {
			//
		}
	}
}
