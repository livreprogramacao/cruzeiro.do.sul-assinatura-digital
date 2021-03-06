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

import demo.IAIKDemo;

/**
 * Demo to show how to use the AES Implementation.
 * key size: standard 128 bit
 * cipher mode: CBC
 * padding sheme: PKCS5-Padding
 *
 * @version File Revision <!-- $$Revision: --> 14 <!-- $ -->
 */
public class AES implements IAIKDemo {

	/**
	 * Doing encryption and decryption using AES.
	 */
	public boolean demonstrateAES()
	    throws Exception
	{

		//generating key with standard key size
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "IAIK");
		SecretKey key = keyGenerator.generateKey();

		//generating plain text to be encryped and decrypted
		byte[] plain_text = "My important secret message".getBytes("ASCII");

		System.out.println("Doing AES CBC ...");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IAIK");

		//encryption with automatic generated IV
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plain_text);

		System.out.println("Encrypted data: " + iaik.utils.Util.toString(ciphertext));

		//get generated IV
		byte[] iv = cipher.getIV();

		//decryption
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_text, decryptedtext)) {
			System.out.println("AES mode decryption error!");
			return false;
		}

		System.out.println("Decrypted data: " + new String(decryptedtext));

		return true;
	}

	public void start() {
		try {
			boolean ok = true;

			ok &= demonstrateAES();

			if (ok) System.out.println("AES demo OK! No ERRORS found!\n");
			else throw new RuntimeException("AES demo NOT OK! There were ERRORS!!!");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs the AES demo.
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);

		(new AES()).start();
		iaik.utils.Util.waitKey();
	}
}
