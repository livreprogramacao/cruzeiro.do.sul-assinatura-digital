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
import iaik.utils.Util;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Demo to show how to use the RC5-Implementation.
 * key size: standard 128 bit
 * cipher mode: CBC
 * padding sheme: PKCS5-Padding
 * 
 * @version File Revision <!-- $$Revision: --> 18 <!-- $ -->
 */
public class RC5 {

	/**
	 * Doing encryption and decryption using RC5.
	 */
	public boolean demonstrateRC5()
	    throws Exception
	{

		//Generating a key with standard bit size.
		KeyGenerator keygenerator = KeyGenerator.getInstance("RC5");
		SecretKey key = keygenerator.generateKey();

		//Generating the message to encrypt and decrypt.
		byte[] plain_text = "My important secret message".getBytes("ASCII");

		System.out.println("Doing RC5 CBC ...");

		//Create a Cipher Object for RC5 in CBC Mode with PKCS5 Padding.
		Cipher cipher = Cipher.getInstance("RC5/CBC/PKCS5Padding", "IAIK");

		//Encryption
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plain_text);

		System.out.println("Encrypted data: " + iaik.utils.Util.toString(ciphertext));

		//Decryption
		AlgorithmParameters param = cipher.getParameters();
		cipher.init(Cipher.DECRYPT_MODE, key, param);

		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_text, decryptedtext)) {
			System.out.println("RC5 mode decryption error!");
			System.out.println(Util.toString(decryptedtext));
			return false;
		}

		System.out.println("Decryped data: " + new String(decryptedtext));

		return true;
	}

	public void start() {

		try {
			boolean ok = true;

			ok = demonstrateRC5();

			if (ok) System.out.println("RC5 demo OK! No ERRORS found!\n");
			else throw new RuntimeException("RC5 demo NOT OK! There were ERRORS!!!");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs the RC5 demo.
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);
		(new RC5()).start();
		iaik.utils.Util.waitKey();
	}
}
