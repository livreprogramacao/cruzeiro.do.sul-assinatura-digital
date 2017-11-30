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
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;

import demo.IAIKDemo;

/**
 * Demo to show how to use the RC2-Implementation.
 * key size: standard 128 bit
 * cipher mode: CBC
 * padding sheme: PKCS5-Padding
 * 
 * <p>
 *
 * @version File Revision <!-- $$Revision: --> 19 <!-- $ -->
 */
public class RC2 implements IAIKDemo {

	/**
	 * Doing encryption and decryption using RC2.
	 */
	public boolean demonstrateRC2()
	    throws Exception
	{

		//Generating a key with standard bit size.
		KeyGenerator keygenerator = KeyGenerator.getInstance("RC2", "IAIK");
		SecretKey key = keygenerator.generateKey();

		//Generating the message to encrypt and decrypt.
		byte[] plain_text = "My important secret message".getBytes("ASCII");

		System.out.println("Doing RC2 CBC ... ");

		//Create a Cipher Object for RC2 in CBC Mode with PKCS5 Padding.
		Cipher cipher = Cipher.getInstance("RC2/CBC/PKCS5Padding", "IAIK");

		//Encryption
		AlgorithmParameterSpec spec = new RC2ParameterSpec(128);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		byte[] ciphertext = cipher.doFinal(plain_text);

		System.out.println("Encrypted data: " + iaik.utils.Util.toString(ciphertext));

		AlgorithmParameters param = cipher.getParameters();

		//Decryption
		cipher.init(Cipher.DECRYPT_MODE, key, param);
		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_text, decryptedtext)) {
			System.out.println("RC2 decryption Error!");
			return false;
		}

		System.out.println("Decrypted data: " + new String(decryptedtext));

		return true;
	}

	public void start() {

		try {
			boolean ok = demonstrateRC2();

			if (ok) {
				System.out.println("Encryption successful!\n");
			} else {
				throw new RuntimeException("ERRORS during encryption!!!");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs the RC2 Demo.
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);
		(new RC2()).start();
		iaik.utils.Util.waitKey();
	}
}
