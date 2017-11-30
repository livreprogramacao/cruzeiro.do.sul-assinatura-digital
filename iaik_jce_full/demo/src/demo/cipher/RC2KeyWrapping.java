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

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import demo.IAIKDemo;

import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

/**
 * This example demonstrates the use of the CMS RC2 Key wrap cipher.
 * <p>
 * This example shows how this API can be used to encrypt a symmetric RC2
 * content encryption key with a RC2 key encryption key as defined by
 * RFC 2630 (Cryptographic Message Syntax - CMS).
 * @version File Revision <!-- $$Revision: --> 10 <!-- $ -->
 */
public class RC2KeyWrapping implements IAIKDemo {

	// static variables defining conventions previously agreed upon,
	// i.e. the algorithms to use
	private final static String keyWrapAlgorithm = "RC2WrapRC2";
	private final static int keyType = Cipher.SECRET_KEY;
	private final static String keyAlgorithm = "RC2";

	public RC2KeyWrapping() {
		// empty
	}

	public void start() {

		try {
			// generate the RC2 Key Encryption Key (KEK)
			int keyLength = 128;
			KeyGenerator keyGen = KeyGenerator.getInstance("RC2", "IAIK");
			keyGen.init(keyLength);
			// generate a new key
			Key kek = keyGen.generateKey();

			AlgorithmParameterSpec rc2KeyWrapParamSpec = null;
			// only 40 key bits shall be effective for this test
			//rc2KeyWrapParamSpec = new RC2WrapParameterSpec(40);

			// first generate the RC2 content encryption key we want to wrap
			keyGen.init(keyLength);
			Key keyToWrap = keyGen.generateKey();
			System.out.println("Key to wrap:");
			System.out.println(Util.toString(keyToWrap.getEncoded()));

			// encrypt something with the original key 
			Cipher cec = Cipher.getInstance("RC2/CBC/PKCS5Padding", "IAIK");
			cec.init(Cipher.ENCRYPT_MODE, keyToWrap);
			byte[] plain = "Encrypt this message".getBytes();
			byte[] encrypted = cec.doFinal(plain);
			AlgorithmParameters params = cec.getParameters();

			// wrap the key
			Cipher cipher1 = Cipher.getInstance(keyWrapAlgorithm, "IAIK");
			cipher1.init(Cipher.WRAP_MODE, kek, rc2KeyWrapParamSpec);
			// get the parameters:
			AlgorithmParameters rc2KeyWrapParameters = cipher1.getParameters();
			byte[] wrappedKey = cipher1.wrap(keyToWrap);
			System.out.println("Wrapped key:");
			System.out.println(Util.toString(wrappedKey));

			// in the real world the wrapped key would now be sent to the
			// other peer in some way.

			// the recipient unwraps the key
			Cipher cipher2 = Cipher.getInstance(keyWrapAlgorithm, "IAIK");
			cipher2.init(Cipher.UNWRAP_MODE, kek, rc2KeyWrapParameters);
			Key unwrappedKey = cipher2.unwrap(wrappedKey, keyAlgorithm, keyType);
			System.out.println("Key unwrapped:");
			System.out.println(Util.toString(unwrappedKey.getEncoded()));

			if (CryptoUtils
			    .secureEqualsBlock(keyToWrap.getEncoded(), unwrappedKey.getEncoded())) {
				System.out.println("Wrap-Unwrap successful!");
			} else {
				System.out.println("Wrap-Unwrap failed!");
			}

			// decrypt it with the unwrapped key
			cec = Cipher.getInstance("RC2/CBC/PKCS5Padding", "IAIK");
			cec.init(Cipher.DECRYPT_MODE, unwrappedKey, params);
			byte[] decrypted = cec.doFinal(encrypted);
			if (CryptoUtils.equalsBlock(plain, decrypted)) {
				System.out.println("Encrypt - decrypt successful!");
			} else {
				throw new Exception("Encrypt - decrypt failed!");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);
		(new RC2KeyWrapping()).start();
		iaik.utils.Util.waitKey();
	}

}
