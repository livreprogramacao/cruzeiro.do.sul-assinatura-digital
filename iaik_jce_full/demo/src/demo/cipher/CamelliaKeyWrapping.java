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

import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import demo.IAIKDemo;
import demo.util.DemoUtil;

/**
 * This example demonstrates the use of the CMS Camellia Key wrap cipher.
 * <p>
 * This example shows how this API can be used to encrypt a symmetric Camellia
 * content encryption key with a Camellia key encryption key as defined by
 * <a href = "http://www.ietf.org/rfc/rfc3657" target="_blank">RFC 3657</a>.
 * 
 * @version File Revision <!-- $$Revision: --> 4 <!-- $ -->
 */
public class CamelliaKeyWrapping implements IAIKDemo {

	// static variables defining conventions previously agreed upon,
	// i.e. the algorithms to use
	private final static String keyWrapAlgorithm = "CamelliaWrapCamellia";
	private final static int keyType = Cipher.SECRET_KEY;
	private final static String keyAlgorithm = "Camellia";

	public CamelliaKeyWrapping() {
		// empty
	}

	public void start() {

		try {
			// generate the Camellia Key Encryption Key (KEK)
			KeyGenerator kg = KeyGenerator.getInstance(keyWrapAlgorithm);
			Key kek = kg.generateKey();

			// first generate the Camellia key we want to wrap
			// this will usually be a symmetric content encryption key
			kg = KeyGenerator.getInstance(keyAlgorithm);
			Key keyToWrap = kg.generateKey();
			System.out.println("Key to wrap:");
			System.out.println(Util.toString(keyToWrap.getEncoded()));

			// encrypt something with the original key 
			Cipher cec = Cipher.getInstance("Camellia/CBC/PKCS5Padding", "IAIK");
			cec.init(Cipher.ENCRYPT_MODE, keyToWrap);
			byte[] plain = "Encrypt this message".getBytes();
			byte[] encrypted = cec.doFinal(plain);
			byte[] iv = cec.getIV();

			// wrap the key
			Cipher cipher1 = Cipher.getInstance(keyWrapAlgorithm, "IAIK");
			cipher1.init(Cipher.WRAP_MODE, kek);
			byte[] wrappedKey = cipher1.wrap(keyToWrap);
			System.out.println("Wrapped key:");
			System.out.println(Util.toString(wrappedKey));

			// in the real world the wrapped key would now be sent to the
			// other peer in some way.

			// the recipient unwraps the key
			Cipher cipher2 = Cipher.getInstance(keyWrapAlgorithm, "IAIK");
			cipher2.init(Cipher.UNWRAP_MODE, kek);
			Key unwrappedKey = cipher2.unwrap(wrappedKey, keyAlgorithm, keyType);
			System.out.println("Key unwrapped:");
			System.out.println(Util.toString(unwrappedKey.getEncoded()));

			// compare with original key
			byte[] ktw = keyToWrap.getEncoded();
			if (CryptoUtils.secureEqualsBlock(ktw, unwrappedKey.getEncoded())) {
				System.out.println("Wrap-Unwrap successful!");
			} else {
				throw new Exception("Wrap-Unwrap failed!");
			}

			// decrypt with the unwrapped key
			cec = Cipher.getInstance("Camellia/CBC/PKCS5Padding", "IAIK");
			cec.init(Cipher.DECRYPT_MODE, unwrappedKey, new IvParameterSpec(iv));
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

		DemoUtil.initDemos();
		(new CamelliaKeyWrapping()).start();
		iaik.utils.Util.waitKey();
	}

}
