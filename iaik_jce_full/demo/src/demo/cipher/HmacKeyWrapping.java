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

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import demo.IAIKDemo;

/**
 * This example demonstrates the use of the CMS HMACwith3DESwrap and
 * HMACwithAESwrap cipher.
 * <p>
 * This example shows how this API can be used to encrypt (wrap) a HMAC key
 * with a TripleDES / AES key encryption key by using the HMACwith3DESwrap /
 * HMACwithAESwrap key wrap cipher specified in RFC 3537.
 * 
 * @version File Revision <!-- $$Revision: --> 5 <!-- $ -->
 */
public class HmacKeyWrapping implements IAIKDemo {

	/** 
	 * Default constructor.
	 */
	public HmacKeyWrapping() {
		// empty
	}

	public void start() {
		System.out.println("**** Wrapping HMAC key with 3DES ****");
		start("3DESwrapHMAC");
		System.out.println("**** Wrapping HMAC key with AES ****");
		start("AESwrapHMAC");
	}

	public void start(String keyWrapAlg) {

		try {
			//  test data
			byte[] data = "This is a test message".getBytes();

			// generate the TripleDES Key Encryption Key (KEK)
			KeyGenerator kg = KeyGenerator.getInstance("DESede", "IAIK");
			SecretKey kek = kg.generateKey();

			// generate the HMAC key we want to wrap
			kg = KeyGenerator.getInstance("HmacSHA1", "IAIK");
			Key hmacKey = kg.generateKey();
			System.out.println("Key to wrap:");
			System.out.println(Util.toString(hmacKey.getEncoded()));

			// calculate a MAC on some data
			Mac mac = Mac.getInstance("HmacSHA1", "IAIK");
			mac.init(hmacKey);
			byte[] macValue = mac.doFinal(data);

			// wrap the key
			Cipher cipher1 = Cipher.getInstance(keyWrapAlg, "IAIK");
			cipher1.init(Cipher.WRAP_MODE, kek);
			byte[] wrappedKey = cipher1.wrap(hmacKey);
			System.out.println("Wrapped key:");
			System.out.println(Util.toString(wrappedKey));

			// in the real world the wrapped key would now be sent to the
			// other peer in some way.

			// the recipient unwraps the key
			Cipher cipher2 = Cipher.getInstance(keyWrapAlg, "IAIK");
			cipher2.init(Cipher.UNWRAP_MODE, kek);
			Key unwrappedKey = cipher2.unwrap(wrappedKey, "HmacSHA1", Cipher.SECRET_KEY);
			System.out.println("Unwrapped key:");
			System.out.println(Util.toString(unwrappedKey.getEncoded()));

			if (CryptoUtils.secureEqualsBlock(hmacKey.getEncoded(), unwrappedKey.getEncoded())) {
				System.out.println("Wrap-Unwrap successful!");
			} else {
				System.out.println("Wrap-Unwrap failed!");
			}

			// verify the MAC with the unwrapped key
			mac = Mac.getInstance("HmacSHA1", "IAIK");
			mac.init(unwrappedKey);
			byte[] macVal = mac.doFinal(data);

			if (CryptoUtils.secureEqualsBlock(macValue, macVal)) {
				System.out.println("Mac verification successful!");
			} else {
				throw new Exception("Mac verification failed!");
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
		(new HmacKeyWrapping()).start();
		iaik.utils.Util.waitKey();
	}

}
