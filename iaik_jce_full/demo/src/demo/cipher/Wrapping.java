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

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import demo.IAIKDemo;

import iaik.security.provider.IAIK;
import iaik.security.random.SecRandom;
import iaik.utils.Util;

/**
 * This example demonstrates the use of key wrapping introduced by Sun in
 * their JCE 1.2.1 API.
 * <p>
 * The point of that API is basically to define a way to encrypt and decrypt
 * keys instead of byte arrays. Internally this will usually we implemented
 * simply by encoding the key and then encrypting the byte array and vice
 * versa for decryption.
 * <p>
 * This example shows how this API can be used to easily exchange a symmetric
 * content encryption key (e.g. Triple DES) using RSA and key wrapping.
 * Note that key wrapping can be used to wrap public, private, and secret keys
 * and that all symmetric ciphers and the RSA cipher support key wrapping
 * in the IAIK JCE.
 * @version File Revision <!-- $$Revision: --> 9 <!-- $ -->
 */
public class Wrapping implements IAIKDemo {

	// static variables defining conventions previously agreed upon,
	// i.e. the algorithms to use
	private final static String encryptionAlgorithm = "RSA/ECB/PKCS1Padding";
	private final static int keyType = Cipher.SECRET_KEY;
	private final static String keyAlgorithm = "DESede";

	public Wrapping() {
		// empty
	}

	public void start() {

		try {
			SecureRandom random = SecRandom.getDefault();

			// generate the key pair for the key exchange
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "IAIK");
			kpg.initialize(512, random);
			KeyPair kp = kpg.generateKeyPair();

			// first generate the Triple DES we want to wrap
			// this will usually be a symmetric content encryption key
			byte[] b = new byte[24];
			random.nextBytes(b);
			Key keyToWrap = new SecretKeySpec(b, keyAlgorithm);
			System.out.println("Key to wrap:");
			System.out.println(Util.toString(keyToWrap.getEncoded()));

			// wrap the key, i.e. encrypt it using the recipient's RSA public key
			Cipher cipher1 = Cipher.getInstance(encryptionAlgorithm, "IAIK");
			cipher1.init(Cipher.WRAP_MODE, kp.getPublic());
			byte[] wrappedKey = cipher1.wrap(keyToWrap);
			System.out.println("Wrapped key:");
			System.out.println(Util.toString(wrappedKey));

			// in the real world the wrapped key would now be sent to the
			// other peer in some way.

			// the recipient unwraps the key using its RSA private key
			Cipher cipher2 = Cipher.getInstance(encryptionAlgorithm, "IAIK");
			cipher2.init(Cipher.UNWRAP_MODE, kp.getPrivate());
			Key unwrappedKey = cipher2.unwrap(wrappedKey, keyAlgorithm, keyType);
			System.out.println("Key unwrapped:");
			System.out.println(Util.toString(unwrappedKey.getEncoded()));

			// now both peers have the same symmetric key, exchanged securely via RSA
			// they can now use it for content encryption

			// NOTE: of course this is only secure if the public key was distributed
			//       securely. This may be achieved using certificates.
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);
		(new Wrapping()).start();
		iaik.utils.Util.waitKey();

	}
}
