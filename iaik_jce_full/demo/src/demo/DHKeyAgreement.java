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

package demo;

import iaik.security.random.SecRandom;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import demo.util.DemoUtil;

/**
 * This demo shows how to use Diffie-Hellman key agreement.
 * 
 * @version File Revision <!-- $$Revision: --> 19 <!-- $ -->
 */
public class DHKeyAgreement {

	// these are precomputed DH parameters
	BigInteger p = new BigInteger(
	    "da583c16d9852289d0e4af756f4cca92dd4be533b804fb0fed94ef9c8a4403ed574650d36999db29d776276ba2d3d412e218f4dd1e084cf6d8003e7c4774e833",
	    16);
	BigInteger g = BigInteger.valueOf(2);
	DHParameterSpec params;
	SecureRandom random;

	/**
	 * Default constructor.
	 */
	public DHKeyAgreement() {
		random = SecRandom.getDefault();
		params = new DHParameterSpec(p, g);
	}

	/**
	 * Starts the demo.
	 * 
	 * @return true if everything works fine, false otherwise
	 */
	public boolean start() {
		try {
			// 1. user1 creates his key pair
			System.out.println("Create key pair for user1...");
			User user1 = new User();
			// 2. user2 creates his key pair
			System.out.println("Create key pair for user2...");
			User user2 = new User();

			// 3. the public keys are sent to a public directory
			Key publicKeyUser1 = user1.getPublicKey();
			Key publicKeyUser2 = user2.getPublicKey();

			// 4. perform the key agreement with the public key of the other user
			byte[] secret1 = user1.agreeSecret(publicKeyUser2);
			byte[] secret2 = user2.agreeSecret(publicKeyUser1);

			// 5. now both users should have the same secret!
			System.out.println("Secret from user1: " + iaik.utils.Util.toString(secret1));
			System.out.println("Secret from user2: " + iaik.utils.Util.toString(secret2));
			System.out.println();

			// 6. the secrets must be equal otherwise there was an error
			if (iaik.utils.CryptoUtils.secureEqualsBlock(secret1, secret2)) {
				System.out.println("Now user1 and user2 share a common secret!");
				return true;
			}

			System.out.println("Diffie-Hellman key agreement ERROR!");
			return false;
		} catch (GeneralSecurityException ex) {
			System.out.println("Exception: " + ex.toString());
			return false;
		}
	}

	/**
	 * The main method for a stand-alone application.
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		(new DHKeyAgreement()).start();
		System.in.read();
	}

	/**
	 * This class implements an user who owns a Diffie-Hellman key pair. This key
	 * pair is used for the key agreement.
	 */
	class User {

		/**
		 * The key pair of this user.
		 */
		KeyPair key_pair;

		/**
		 * Default constructor. Creates a new DH key pair for this user.
		 * 
		 * @exception GeneralSecurityException
		 *              if there is a problem while generating the key pair
		 */
		public User()
		    throws GeneralSecurityException
		{
			try {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("DH", "IAIK");
				generator.initialize(params, random);
				key_pair = generator.generateKeyPair();

			} catch (InvalidAlgorithmParameterException ex) {
				throw new GeneralSecurityException(ex.toString());
			} catch (NoSuchAlgorithmException ex) {
				throw new GeneralSecurityException(ex.toString());
			} catch (NoSuchProviderException ex) {
				throw new GeneralSecurityException(ex.toString());
			}
		}

		/**
		 * Returns the public key of this user. This is equal to sending the key to
		 * an public directory.
		 */
		public Key getPublicKey() {
			return key_pair.getPublic();
		}

		/**
		 * This method uses the public key of the other user to agree on a common
		 * secret.
		 * 
		 * @param publicKey
		 *          the public key of the other user
		 * @return the shared secret (only used to compare the both secrets)
		 * 
		 * @exception GeneralSecurityException
		 *              if there occurs an error during the key agreement
		 */
		public byte[] agreeSecret(Key publicKey)
		    throws GeneralSecurityException
		{

			try {
				// get a new KeyAgreement object
				KeyAgreement key_agreement = KeyAgreement.getInstance("DH", "IAIK");
				// initialize it using the private key of the user
				key_agreement.init(key_pair.getPrivate());

				// there is just one phase if only 2 entities agree on a common key
				key_agreement.doPhase(publicKey, true);
				// now generate the shared secret
				byte[] secret = key_agreement.generateSecret();

				// and return the secret to compare it with the other secret
				return secret;

			} catch (InvalidKeyException ex) {
				throw new GeneralSecurityException(ex.toString());
			} catch (NoSuchProviderException ex) {
				throw new GeneralSecurityException(ex.toString());
			} catch (NoSuchAlgorithmException ex) {
				throw new GeneralSecurityException(ex.toString());
			}
		}
	}
}
