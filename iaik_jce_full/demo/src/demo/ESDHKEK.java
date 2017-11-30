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

import iaik.asn1.structures.AlgorithmID;
import iaik.security.dh.ESDHKEKParameterSpec;
import iaik.security.dh.ESDHPublicKey;
import iaik.security.random.SecRandom;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import demo.util.DemoUtil;

/**
 * This demo shows how to use Ephemeral-Static Diffie-Hellman key agreement
 * algorithm (<a href = "http://www.ietf.org/rfc/rfc2631.txt"
 * target="_blank">RFC 2631</a>) for generating a shared secret key encryption
 * key. The demo runs in static-static mode, where the sender uses a static DH
 * key from a certificate.
 * <p>
 * Please note that this demo uses DHParameterSpec and ESDHParameterSpec, the
 * first for representing the DH parameters p and g (used for key generation),
 * and the latter used for initializing the ESDHKeyAgreement with the RFC 2631
 * OtherInfo!
 * 
 * @version File Revision <!-- $$Revision: --> 17 <!-- $ -->
 */
public class ESDHKEK implements IAIKDemoWithResult {

	SecureRandom random;

	/**
	 * Default constructor.
	 */
	public ESDHKEK() {
		random = SecRandom.getDefault();
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
			User user1 = new User(null);
			// 2. user2 creates his key pair
			System.out.println("Create key pair for user2...");
			User user2 = new User(((ESDHPublicKey) user1.getPublicKey()).getParams());

			// 3. the public keys are sent to a public directory
			Key publicKeyUser1 = user1.getPublicKey();
			Key publicKeyUser2 = user2.getPublicKey();

			// we use static-static mode and therefore need a random PartyAInfo:
			byte[] partyAInfo = new byte[64];
			random.nextBytes(partyAInfo);

			// 4. perform the key agreement with the public key of the other user
			SecretKey secretKey1 = user1.agreeSecret(publicKeyUser2, partyAInfo);
			SecretKey secretKey2 = user2.agreeSecret(publicKeyUser1, partyAInfo);

			// 5. now both users should have the same secret key!
			System.out.println("Secret key from user1: " + secretKey1);
			System.out.println("Secret key from user2: " + secretKey2);
			System.out.println();

			// 6. the secret keys must be equal otherwise there was an error
			if (iaik.utils.CryptoUtils.secureEqualsBlock(secretKey1.getEncoded(),
			    secretKey2.getEncoded())) {
				System.out.println("Now user1 and user2 share a common secret key!");
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
	 * The main method for a standalone application.
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		(new ESDHKEK()).start();
		System.in.read();
	}

	/**
	 * This class implements a user who owns a Diffie-Hellman key pair. This key
	 * pair is used for the key agreement.
	 */
	class User {

		/**
		 * The key pair of this user.
		 */
		KeyPair key_pair;

		/**
		 * Default constructor. Creates a new ESDH key pair for this user.
		 * 
		 * @param paramSpec
		 *          any parameters the ESDHKeyPairGenerator shall be initialized
		 *          with
		 * 
		 * @exception GeneralSecurityException
		 *              if there is a problem while generating the key pair
		 */
		public User(AlgorithmParameterSpec paramSpec)
		    throws GeneralSecurityException
		{
			try {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("ESDH", "IAIK");
				if (paramSpec == null) {
					generator.initialize(512, random);
				} else {
					generator.initialize(paramSpec, random);
				}
				key_pair = generator.generateKeyPair();

			} catch (NoSuchAlgorithmException ex) {
				throw new GeneralSecurityException(ex.toString());
			} catch (NoSuchProviderException ex) {
				throw new GeneralSecurityException(ex.toString());
			}
		}

		/**
		 * Returns the public key of this user. This is equal to sending the key to
		 * a public directory.
		 */
		public Key getPublicKey() {
			return key_pair.getPublic();
		}

		/**
		 * This method uses the public key of the other user to create a common
		 * secret key encryption key.
		 * 
		 * @param publicKey
		 *          the public key of the other user
		 * @param partyAInfo
		 *          a random string from the sender
		 * @return the shared secret key
		 * 
		 * @exception GeneralSecurityException
		 *              if there occurs an error during the key agreement
		 */
		public SecretKey agreeSecret(Key publicKey, byte[] partyAInfo)
		    throws GeneralSecurityException
		{

			try {

				// we want TripleDES key wrap
				AlgorithmID tripleDesWrap = AlgorithmID.cms_3DES_wrap;
				// key length of KEK:
				int keyLength = 192;
				// generate the OtherInfo
				ESDHKEKParameterSpec otherInfo = new ESDHKEKParameterSpec(
				    tripleDesWrap.getAlgorithm(), keyLength);
				otherInfo.setPartyAInfo(partyAInfo);

				// get a new KeyAgreement object
				KeyAgreement key_agreement = KeyAgreement.getInstance("ESDH", "IAIK");
				// initialize it using the private key of the user
				key_agreement.init(key_pair.getPrivate(), otherInfo, random);

				// there is just one phase if only 2 entities agree on a common key
				key_agreement.doPhase(publicKey, true);
				// now generate the shared secret key
				SecretKey secretKey = key_agreement.generateSecret("3DES");

				// and return the secret to compare it with the other secret
				return secretKey;

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
