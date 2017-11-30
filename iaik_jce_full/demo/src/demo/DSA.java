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

import iaik.security.provider.IAIK;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

/**
 * DSA signature demo.
 */
public class DSA implements IAIKDemo {

	/**
	 * Generates a DSA key pair, calculates and verifies a DSA signature.
	 * 
	 * @param algorithm
	 *          the algorithm to be used
	 * 
	 * @return <code>true</code> if verification is successful, <code>false</code>
	 *         if it fails
	 * 
	 * @throws Exception
	 *           if an error occurs
	 */
	public boolean signAndVerify(String algorithm, KeyPair keyPair)
	    throws Exception
	{

		/*
		 * generate KeyPair with standard keysize 1024 bits for SHA1withDSA and 2048
		 * bits for SHA224withDSA and SHA256withDSA - keysize can be modified by
		 * calling method initialize
		 */
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm, "IAIK");
		keyPair = keyGenerator.generateKeyPair();

		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		// create message that should be signed and verified
		byte[] message = "Message to be signed".getBytes();

		Signature dsa = Signature.getInstance(algorithm, "IAIK");

		// init Signature object with private key
		dsa.initSign(privateKey);

		// create the signature
		dsa.update(message);
		byte[] dsasig = dsa.sign();

		// prepare for verification of signature
		dsa.initVerify(publicKey);
		dsa.update(message);

		// verify signature
		if (dsa.verify(dsasig)) {
			System.out.println("Signature with " + algorithm + " was successfully verified.");
			return true;
		}

		System.out.println("Signature with " + algorithm + " could not be verified.");
		return false;
	}

	/**
	 * Starts the demo.
	 */
	public void start() {
		try {
			boolean ok = true;

			ok &= signAndVerify("SHA1withDSA", null);
			ok &= signAndVerify("SHA224withDSA", null);
			ok &= signAndVerify("SHA256withDSA", null);

			if (ok) {
				System.out.println("DSA Demo OK! No ERRORS found!\n");
			} else {
				throw new RuntimeException("DSA demo NOT OK! There were ERRORS!!!");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Main method.
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);

		(new DSA()).start();
		iaik.utils.Util.waitKey();
	}

}
