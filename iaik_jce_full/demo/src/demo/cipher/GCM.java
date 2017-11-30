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
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.IAIKDemo;

import iaik.security.cipher.GCMParameterSpec;
import iaik.security.provider.IAIK;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

/**
 * Demo to show how to use the AES Implementation.
 * key size: standard 128 bit
 * cipher mode: GCM
 * padding sheme: no padding
 *
 * @version File Revision <!-- $$Revision: --> 2 <!-- $ -->
 */
public class GCM implements IAIKDemo {

	/**
	 * Doing encryption and decryption using AES.
	 */
	public boolean demonstrateGCM()
	    throws Exception
	{

		//generating key with standard key size
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "IAIK");
		SecretKey key = keyGenerator.generateKey();

		//generating plain text to be encryped and decrypted
		byte[] plain_text = "My important secret message".getBytes("ASCII");

		System.out.println("Doing AES GCM ...");

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "IAIK");

		System.out.println("#########################################################");
		System.out.println("Encrypt without parameters:");
		//encryption with automatic generated nonce
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plain_text);

		System.out.println("Encrypted data: " + Util.toString(ciphertext));

		//get parameters to print MAC block, contrary to CCM the MAC block is saved as parameter
		//not attached to the ciphertext
		AlgorithmParameters params = cipher.getParameters();
		GCMParameterSpec specs = (GCMParameterSpec) params
		    .getParameterSpec(GCMParameterSpec.class);
		byte[] mac = specs.getMac();
		System.out.println("MAC block: " + Util.toString(mac));

		//decryption
		cipher.init(Cipher.DECRYPT_MODE, key, params);
		byte[] decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_text, decryptedtext)) {
			System.out.println("AES mode decryption error!");
			return false;
		}

		System.out.println("Decrypted data: " + new String(decryptedtext, "ASCII"));

		System.out.println("#########################################################");
		System.out.println("Encrypt with specified parameters:");

		//encrypt with more parameters,
		//e.g. header information that shall be authenticated, different MAC-length than default value (12 bytes)
		byte[] nonce = new byte[12];
		SecureRandom random = SecRandom.getDefault();
		random.nextBytes(nonce);
		specs = new GCMParameterSpec(Util.toByteArray("01:01:A2"), nonce, 16);

		//encryption with specified parameters
		cipher.init(Cipher.ENCRYPT_MODE, key, specs);
		ciphertext = cipher.doFinal(plain_text);

		System.out.println("Encrypted data: " + Util.toString(ciphertext));

		params = cipher.getParameters();
		specs = (GCMParameterSpec) params.getParameterSpec(GCMParameterSpec.class);
		mac = specs.getMac();
		System.out.println("MAC block: " + Util.toString(mac));
		specs = new GCMParameterSpec(Util.toByteArray("01:01:A2"), nonce, mac);
		cipher.init(Cipher.DECRYPT_MODE, key, specs);
		decryptedtext = cipher.doFinal(ciphertext);

		if (!CryptoUtils.equalsBlock(plain_text, decryptedtext)) {
			System.out.println("AES mode decryption error!");
			return false;
		}

		System.out.println("Decrypted data: " + new String(decryptedtext, "ASCII"));

		System.out.println("#########################################################");
		System.out.println("retrieve parameter details: ");

		params = cipher.getParameters();
		specs = (GCMParameterSpec) params.getParameterSpec(GCMParameterSpec.class);
		System.out.println("MAC block: " + Util.toString(specs.getMac()));
		System.out.println("Associated data " + Util.toString(specs.getAAD()));
		System.out.println("Nonce: " + Util.toString(specs.getNonce()));

		System.out.println("#########################################################");
		System.out.println("Encode GCM parameters nonce and MAC length:");
		//Associated data is not encoded, as the recipient should know e.g. header information anyway
		//and only needs to authenticate them;
		//the MAC block has to be provided by other means

		byte[] encoded = params.getEncoded();

		System.out.println("Encoded parameter: " + Util.toString(encoded));
		params = AlgorithmParameters.getInstance("GCM", "IAIK");
		params.init(encoded);
		specs = (GCMParameterSpec) params.getParameterSpec(GCMParameterSpec.class);
		System.out.println("Nonce: " + Util.toString(specs.getNonce()));
		System.out.println("MAC length: " + specs.getMacLength());

		System.out.println("#########################################################");

		return true;
	}

	public void start() {
		try {
			boolean ok = true;

			ok &= demonstrateGCM();

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

		(new GCM()).start();
		Util.waitKey();
	}
}
