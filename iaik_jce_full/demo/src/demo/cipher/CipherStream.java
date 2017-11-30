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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import demo.IAIKDemo;

import iaik.security.provider.IAIK;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;

/**
 * This class tests the CipherInputStream implementation.
 * <p>
 * A CipherInputStream combines the functionality of an InputStream and
 * a Cipher.
 * <p>
 * This class first initializes the CipherInputStream with a TripleDES cipher in
 * ENCRYPT mode for reading plain data from the input source thereby encrypting it
 * and writing the enctypted data to an OutputStream. Finally the CipherInputStream is
 * initialized with a TripleDES cipher in DECRYPT mode for reading back the
 * encrypted data and decrypting it again.
 *
 * @see javax.crypto.CipherInputStream
 * @version File Revision <!-- $$Revision: --> 17 <!-- $ -->
 */
public class CipherStream implements IAIKDemo {

	// Test data
	private byte[] data;
	// test data size
	private final static int BUFFER_SIZE = 2048 * 4;

	/**
	 * Default constructor.
	 */
	public CipherStream() {
		data = new byte[BUFFER_SIZE];
		Random rnd = new Random();
		rnd.nextBytes(data);
	}

	/**
	 * Starts the demo.
	 */
	public void start() {
		try {

			// temporary buffer
			byte[] tmp = new byte[1000];

			// create a new secret key
			KeyGenerator kg = KeyGenerator.getInstance("3DES", "IAIK");
			//  kg.init(112, null);          // 2 key triple DES
			kg.init(168, null); // 3 key triple DES
			Key key = kg.generateKey();
			byte[] iv = new byte[8];
			SecureRandom random = SecRandom.getDefault();
			random.nextBytes(iv);

			//
			// Encrypt
			//

			// create a new cipher object
			Cipher c = Cipher.getInstance("3DES/CBC/PKCS5Padding", "IAIK");
			c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), null);

			ByteArrayInputStream is = new ByteArrayInputStream(data);
			// create a new CipherInputStream
			CipherInputStream cis = new CipherInputStream(is, c);
			ByteArrayOutputStream os = new ByteArrayOutputStream();

			// read the data through the cipher input stream
			int r;
			while ((r = cis.read(tmp)) != -1)
				os.write(tmp, 0, r);

			cis.close();
			os.close();

			//
			// Decrypt
			//

			// initialize the cipher again
			c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv), null);
			is = new ByteArrayInputStream(os.toByteArray());
			// create a new CipherInputStream
			cis = new CipherInputStream(is, c);

			// don't forget to reset our output stream
			os.reset();
			// and readd the data again
			while ((r = cis.read(tmp)) != -1)
				os.write(tmp, 0, r);

			cis.close();
			os.close();

			// the decrypted data shall be same as the original data
			if (!CryptoUtils.equalsBlock(data, os.toByteArray())) {
				throw new RuntimeException("ERROR!");
			}

			System.out.println("Test O.K.!");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs the CipherInputStream test.
	 */
	public static void main(String[] args)
	    throws IOException
	{
		Security.insertProviderAt(new IAIK(), 2);
		(new CipherStream()).start();
		System.out.println("finished.");
		System.in.read();
	}
}
