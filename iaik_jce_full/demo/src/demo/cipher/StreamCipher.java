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
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import demo.IAIKDemo;

/**
 * This class demonstrates how to use blockwise encryption with cipher.update.
 * <p>
 * The Demo uses DES in CBC Mode with standard key size.
 *
 * @version File Revision <!-- $$Revision: --> 28 <!-- $ -->
 */
public class StreamCipher implements IAIKDemo {

	final static int plainTextLength = 2000;

	/**
	 * Doing encryption and decryption using DES.
	 * Plain text is generated randomly with 2000 byte length.
	 * Key ist generated with standard key size.
	 */
	public boolean blockwiseEncrypting()
	    throws Exception
	{

		//  generating key
		KeyGenerator keygenerator = KeyGenerator.getInstance("DES", "IAIK");
		SecretKey key = keygenerator.generateKey();

		//  generate random plain text
		SecureRandom random = SecRandom.getDefault();
		byte[] plainText_bytes = new byte[plainTextLength];
		random.nextBytes(plainText_bytes);
		ByteArrayInputStream plainText = new ByteArrayInputStream(plainText_bytes);
		System.out.println("Plain text: \n" + Util.toString(plainText_bytes) + "\n");

		//  generate cipher object     
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding", "IAIK");

		//  Blockwise encryption

		cipher.init(Cipher.ENCRYPT_MODE, key);

		System.out.println("Encrypted data: ");

		ByteArrayOutputStream encryptedDataBuffer = new ByteArrayOutputStream(1024);
		int bytesRead;
		byte[] buffer = new byte[1024];
		while ((bytesRead = plainText.read(buffer, 0, buffer.length)) >= 0) {
			byte[] dataPart = cipher.update(buffer, 0, bytesRead);
			if (dataPart != null) {
				encryptedDataBuffer.write(dataPart);
				System.out.print(Util.toString(dataPart));
			}
		}
		byte[] dataPart = cipher.doFinal();
		encryptedDataBuffer.write(dataPart);
		System.out.println(Util.toString(dataPart));
		System.out.println();

		//  Blockwise decryption

		byte[] iv = cipher.getIV();
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		System.out.println("Decrypted data: ");

		byte[] ciphertext_bytes = encryptedDataBuffer.toByteArray();
		ByteArrayInputStream cipherText = new ByteArrayInputStream(ciphertext_bytes);

		ByteArrayOutputStream decryptedDataBuffer = new ByteArrayOutputStream(1024);
		while ((bytesRead = cipherText.read(buffer, 0, buffer.length)) >= 0) {
			dataPart = cipher.update(buffer, 0, bytesRead);
			if (dataPart != null) {
				decryptedDataBuffer.write(dataPart);
				System.out.print(Util.toString(dataPart));
			}
		}
		dataPart = cipher.doFinal();
		decryptedDataBuffer.write(dataPart);
		System.out.println(Util.toString(dataPart));
		System.out.println();

		//  are the two plain blocks equal ?

		byte[] decryptedText_bytes = decryptedDataBuffer.toByteArray();

		if (!CryptoUtils.equalsBlock(plainText_bytes, decryptedText_bytes)) {
			System.out.println("DES decryption Error!");
			return false;
		}

		return true;
	}

	public void start() {
		try {
			boolean ok = true;
			ok &= blockwiseEncrypting();
			if (ok) System.out.println("Blockwise Encryption OK! No ERRORS found!\n");
			else throw new RuntimeException("Blockwise Encryption NOT OK! There were ERRORS!!!");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the Demo to show blockwise encryption of Streamciphers using DES in CBC Mode.
	 *
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);

		(new StreamCipher()).start();
		iaik.utils.Util.waitKey();
	}
}
