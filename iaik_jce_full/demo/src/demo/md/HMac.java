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

package demo.md;

import iaik.security.provider.IAIK;

import java.io.IOException;
import java.security.Security;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import demo.IAIKDemo;

/**
 * This class tests HMac implementation as specified in <a href =
 * "http://www.ietf.org/rfc/rfc2104.txt" target="_blank">RFC&nbsp;2104</a>.
 * <p>
 * 
 * @version File Revision <!-- $$Revision: --> 23 <!-- $ -->
 */
public class HMac implements IAIKDemo {

	private Random random;

	/**
	 * Default Constructor.
	 */
	public HMac() {
		random = new Random();
	}

	/**
	 * Computes the HMAC on the given data using the given key, and compares the
	 * result with the given pre-computed correct value.
	 * 
	 * @param algorithm
	 *          the HMAC algorithm to be used, e.g. "HMAC/SHA-1"
	 * @param key
	 *          the key data to be used for generating a secret key necessary for
	 *          MAC computation
	 * @param data
	 *          the data on which the MAC shall be computed
	 * @param correct
	 *          the pre-computed correct value for verifying the rseult of the MAC
	 *          computation
	 * 
	 * @return <code>true</code> if the MAC computation yields the correct result
	 *         <code>false</code> otherwise
	 */
	public boolean hmac(String algorithm, byte[] key, byte[] data, byte[] correct)
	    throws Exception
	{
		Mac mac = Mac.getInstance(algorithm, "IAIK");
		mac.init(new SecretKeySpec(key, "RAW"));

		byte[] result = mac.doFinal(data);

		boolean ok = true;
		ok &= iaik.utils.CryptoUtils.secureEqualsBlock(correct, result);
		// second call with the same key
		result = mac.doFinal(data);
		ok &= iaik.utils.CryptoUtils.secureEqualsBlock(correct, result);
		// third call with the same key; initialized again
		mac.init(new SecretKeySpec(key, "RAW"));
		result = mac.doFinal(data);
		ok &= iaik.utils.CryptoUtils.secureEqualsBlock(correct, result);

		return ok;
	}

	/**
	 * Repeatetly computes a HMAC on the given data and compares if the result is
	 * always the same.
	 * 
	 * @param algorithm
	 *          the HMAC algorithm to be used, e.g. "HMAC/SHA-1"
	 * @param data
	 *          the data on which the MAC shall be computed
	 * @param keyLength
	 *          the length of the key to be used
	 * 
	 * @return <code>true</code> if the test succeeds, <code>false</code>
	 *         otherwise
	 */
	public boolean hmac(String algorithm, byte[] data, int keyLength)
	    throws Exception
	{

		System.out.println("Doing " + algorithm);

		KeyGenerator kg = KeyGenerator.getInstance(algorithm, "IAIK");
		kg.init(keyLength * 8);
		SecretKey secretKey = kg.generateKey();
		byte[] key = secretKey.getEncoded();
		if (key.length != keyLength) {
			throw new Exception(algorithm + " KeyGenerator generated key with wrong length!");
		}

		Mac mac = Mac.getInstance(algorithm, "IAIK");
		mac.init(secretKey);
		byte[] result = mac.doFinal(data);

		boolean ok = true;
		// second call with the same key
		ok &= iaik.utils.CryptoUtils.secureEqualsBlock(result, mac.doFinal(data));
		// third call with the same key; initialized again
		mac.init(new SecretKeySpec(key, "RAW"));
		ok &= iaik.utils.CryptoUtils.secureEqualsBlock(result, mac.doFinal(data));

		return ok;
	}

	/**
	 * Demonstrates the HMAC algorithm implementation.
	 */
	public void start() {

		try {
			boolean ok = true;
			ok &= hmacMd5();

			ok &= hmacAll();

			if (!ok) throw new RuntimeException("HMac NOT OK! ERRORS found!");

			System.out.println("HMac OK! No ERRORS found!\n");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}

	}

	/**
	 * Tests the HMAC algorithm using Md5 for hash computation.
	 * 
	 * @return <code>true</code> if the test yields the correct result,
	 *         <code>false</code> otherwise
	 */
	public boolean hmacMd5()
	    throws Exception
	{

		boolean ok = true;

		byte[] key1 = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		    0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
		byte[] data1 = "Hi There".getBytes();
		byte[] digest1 = { (byte) 0x92, (byte) 0x94, (byte) 0x72, (byte) 0x7a, (byte) 0x36,
		    (byte) 0x38, (byte) 0xbb, (byte) 0x1c, (byte) 0x13, (byte) 0xf4, (byte) 0x8e,
		    (byte) 0xf8, (byte) 0x15, (byte) 0x8b, (byte) 0xfc, (byte) 0x9d };

		byte[] key2 = "Jefe".getBytes();
		byte[] data2 = "what do ya want for nothing?".getBytes();
		byte[] digest2 = { (byte) 0x75, (byte) 0x0c, (byte) 0x78, (byte) 0x3e, (byte) 0x6a,
		    (byte) 0xb0, (byte) 0xb5, (byte) 0x03, (byte) 0xea, (byte) 0xa8, (byte) 0x6e,
		    (byte) 0x31, (byte) 0x0a, (byte) 0x5d, (byte) 0xb7, (byte) 0x38 };

		byte[] key3 = { (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
		    (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
		    (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA };
		byte[] data3 = new byte[50];
		for (int i = 0; i < 50; i++)
			data3[i] = (byte) 0xDD;
		byte[] digest3 = { (byte) 0x56, (byte) 0xbe, (byte) 0x34, (byte) 0x52, (byte) 0x1d,
		    (byte) 0x14, (byte) 0x4c, (byte) 0x88, (byte) 0xdb, (byte) 0xb8, (byte) 0xc7,
		    (byte) 0x33, (byte) 0xf0, (byte) 0xe8, (byte) 0xb3, (byte) 0xf6 };

		ok &= hmac("HMAC/MD5", key1, data1, digest1);
		ok &= hmac("HMAC/MD5", key2, data2, digest2);
		ok &= hmac("HMAC/MD5", key3, data3, digest3);

		return ok;

	}

	/**
	 * Tests the HMAC algorithm for several hash algorithms.
	 * 
	 * @return <code>true</code> if the test yields the correct result,
	 *         <code>false</code> otherwise
	 */
	public boolean hmacAll()
	    throws Exception
	{

		boolean ok = true;

		byte[] data = new byte[1024];
		random.nextBytes(data);

		ok &= hmac("HMAC/MD5", data, 16);
		ok &= hmac("HMAC/SHA-1", data, 20);
		ok &= hmac("HMAC/SHA-224", data, 28);
		ok &= hmac("HMAC/SHA-256", data, 32);
		ok &= hmac("HMAC/SHA-384", data, 48);
		ok &= hmac("HMAC/SHA-512", data, 64);
		ok &= hmac("HMAC/RIPEMD128", data, 16);
		ok &= hmac("HMAC/RIPEMD160", data, 20);
		ok &= hmac("HMAC/WHIRLPOOL", data, 64);
	
		return ok;

	}

	/**
	 * Performs some tests for HMAC.
	 */
	public static void main(String arg[])
	    throws IOException
	{

		Security.insertProviderAt(new IAIK(), 2);
		(new HMac()).start();
		System.in.read();
	}
}
