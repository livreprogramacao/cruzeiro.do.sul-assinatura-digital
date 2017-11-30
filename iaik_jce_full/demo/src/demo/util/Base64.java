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

package demo.util;

import iaik.utils.Base64InputStream;
import iaik.utils.Base64OutputStream;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import demo.IAIKDemo;

/**
 * Tests the Base64 implementation.
 * <P>
 * First the encoding/decoding process is observed by means of some ASCII
 * strings. Subsequently random chosen data serves as input to create an Base64
 * encoded output stream writing the encoded data to a "test\Base64Test.txt"
 * file. The Base64InputStream test reads the encoded data from this file,
 * decodes it, and compares it with the original plain data.
 * 
 * @version File Revision <!-- $$Revision: --> 12 <!-- $ -->
 */
public class Base64 implements IAIKDemo {

	// number of random bytes
	private final static int SIZE = 1024;

	// the random test data
	private static final byte[] data = new byte[SIZE];

	/**
	 * Tests the Base64InputStream implementation by reading BASE64 encoded data
	 * from a stream, decoding it, and comparing the recovered data with the
	 * original data.
	 * <p>
	 * 
	 * @param is
	 *          the stream from which the BASE64 encoded data is read
	 * @exception IOException
	 *              if a read error occurs
	 * @see iaik.utils.Base64InputStream
	 */
	public void testBase64InputStream(InputStream is)
	    throws IOException
	{

		System.out.println("Test Base64InputStream...");
		// create a BASE64 input stream
		final Base64InputStream b64is = new Base64InputStream(is);
		// create a buffer for reading the data
		final byte[] buffer = new byte[2 * SIZE];
		// read and decode the data
		final int len = b64is.read(buffer);
		// compare the read data against the original data
		if (!CryptoUtils.equalsBlock(data, 0, buffer, 0, len)) {
			throw new RuntimeException("Base64 In/OutputStream Error!");
		}
	}

	/**
	 * Tests the Base64OutputStream implementation by BASE64 encoding randomly
	 * generated data and writing it to a stream.
	 * 
	 * @param os
	 *          the stream to which the BASE64 encoded data shall be written
	 * @exception IOException
	 *              if an write error occurs
	 * 
	 * @see iaik.utils.Base64OutputStream
	 */
	public void testBase64OutputStream(OutputStream os)
	    throws IOException
	{

		System.out.println("Test Base64OutputStream...");

		// create a new BASE64 output stream
		final Base64OutputStream b64os = new Base64OutputStream(os);
		// and write the test data to it
		b64os.write(data);
		// close is important for adding padding
		b64os.close();
	}

	/**
	 * Tests the correctness of the Base64 implementation.
	 * <P>
	 * Given are two arrays of ASCII-strings indicating the plain and the
	 * corresponding BASE64 encoded data. First the encoding process is tested by
	 * encoding the plain data and comparing it with the given BASE64 encoded
	 * data. Subsequently the result of the encoding process is decoded and
	 * checked against the original plain data.
	 * 
	 * @exception IOException
	 *              if an I/O error occurs
	 */
	public void testBase64()
	    throws IOException
	{

		final byte[][] plain = new byte[2][];
		final byte[][] base64 = new byte[2][];

		plain[0] = "joe:eoj".getBytes();
		plain[1] = "12345678:87654321".getBytes();
		base64[0] = "am9lOmVvag==".getBytes();
		base64[1] = "MTIzNDU2Nzg6ODc2NTQzMjE=".getBytes();

		System.out.println("Test Base64 encode/decode...");

		for (int i = 0; i < 2; i++) {
			System.out.println("Test " + i + "...");

			final byte[] myBase64 = Util.Base64Encode(plain[i]);

			for (int j = 0; j < myBase64.length; j++) {
				if (!CryptoUtils.equalsBlock(myBase64, base64[i])) {
					throw new RuntimeException("Base64 encoding Error!");
				}
			}

			final byte[] myPlain = Util.Base64Decode(myBase64);

			for (int j = 0; j < myPlain.length; j++) {
				if (!CryptoUtils.equalsBlock(myPlain, plain[i])) {
					throw new RuntimeException("Base64 decoding Error!");
				}
			}
		}
		System.out.println();
	}

	/**
	 * Tests the Base64 implementation.
	 * <P>
	 * First the encoding/decoding process is observed by means of some ASCII
	 * strings. Subsequently random chosen data serves as input to create an
	 * Base64 encoded output stream writing the encoded data to a
	 * "test\Base64Test.txt" file. The Base64InputStream test reads the encoded
	 * data from this file, decodes it, and compares it with the original plain
	 * data.
	 */
	public void start() {

		try {
			// SIZE bytes random data
			final Random random = new Random();
			random.nextBytes(data);

			// default test
			testBase64();
			// stream test
			final ByteArrayOutputStream os = new ByteArrayOutputStream();
			testBase64OutputStream(os);
			testBase64InputStream(new ByteArrayInputStream(os.toByteArray()));

			System.out.println("TestBase64 OK! No ERRORS found!\n");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs some tests for the Base64 implementation.
	 */
	public static void main(String arg[]) {
		(new Base64()).start();
		iaik.utils.Util.waitKey();
	}
}
