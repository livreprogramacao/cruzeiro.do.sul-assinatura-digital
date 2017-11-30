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
import iaik.utils.Util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class AESSpeedTest {

	private final static int TYPE_CIPHER_ENCRYPT = 1;
	private final static int TYPE_CIPHER_DECRYPT = 2;
	private final static int TYPE_SETUP_ENCRYPT = 3;
	private final static int TYPE_SETUP_DECRYPT = 4;

	private final static String CIPHER_MODE = "/ECB/NoPadding";

	private final static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
	private final static int DECRYPT_MODE = Cipher.DECRYPT_MODE;

	private final static int CHUNKSIZE = 1024;

	private final static int ENCRYPTIONS_PER_TEST = 1024 * 2;

	private final static int CRYPT_MEASUREMENTS = 128;

	private final static int SETUP_MEASUREMENTS = 128;
	private final static int SETUP_REPETITIONS = 1024;
	private final static int SETUP_KEYS = 32;

	private final static int INITIAL_SKIP = 2;

	private final String algorithmName;
	private final int type;
	private final int keyLength;
	private int mode;

	private final byte[] testArray = new byte[CHUNKSIZE];

	public AESSpeedTest(String algorithmName, int type, int keyLength) {
		this.algorithmName = algorithmName;
		this.type = type;
		this.keyLength = keyLength;
		if ((type == TYPE_CIPHER_ENCRYPT) || (type == TYPE_SETUP_ENCRYPT)) {
			mode = ENCRYPT_MODE;
		} else if ((type == TYPE_CIPHER_DECRYPT) || (type == TYPE_SETUP_DECRYPT)) {
			mode = DECRYPT_MODE;
		} else {
			throw new IllegalArgumentException("Invalid test type: " + type);
		}
	}

	public void runTests(PrintStream out)
	    throws Exception
	{
		runTests(new PrintWriter(out));
	}

	public void runTests(PrintWriter out)
	    throws Exception
	{
		if (type <= TYPE_CIPHER_DECRYPT) {
			cryptTest(out);
		} else {
			keysetupTest(out);
		}
	}

	public void keysetupTest(PrintWriter out)
	    throws Exception
	{
		final boolean encrypt = (mode == ENCRYPT_MODE);
		System.out.println("Running key setup speed test for algorithm " + algorithmName
		    + "/" + (keyLength * 8) + "...");
		final byte[] key = new byte[keyLength];
		final int n = SETUP_MEASUREMENTS;
		final int[] results = new int[n];
		final Random random = new Random();
		final int m = SETUP_KEYS;
		for (int i = -1 * INITIAL_SKIP; i < n; i++) {
			final Cipher cipher = Cipher.getInstance(algorithmName + CIPHER_MODE, "IAIK");
			final SecretKeySpec[] keys = new SecretKeySpec[m];
			for (int j = 0; j < m; j++) {
				random.nextBytes(key);
				keys[j] = new SecretKeySpec(key, algorithmName);
			}
			final int result = runSetupTest(cipher, keys);
			if (i >= 0) {
				results[i] = result;
			}
		}
		final int opsPerResult = m * SETUP_REPETITIONS;
		final String text = pad("Final " + (encrypt ? "en" : "de") + "/setup result for "
		    + algorithmName + "/" + (keyLength * 8) + ": ", 40);
		showResults(text, " keys/second", results, opsPerResult, 1000);
	}

	private int runSetupTest(Cipher cipher, SecretKeySpec[] keys)
	    throws Exception
	{
		final long n = SETUP_REPETITIONS;
		long time = System.currentTimeMillis();
		final AlgorithmParameterSpec algSpec = null;
		for (int j = 0; j < keys.length; j++) {
			for (int i = 0; i < n; i++) {
				cipher.init(mode, keys[j], algSpec, null);
			}
		}
		time = System.currentTimeMillis() - time;
		System.out.println("Time elapsed: " + (time / 1000.0) + "; "
		    + ((n * keys.length * 1000) / (time)) + " keys/second");
		runGC(false);
		return (int) time;
	}

	public void cryptTest(PrintWriter out)
	    throws Exception
	{
		final boolean encrypt = (mode == ENCRYPT_MODE);
		final String crypt = (encrypt ? "en" : "de") + "cryption";
		System.out.println("Running " + crypt + " speed test for algorithm " + algorithmName
		    + "/" + (keyLength * 8) + "...");
		final byte[] key = new byte[keyLength];
		final int n = CRYPT_MEASUREMENTS;
		final int[] results = new int[n];
		final Random random = new Random();
		for (int i = -1 * INITIAL_SKIP; i < n; i++) {
			final Cipher cipher = Cipher.getInstance(algorithmName + CIPHER_MODE, "IAIK");
			random.nextBytes(testArray);
			random.nextBytes(key);
			final SecretKeySpec keySpec = new SecretKeySpec(key, algorithmName);
			cipher.init(mode, keySpec);
			final int result = runTest(cipher);
			if (i >= 0) {
				results[i] = result;
			}
		}
		final int opsPerResult = 8 * ENCRYPTIONS_PER_TEST * testArray.length;
		final String text = pad("Final " + (encrypt ? "en" : "de") + "cipher result for "
		    + algorithmName + "/" + (keyLength * 8) + ": ", 40);
		showResults(text, " * 1000 bits/second", results, opsPerResult, 1);
	}

	private void showResults(String text,
	                         String opname,
	                         int[] results,
	                         int opsPerResult,
	                         int mult)
	    throws Exception
	{
		long totalTime, totalCount;

		totalTime = 0;
		final int n = results.length;
		for (int i = 0; i < n; i++) {
			totalTime += results[i];
		}
		totalCount = (long) n * opsPerResult;
		final double mean = ((double) totalTime) / n;
		System.out.println("Mean time: " + mean + " ms");
		System.out.println("Mean speed: " + ((mult * totalCount) / totalTime) + opname);

		Util.bubbleSort(results);
		final int median = results[(results.length + 1) / 2];
		System.out.println("Median: " + median + " ms");

		final double dev = stdDev(mean, results);
		System.out.println("Standard deviation: " + dev);

		final double min = median - (3 * dev);
		final double max = median + (3 * dev);
		totalTime = 0;
		int remaining = 0;
		for (int i = 0; i < n; i++) {
			final int t = results[i];
			if ((t >= min) && (t <= max)) {
				remaining++;
				totalTime += t;
			}
		}
		System.out.println("Remaining measurements: " + remaining);
		totalCount = (long) remaining * opsPerResult;
		final long rate = (mult * totalCount) / totalTime;
		final String resultString = text + rate + opname;
		System.out.println(resultString);
		try {
			final OutputStream os = new FileOutputStream("aes/allresults.txt", true);
			final PrintWriter pw = new PrintWriter(os);
			pw.println(resultString);
			pw.flush();
			pw.close();
			os.close();
		} catch (final IOException e) {
			System.err.println("Could not append results: ");
			e.printStackTrace(System.err);
		}
	}

	private static String pad(String s, int length) {
		while (s.length() < length) {
			s = s + " ";
		}
		return s;
	}

	private static double stdDev(double m, int[] values) {
		double sum = 0;
		final int n = values.length;
		for (int i = 0; i < n; i++) {
			final double t = (m - values[i]);
			sum += t * t;
		}
		final double var = sum / n;
		return Math.sqrt(var);
	}

	private int runTest(Cipher cipher)
	    throws Exception
	{
		final long n = ENCRYPTIONS_PER_TEST;
		long time = System.currentTimeMillis();
		for (int i = 0; i < n; i++) {
			cipher.doFinal(testArray, 0, testArray.length, testArray, 0);
		}
		time = System.currentTimeMillis() - time;
		System.out.println("Time elapsed: " + (time / 1000.0) + "; "
		    + ((testArray.length * n * 8) / (time)) + " * 1000 bits/second");
		return (int) time;
	}

	private static void usage() {
		System.err.println("Usage: AESSpeedTest ce|cd|ke|kd AlgorithmName KeyLengthBits");
		System.exit(1);
	}

	private static void main0(String args[])
	    throws Exception
	{
		Security.insertProviderAt(new IAIK(), 2);
		if (args.length != 3) {
			usage();
		}
		int type;
		final String t = args[0].toLowerCase();
		if (t.equals("ce")) {
			type = TYPE_CIPHER_ENCRYPT;
		} else if (t.equals("cd")) {
			type = TYPE_CIPHER_DECRYPT;
		} else if (t.equals("ke")) {
			type = TYPE_SETUP_ENCRYPT;
		} else if (t.equals("kd")) {
			type = TYPE_SETUP_DECRYPT;
		} else {
			usage();
			type = 0; //
		}
		final String algorithm = args[1];
		int keylength = 0;
		try {
			keylength = Integer.parseInt(args[2]);
		} catch (final NumberFormatException e) {
			usage();
		}
		new AESSpeedTest(algorithm, type, keylength / 8).runTests(System.out);
	}

	private static void runGC(boolean verbose) {
		long freeBefore = 0, totalBefore = 0, start = 0;
		final Runtime runtime = Runtime.getRuntime();
		if (verbose) {
			freeBefore = runtime.freeMemory();
			totalBefore = runtime.totalMemory();
			start = System.currentTimeMillis();
		}
		runtime.gc();
		runtime.runFinalization();
		if (verbose) {
			final long end = System.currentTimeMillis();
			final double time = (end - start) / 1000.0;
			final long freeAfter = runtime.freeMemory();
			final long totalAfter = runtime.totalMemory();
			System.out.println("* Garbage collection took " + time + " seconds.");
			System.out.print("* Before: " + freeBefore + "/" + totalBefore + "/"
			    + (totalBefore - freeBefore) + ", ");
			System.out.println("After: " + freeAfter + "/" + totalAfter + "/"
			    + (totalAfter - freeAfter));
		}
	}

	/**
	 *
	 */
	public static void main(String args[]) {
		try {
			main0(args);
		} catch (final Throwable e) {
			System.err.println("An exception occured:");
			e.printStackTrace(System.err);
		}
		// iaik.utils.Util.waitKey();
	}
}
