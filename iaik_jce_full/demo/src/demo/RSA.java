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

import iaik.asn1.OCTET_STRING;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAOaepPSourceParameterSpec;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.security.rsa.RSAPrivateKey;
import iaik.security.rsa.RSAPublicKey;
import iaik.utils.CryptoUtils;
import iaik.utils.NumberTheory;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

import javax.crypto.Cipher;

import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class tests the RSA cipher implementation.
 * <p>
 * IAIK-JCE allows to use the <code>javax.crypto.Cipher</code> class for working
 * with RSA ciphers. Creating a RSA cipher is done in the same way as creating
 * a, for instance, DES or IDEA cipher by calling a proper
 * <code>getInstance</code> factory method, e.g.:
 * <p>
 * <code>Cipher rsa = Cipher.getInstance("RSA", "IAIK");</code>
 * <p>
 * The supplied transformation string may be expanded to perform block
 * formatting according to <a href =
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/>PKCS#1</a> with block type 1
 * or blocktype 2, i.e.:
 * <p>
 * 
 * <PRE>
 * Cipher rsa = Cipher.getInstance(&quot;RSA/ECB/PKCS1Padding&quot;, &quot;IAIK&quot;);
 * </PRE>
 * <p>
 * If you want to use OAEP as encryption scheme you have to specify "OAEP" as
 * padding scheme when instantiating the cipher object:
 * 
 * <pre>
 * Cipher rsa = Cipher.getInstance(&quot;RSA/ECB/OAEP&quot;);
 * </pre>
 * 
 * The further proceeding uses cipher initialization, cipher update and cipher
 * finishing as used with any other cipher, e.g.:
 * <p>
 * 
 * <PRE>
 * rsa.init(Cipher.ENCRYPT_MODE, public_key);
 * byte[] encrypted = rsa.doFinal(plain_data);
 * </PRE>
 * <p>
 * 
 * @version File Revision <!-- $$Revision: --> 29 <!-- $ -->
 */
public class RSA implements IAIKDemo {

	PublicKey rsa_pub;
	PrivateKey rsa_priv;

	/**
	 * Default constructor. Inits the keys.
	 */
	public RSA() {
		rsa_pub = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_1024)[0]
		    .getPublicKey();
		rsa_priv = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
	}

	/**
	 * Performs the RSA cipher implementation test.
	 */
	public void start() {

		System.out.println("Testing RSA cipher with PKCS#1v1.5 padding.");
		rsa("RSA/ECB/PKCS1Padding");

		System.out.println("Testing RSA cipher with OAEP padding.");
		rsa("RSA/ECB/OAEP");

		System.out.println("Testing RSA cipher with OAEPWithSHA256AndMGF1Padding padding.");
		rsa("RSA/ECB/OAEPWithSHA256AndMGF1Padding");

		System.out.println("Testing RSA OAEP parameter creation.");
		testOAEPParametersCreate();

		System.out.println("Testing RSA OAEP parameter parsing.");
		testOAEPParametersParse();

		System.out.println("Testing RSA OAEP PSourceAlgorithm parameters.");
		testOAEPPSourceParameters();

		System.out.println("Testing RSA with non-CRT private key.");
		testNonCRTKey();

		System.out.println("Testing RSA with non-CRT private key but with public exponent.");
		testNonCRTKeyWithPublic();

		System.out
		    .println("Testing RSA with private key with invalid private exponent but with correct CRT components.");
		testInconsistentPrivateKey();

		System.out
		    .println("Testing RSA with private key with invalid private exponent but with correct CRT components"
		        + "with p and q reversed.");
		testInconsistentPrivateKey2();
	}

	/**
	 * RSA cipher test.
	 * 
	 * @param transformation
	 *          the Cipher transformation string (e.g. "RSA/ECB/OAEP");
	 */
	public void rsa(String transformation) {

		try {

			final byte[] plain = "This is a test!".getBytes();

			final Cipher rsa = Cipher.getInstance(transformation, "IAIK");
			rsa.init(Cipher.ENCRYPT_MODE, rsa_pub);
			final byte[] encrypted = rsa.doFinal(plain);

			System.out.println("Encrypted data: " + iaik.utils.Util.toString(encrypted));

			// now decrypt
			rsa.init(Cipher.DECRYPT_MODE, rsa_priv);
			final byte[] decrypted = rsa.doFinal(encrypted);

			System.out.println("Decrypted data: " + new String(decrypted));

			if (!CryptoUtils.equalsBlock(plain, decrypted)) {
				throw new RuntimeException("plain and decrypted are different!");
			}
			System.out.println("Ok!");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Test of OAEP parameter parsing. This method first uses a
	 * "RSA/ECB/OAEPWithSHA256AndMGF1Padding" cipher to encrypt some data and then
	 * inits a "RSA/ECB/OAEP" cipher with the parameters from the first cipher to
	 * decrypt the encrypted data.
	 */
	public void testOAEPParametersParse() {

		try {

			final byte[] plain = "This is a test!".getBytes();

			Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA256AndMGF1Padding", "IAIK");
			rsa.init(Cipher.ENCRYPT_MODE, rsa_pub);
			final byte[] encrypted = rsa.doFinal(plain);
			System.out.println("Encrypted data: " + iaik.utils.Util.toString(encrypted));

			// get parameters
			AlgorithmParameters params = rsa.getParameters();
			// parameters are encoded and transfered
			final byte[] encodedParameters = params.getEncoded();
			// decode parameters
			params = AlgorithmParameters.getInstance("OAEP", "IAIK");
			params.init(encodedParameters);

			// now decrypt
			rsa = Cipher.getInstance("RSA/ECB/OAEP", "IAIK");
			rsa.init(Cipher.DECRYPT_MODE, rsa_priv, params, null);
			final byte[] decrypted = rsa.doFinal(encrypted);

			System.out.println("Decrypted data: " + new String(decrypted));

			if (!CryptoUtils.equalsBlock(plain, decrypted)) {
				throw new RuntimeException("plain and decrypted are different!");
			}
			System.out.println("Ok!");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Test of OAEP parameter creation. This method first uses a "RSA/ECB/OAEP"
	 * cipher and inits it with OAEP paramaters to encrypt some data and then uses
	 * a "RSA/ECB/OAEPWithSHA256AndMGF1Padding" cipher to decrypt the encrypted
	 * data.
	 */
	public void testOAEPParametersCreate() {

		try {

			final byte[] plain = "This is a test!".getBytes();

			Cipher rsa = Cipher.getInstance("RSA/ECB/OAEP", "IAIK");

			// hash, mgf and pSource algorithm parameters
			final AlgorithmID hashID = (AlgorithmID) AlgorithmID.sha256.clone();
			final AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
			mgfID.setParameter(hashID.toASN1Object());
			final AlgorithmID pSourceID = (AlgorithmID) AlgorithmID.pSpecified.clone();
			pSourceID.setParameter(new OCTET_STRING());
			// hash and mgf engines
			final MessageDigest hashEngine = hashID.getMessageDigestInstance();
			final MaskGenerationAlgorithm mgfEngine = mgfID
			    .getMaskGenerationAlgorithmInstance();
			final MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
			mgf1ParamSpec.setHashEngine(hashEngine);
			mgfEngine.setParameters(mgf1ParamSpec);
			// create the RSAOaepParameterSpec
			final RSAOaepParameterSpec oaepParamSpec = new RSAOaepParameterSpec(hashID, mgfID,
			    pSourceID);
			// set engines
			oaepParamSpec.setHashEngine(hashEngine);
			oaepParamSpec.setMGFEngine(mgfEngine);

			rsa.init(Cipher.ENCRYPT_MODE, rsa_pub, oaepParamSpec);
			final byte[] encrypted = rsa.doFinal(plain);
			System.out.println("Encrypted data: " + iaik.utils.Util.toString(encrypted));

			// now decrypt
			rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA256AndMGF1Padding", "IAIK");
			rsa.init(Cipher.DECRYPT_MODE, rsa_priv);
			final byte[] decrypted = rsa.doFinal(encrypted);

			System.out.println("Decrypted data: " + new String(decrypted));

			if (!CryptoUtils.equalsBlock(plain, decrypted)) {
				throw new RuntimeException("plain and decrypted are different!");
			}
			System.out.println("Ok!");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Test of OAEP PSourceAlgorithm parameters. This method first uses a
	 * "RSA/ECB/OAEPWithSHA1AndMGF1Padding" cipher and inits it with
	 * PSourceAlgorithm parameters only to encrypt some data and then inits a
	 * "RSA/ECB/OAEP" cipher with the parameters from the first cipher to decrypt
	 * the encrypted data.
	 */
	public void testOAEPPSourceParameters() {

		try {

			final byte[] plain = "This is a test!".getBytes();

			Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "IAIK");

			// set the PSourceAlgorithm parameter
			final RSAOaepPSourceParameterSpec paramSpec = new RSAOaepPSourceParameterSpec(
			    (AlgorithmID) AlgorithmID.pSpecified.clone());
			final byte[] label = new byte[8];
			final Random random = new Random();
			random.nextBytes(label);
			paramSpec.setLabel(label);
			rsa.init(Cipher.ENCRYPT_MODE, rsa_pub, paramSpec);
			final byte[] encrypted = rsa.doFinal(plain);
			System.out.println("Encrypted data: " + iaik.utils.Util.toString(encrypted));

			// get parameters
			AlgorithmParameters params = rsa.getParameters();
			// parameters are encoded and transfered
			final byte[] encodedParameters = params.getEncoded();
			// decode parameters
			params = AlgorithmParameters.getInstance("OAEP", "IAIK");
			params.init(encodedParameters);

			// now decrypt
			rsa = Cipher.getInstance("RSA/ECB/OAEP", "IAIK");
			rsa.init(Cipher.DECRYPT_MODE, rsa_priv, params, null);
			final byte[] decrypted = rsa.doFinal(encrypted);

			System.out.println("Decrypted data: " + new String(decrypted));

			if (!CryptoUtils.equalsBlock(plain, decrypted)) {
				throw new RuntimeException("plain and decrypted are different!");
			}
			System.out.println("Ok!");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * This method performs a simple encryption decryption with the provided
	 * parameters. If the operations fails, it throws a RuntimeException.
	 * 
	 * @preconditions
	 * @postconditions
	 */
	private void testEncryptDecrypt(String transformation,
	                                RSAPublicKey publicKey,
	                                RSAPrivateKey privateKey,
	                                byte[] plaintext)
	{
		try {
			final Cipher rsa = Cipher.getInstance(transformation, "IAIK");
			rsa.init(Cipher.ENCRYPT_MODE, publicKey);

			final byte[] encrypted = rsa.doFinal(plaintext);

			// now decrypt
			rsa.init(Cipher.DECRYPT_MODE, privateKey);
			final byte[] decrypted = rsa.doFinal(encrypted);

			System.out.println("Decrypted data: " + new String(decrypted));

			if (!CryptoUtils.equalsBlock(plaintext, decrypted)) {
				throw new RuntimeException("plain and decrypted are different!");
			}
			System.out.println("Ok!");

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * This method performs some simple tests to verify that non-CRT private keys
	 * work correctly.
	 * 
	 * @preconditions
	 * @postconditions
	 */
	public void testNonCRTKey() {
		final RSAPrivateKey crtPrivateKey = (RSAPrivateKey) rsa_priv;

		// create a RSA private key which has no CRT components
		final RSAPrivateKey privateKey = new RSAPrivateKey(crtPrivateKey.getModulus(),
		    crtPrivateKey.getPrivateExponent());
		testEncryptDecrypt("RSA/ECB/PKCS1Padding", (RSAPublicKey) rsa_pub, privateKey,
		    "This is a test!".getBytes());
	}

	/**
	 * This method performs some simple tests to verify that private keys with no
	 * CRT components but with the public exponent use blinding.
	 * 
	 * @preconditions
	 * @postconditions
	 */
	public void testNonCRTKeyWithPublic() {
		final RSAPrivateKey crtPrivateKey = (RSAPrivateKey) rsa_priv;

		// create a RSA private key which has no CRT components except public
		// exponent
		final RSAPrivateKey privateKey = new RSAPrivateKey(crtPrivateKey.getModulus(),
		    crtPrivateKey.getPublicExponent(), crtPrivateKey.getPrivateExponent(),
		    NumberTheory.ZERO, NumberTheory.ZERO, NumberTheory.ZERO, NumberTheory.ZERO,
		    NumberTheory.ZERO);

		testEncryptDecrypt("RSA/ECB/PKCS1Padding", (RSAPublicKey) rsa_pub, privateKey,
		    "This is a test!".getBytes());
	}

	/**
	 * This method performs some simple tests to verify that private keys are used
	 * as is. Even if the CRT components do not correspond to the private
	 * exponent, the implementation should try to use the key as is. If CRT
	 * components are available, it should work with them and not touch the
	 * private exponent.
	 * 
	 * @preconditions
	 * @postconditions
	 */
	public void testInconsistentPrivateKey() {
		final RSAPrivateKey crtPrivateKey = (RSAPrivateKey) rsa_priv;

		// create a RSA private with wrong private exponent
		// but correct p, q, and CRT components
		// we leave modulus and public exponent untouched, otherwise we would have
		// to
		// disable blinding (which) requires modulus and public exponent
		final RSAPrivateKey privateKey = new RSAPrivateKey(crtPrivateKey.getModulus(),
		    crtPrivateKey.getPublicExponent(), crtPrivateKey.getPrivateExponent().subtract(
		        NumberTheory.ONE), crtPrivateKey.getPrimeP(), crtPrivateKey.getPrimeQ(),
		    crtPrivateKey.getPrimeExponentP(), crtPrivateKey.getPrimeExponentQ(),
		    crtPrivateKey.getCrtCoefficient());

		testEncryptDecrypt("RSA/ECB/PKCS1Padding", (RSAPublicKey) rsa_pub, privateKey,
		    "This is a test!".getBytes());
	}

	/**
	 * This method performs some simple tests to verify that private keys are used
	 * as is. Even if the CRT components do not correspond to the private
	 * exponent, the implementation should try to use the key as is. If CRT
	 * components are available, it should work with them and not touch the
	 * private exponent. Uses reversed p and q values.
	 * 
	 * @preconditions
	 * @postconditions
	 */
	public void testInconsistentPrivateKey2() {
		final RSAPrivateKey crtPrivateKey = (RSAPrivateKey) rsa_priv;

		// create a RSA private with wrong private exponent
		// but correct p, q, and CRT components
		// we leave modulus and public exponent untouched, otherwise we would have
		// to
		// disable blinding (which) requires modulus and public exponent
		final BigInteger p = crtPrivateKey.getPrimeQ();
		final BigInteger q = crtPrivateKey.getPrimeP();
		final BigInteger pExponent = crtPrivateKey.getPrimeExponentQ();
		final BigInteger qExponent = crtPrivateKey.getPrimeExponentP();
		final BigInteger crtFactor = q.modInverse(p);
		final RSAPrivateKey privateKey = new RSAPrivateKey(crtPrivateKey.getModulus(),
		    crtPrivateKey.getPublicExponent(), crtPrivateKey.getPrivateExponent().subtract(
		        NumberTheory.ONE), p, q, pExponent, qExponent, crtFactor);

		testEncryptDecrypt("RSA/ECB/PKCS1Padding", (RSAPublicKey) rsa_pub, privateKey,
		    "This is a test!".getBytes());
	}

	/**
	 * Starts the RSA cipher implementation test.
	 */
	public static void main(String argv[]) {

		DemoUtil.initDemos();
		try {
			(new RSA()).start();
		} catch (final Exception ex) {
			// ignore
		}
		iaik.utils.Util.waitKey();
	}
}
