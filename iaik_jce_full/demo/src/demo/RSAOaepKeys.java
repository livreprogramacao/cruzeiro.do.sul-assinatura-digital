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
import iaik.pkcs.pkcs1.RSACipher;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.security.rsa.RSAOaepKeyPairGenerator;
import iaik.security.rsa.RSAOaepPrivateKey;
import iaik.security.rsa.RSAOaepPublicKey;
import iaik.utils.CryptoUtils;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import javax.crypto.Cipher;

import demo.util.DemoUtil;

/**
 * This class demonstrates the usage of RSAES-OAEP keys according to
 * <a href = "http://www.ietf.org/rfc/rfc4055.txt">RFC 4055</a>.
 * 
 * @see iaik.security.rsa.RSAOaepPrivateKey
 * @see iaik.security.rsa.RSAOaepPublicKey
 * @see iaik.security.rsa.RSAOaepKeyPairGenerator
 * @see iaik.security.rsa.RSAOaepKeyFactory
 * @see iaik.pkcs.pkcs1.RSACipher
 * @see iaik.pkcs.pkcs1.RSAOaepParameterSpec
 * 
 * @version File Revision <!-- $$Revision: --> 3 <!-- $ -->
 */
public class RSAOaepKeys implements IAIKDemo {

	/**
	 * Default constructor.
	 */
	public RSAOaepKeys() {
	}

	/**
	 * Generates a RSAES-OAEP keypair and uses the public key
	 * for encrypting some data and the private key for decrypting
	 * the encrypted data.
	 */
	public void start() {

		// use this method for switching on/off validation of signature parameters against key parameters
		RSACipher.setValidateAgainstOaepKeyParameters(true);

		// generate key pair
		System.out.println("Generating 1024 bit RSAES-OAEP key pair...");
		KeyPair kp = generateKeyPair();

		// the data to be encrypted
		byte[] data = "This is the data to be encrypted.".getBytes();
		try {

			RSAOaepPublicKey publicKey = (RSAOaepPublicKey) kp.getPublic();
			RSAOaepPrivateKey privateKey = (RSAOaepPrivateKey) kp.getPrivate();

			System.out.println("\nPublic OAEP key is:\n" + publicKey);
			System.out.println("\nPrivate OAEP key is:\n" + privateKey);

			System.out.println("Encrypt data...");

			Cipher rsaOaep = Cipher.getInstance("RSA/ECB/OAEP", "IAIK");
			// init for encryption (OAEP parameters are taken from key)
			rsaOaep.init(Cipher.ENCRYPT_MODE, publicKey);
			// encrypt data
			byte[] encrypted = rsaOaep.doFinal(data);

			System.out.println("\nDecrypting...");
			rsaOaep = Cipher.getInstance("RSA/ECB/OAEP", "IAIK");
			// init for decryption (OAEP parameters are taken from key)
			rsaOaep.init(Cipher.DECRYPT_MODE, privateKey);
			// decrypt   
			byte[] decrypted = rsaOaep.doFinal(encrypted);
			if (CryptoUtils.equalsBlock(data, decrypted) == true) {
				System.out.println("Ok!");
			} else {
				throw new Exception("Error: Decrypted data not equal to original one!");
			}

			AlgorithmParameters params = rsaOaep.getParameters();
			RSAOaepParameterSpec paramSpec = (RSAOaepParameterSpec) params
			    .getParameterSpec(RSAOaepParameterSpec.class);
			System.out.println("\nParameters used for en/decryption:");
			System.out.println(paramSpec);

		} catch (Exception ex) {
			System.out.println("Signature creation/validation error:");
			ex.printStackTrace();
			throw new RuntimeException();
		}

	}

	/**
	 * Generates a RSAES-OAEP KeyPair.
	 * 
	 * @return the key pair 
	 */
	public KeyPair generateKeyPair() {
		KeyPair kp = null;

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSAES-OAEP", "IAIK");

			// initialization with parameters for demonstration purposes (cast required)
			RSAOaepKeyPairGenerator rsaOaepkeyGen = (RSAOaepKeyPairGenerator) keyGen;

			// create OAEP parameters for specifying hash, mgf and pSource algorithms 
			AlgorithmID hashID = (AlgorithmID) AlgorithmID.ripeMd160.clone();
			AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
			mgfID.setParameter(hashID.toASN1Object());
			AlgorithmID pSourceID = (AlgorithmID) AlgorithmID.pSpecified.clone();
			pSourceID.setParameter(new OCTET_STRING());
			// hash and mgf engines
			MessageDigest hashEngine = hashID.getMessageDigestInstance();
			MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
			MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
			mgf1ParamSpec.setHashEngine(hashEngine);
			mgfEngine.setParameters(mgf1ParamSpec);
			// create the RSAOaepParameterSpec
			RSAOaepParameterSpec oaepParamSpec = new RSAOaepParameterSpec(hashID, mgfID,
			    pSourceID);
			// set engines
			oaepParamSpec.setHashEngine(hashEngine);
			oaepParamSpec.setMGFEngine(mgfEngine);

			// initialize key pair generator
			rsaOaepkeyGen.initialize(1024, oaepParamSpec);
			kp = rsaOaepkeyGen.generateKeyPair();
		} catch (Exception ex) {
			System.out.println("Error generating key pair:");
			ex.printStackTrace();
			throw new RuntimeException();
		}
		return kp;
	}

	/**
	 * Main method.
	 */
	public static void main(String arg[]) {

		DemoUtil.initDemos();
		try {
			(new RSAOaepKeys()).start();
		} catch (Exception ex) {
			// ignore
		}
		iaik.utils.Util.waitKey();
	}
}
