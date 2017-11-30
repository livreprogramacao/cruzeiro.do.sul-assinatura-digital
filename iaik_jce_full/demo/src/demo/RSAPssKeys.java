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
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAPssParameterSpec;
import iaik.security.rsa.RSAPssKeyPairGenerator;
import iaik.security.rsa.RSAPssPrivateKey;
import iaik.security.rsa.RSAPssPublicKey;
import iaik.security.rsa.RSAPssSignature;
import iaik.utils.Util;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;

import demo.util.DemoUtil;

/**
 * This class demonstrates the usage of RSASSA-PSS keys according to
 * <a href = "http://www.ietf.org/rfc/rfc4055.txt">RFC 4055</a>.
 * 
 * @see iaik.security.rsa.RSAPssPrivateKey
 * @see iaik.security.rsa.RSAPssPublicKey
 * @see iaik.security.rsa.RSAPssKeyPairGenerator
 * @see iaik.security.rsa.RSAPssKeyFactory
 * @see iaik.security.rsa.RSAPssSignature
 * @see iaik.pkcs.pkcs1.RSAPssParameterSpec
 * 
 * @version File Revision <!-- $$Revision: --> 6 <!-- $ -->
 */
public class RSAPssKeys implements IAIKDemo {

	/**
	 * Default constructor. 
	 */
	public RSAPssKeys() {
	}

	/**
	 * Generates a RSASSA-PSS keypair and uses the private key
	 * for signing some data and the public key for verifying
	 * the signature.
	 */
	public void start() {

		// use this method for switching on/off validation of signature parameters against key parameters
		RSAPssSignature.setValidateAgainstPssKeyParameters(true);

		// generate key pair
		System.out.println("Generating 1024 bit RSASSA-PSS key pair...");
		KeyPair kp = generateKeyPair();

		// the data to be signed
		byte[] data = "This is the data to be signed.".getBytes();
		try {

			RSAPssPublicKey publicKey = (RSAPssPublicKey) kp.getPublic();
			RSAPssPrivateKey privateKey = (RSAPssPrivateKey) kp.getPrivate();

			System.out.println("\nPublic PSS key is:\n" + publicKey);
			System.out.println("\nPrivate PSS key is:\n" + privateKey);

			System.out.println("Calculating signature...");

			Signature rsaPss = Signature.getInstance("RSASSA-PSS", "IAIK");
			// init for signing (PSS parameters are taken from key)
			rsaPss.initSign(privateKey);
			// sign data
			rsaPss.update(data);
			byte[] signature = rsaPss.sign();

			System.out.println("\nVerifying signature...");
			rsaPss = Signature.getInstance("RSASSA-PSS", "IAIK");
			// init for verification (PSS parameters are taken from key)
			rsaPss.initVerify(publicKey);
			// verify signature  
			rsaPss.update(data);
			if (rsaPss.verify(signature) == true) {
				System.out.println("Signature ok!");
			} else {
				throw new SignatureException("Signature verification error!");
			}

			AlgorithmParameters params = Util.getSignatureParameters(rsaPss);
			RSAPssParameterSpec paramSpec = (RSAPssParameterSpec) params
			    .getParameterSpec(RSAPssParameterSpec.class);
			System.out.println("\nParameters used for signing/verification:");
			System.out.println(paramSpec);

		} catch (Exception ex) {
			System.out.println("Signature creation/validation error:");
			ex.printStackTrace();
			throw new RuntimeException();
		}

	}

	/**
	 * Generates a RSASSA-PSS KeyPair.
	 * 
	 * @return the key pair 
	 */
	public KeyPair generateKeyPair() {
		KeyPair kp = null;

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSASSA-PSS", "IAIK");

			// initialization with parameters for demonstration purposes (cast required)
			RSAPssKeyPairGenerator rsaPsskeyGen = (RSAPssKeyPairGenerator) keyGen;

			// create PSS parameters for specifying hash, mgf algorithms and salt length:
			// hash and mgf algorithm ids
			AlgorithmID hashID = (AlgorithmID) AlgorithmID.ripeMd160.clone();
			AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
			mgfID.setParameter(hashID.toASN1Object());
			int saltLength = 20;
			// hash and mgf engines
			MessageDigest hashEngine = hashID.getMessageDigestInstance();
			MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
			MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
			mgf1ParamSpec.setHashEngine(hashEngine);
			mgfEngine.setParameters(mgf1ParamSpec);
			// create the RSAPssParameterSpec
			RSAPssParameterSpec pssParamSpec = new RSAPssParameterSpec(hashID, mgfID,
			    saltLength);
			// set engines
			pssParamSpec.setHashEngine(hashEngine);
			pssParamSpec.setMGFEngine(mgfEngine);

			// initialize key pair generator
			rsaPsskeyGen.initialize(1024, pssParamSpec);
			kp = rsaPsskeyGen.generateKeyPair();
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
			(new RSAPssKeys()).start();
		} catch (Exception ex) {
			// ignore
		}
		iaik.utils.Util.waitKey();
	}
}
