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
import iaik.iso.iso9796.ISO9796P2ParameterSpec;
import iaik.iso.iso9796.ISO9796P2S2S3ParameterSpec;
import iaik.iso.iso9796.ISO9796P2S2S3Signature;
import iaik.iso.iso9796.ISO9796P2Signature;
import iaik.iso.iso9796.RawISO9796P2ParameterSpec;
import iaik.iso.iso9796.RawISO9796P2S2S3ParameterSpec;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAPssParameterSpec;
import iaik.pkcs.pkcs1.RSAPssSaltParameterSpec;
import iaik.pkcs.pkcs1.RSASSAPkcs1v15ParameterSpec;
import iaik.pkcs.pkcs7.DigestInfo;
import iaik.security.rsa.RSAPrivateKey;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Random;

import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class tests the functionality of the signature algorithtms.
 * @version File Revision <!-- $$Revision: --> 37 <!-- $ -->
 */
public class TestSignature implements IAIKDemo {

  PublicKey rsa_pub;
  PrivateKey rsa_priv;
  PublicKey rsa_pub_2048;
  PrivateKey rsa_priv_2048;
  PublicKey dsa_pub;
  PrivateKey dsa_priv;

  /**
   * Default constructor. Loads keys from the keystore.
   */
  public TestSignature() {
    rsa_pub = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_1024)[0]
        .getPublicKey();
    rsa_priv = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
    rsa_pub_2048 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
        IaikKeyStore.SZ_2048)[0].getPublicKey();
    rsa_priv_2048 = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_2048);
    dsa_pub = IaikKeyStore.getCertificateChain(IaikKeyStore.DSA, IaikKeyStore.SZ_1024)[0]
        .getPublicKey();
    dsa_priv = IaikKeyStore.getPrivateKey(IaikKeyStore.DSA, IaikKeyStore.SZ_1024);
  }

  /**
   * Tests the functionality of RSA PKCS1v1.5 signature algorithms.
   */
  public void rsaPKCS1v15() {

    try {
      // 1024 bytes random data to sign
      Random random = new Random();
      byte[] data = new byte[1024];
      random.nextBytes(data);

      Signature md5rsa = Signature.getInstance("MD5withRSA", "IAIK");
      Signature sha1rsa = Signature.getInstance("SHA1withRSA", "IAIK");
      Signature sha224rsa = Signature.getInstance("SHA224withRSA", "IAIK");
      Signature sha256rsa = Signature.getInstance("SHA256withRSA", "IAIK");
      Signature sha384rsa = Signature.getInstance("SHA384withRSA", "IAIK");
      Signature sha512rsa = Signature.getInstance("SHA512withRSA", "IAIK");
      Signature ripemd160rsa = Signature.getInstance("RipeMd160withRSA", "IAIK");
      Signature ripemd128rsa = Signature.getInstance("RipeMd128withRSA", "IAIK");
      Signature whirlpoolrsa = Signature.getInstance("WHIRLPOOLwithRSA", "IAIK");

      // init Signature objects with private keys
      md5rsa.initSign(rsa_priv);
      sha1rsa.initSign(rsa_priv);
      sha224rsa.initSign(rsa_priv);
      sha256rsa.initSign(rsa_priv);
      sha384rsa.initSign(rsa_priv);
      sha512rsa.initSign(rsa_priv);
      ripemd160rsa.initSign(rsa_priv);
      ripemd128rsa.initSign(rsa_priv);
      whirlpoolrsa.initSign(rsa_priv);

      // create the signatures
      md5rsa.update(data);
      sha1rsa.update(data);
      sha224rsa.update(data);
      sha256rsa.update(data);
      sha384rsa.update(data);
      sha512rsa.update(data);
      ripemd160rsa.update(data);
      ripemd128rsa.update(data);
      whirlpoolrsa.update(data);

      byte[] md5sig = md5rsa.sign();
      byte[] sha1sig = sha1rsa.sign();
      byte[] sha224sig = sha224rsa.sign();
      byte[] sha256sig = sha256rsa.sign();
      byte[] sha384sig = sha384rsa.sign();
      byte[] sha512sig = sha512rsa.sign();
      byte[] ripemd160sig = ripemd160rsa.sign();
      byte[] ripemd128sig = ripemd128rsa.sign();
      byte[] whirlpoolrsasig = whirlpoolrsa.sign();

      // verify the signatures
      md5rsa.initVerify(rsa_pub);
      md5rsa.update(data);
      System.out.println("verify MD5withRSA: "
          + (md5rsa.verify(md5sig) ? "OK!" : "NOT OK!"));

      sha1rsa.initVerify(rsa_pub);
      sha1rsa.update(data);
      System.out.println("verify SHA1withRSA: "
          + (sha1rsa.verify(sha1sig) ? "OK!" : "NOT OK!"));

      sha224rsa.initVerify(rsa_pub);
      sha224rsa.update(data);
      System.out.println("verify SHA224withRSA: "
          + (sha224rsa.verify(sha224sig) ? "OK!" : "NOT OK!"));

      sha256rsa.initVerify(rsa_pub);
      sha256rsa.update(data);
      System.out.println("verify SHA256withRSA: "
          + (sha256rsa.verify(sha256sig) ? "OK!" : "NOT OK!"));

      sha384rsa.initVerify(rsa_pub);
      sha384rsa.update(data);
      System.out.println("verify SHA384withRSA: "
          + (sha384rsa.verify(sha384sig) ? "OK!" : "NOT OK!"));

      sha512rsa.initVerify(rsa_pub);
      sha512rsa.update(data);
      System.out.println("verify SHA512withRSA: "
          + (sha512rsa.verify(sha512sig) ? "OK!" : "NOT OK!"));

      ripemd160rsa.initVerify(rsa_pub);
      ripemd160rsa.update(data);
      System.out.println("verify RipeMd160withRSA: "
          + (ripemd160rsa.verify(ripemd160sig) ? "OK!" : "NOT OK!"));

      ripemd128rsa.initVerify(rsa_pub);
      ripemd128rsa.update(data);
      System.out.println("verify RipeMd128withRSA: "
          + (ripemd128rsa.verify(ripemd128sig) ? "OK!" : "NOT OK!"));

      whirlpoolrsa.initVerify(rsa_pub);
      whirlpoolrsa.update(data);
      System.out.println("verify WHIRLPOOLwithRSA: "
          + (whirlpoolrsa.verify(whirlpoolrsasig) ? "OK!" : "NOT OK!"));

      // test raw signature (DigestInfo calculated outside)
      AlgorithmID hashAlgorithm = AlgorithmID.sha1; // e.g. AlgorithmID.sha1
      MessageDigest hashEngine = MessageDigest.getInstance(hashAlgorithm
          .getImplementationName());
      byte[] rawHash = hashEngine.digest(data);
      byte[] preparedHash = new DigestInfo(hashAlgorithm, rawHash).toByteArray();

      Signature rawRsaSignatureEngine = Signature.getInstance("RSA", "IAIK");

      // init Signature object with private keys
      rawRsaSignatureEngine.initSign(rsa_priv);

      // create the signature
      rawRsaSignatureEngine.update(preparedHash);
      byte[] rawRsaSig = rawRsaSignatureEngine.sign();

      // verify the signature
      rawRsaSignatureEngine.initVerify(rsa_pub);
      rawRsaSignatureEngine.update(preparedHash);
      System.out.println("verify raw RSA (DigestInfo calculated outside): "
          + (rawRsaSignatureEngine.verify(rawRsaSig) ? "OK!" : "NOT OK!"));

      // test raw signature (DigestInfo calculated inside)
      rawRsaSignatureEngine = Signature.getInstance("RawRSASSA-PKCS1-v1_5", "IAIK");

      // init Signature object with private keys
      rawRsaSignatureEngine.initSign(rsa_priv);

      // supply hash algorithm id as parameter
      RSASSAPkcs1v15ParameterSpec params = new RSASSAPkcs1v15ParameterSpec(hashAlgorithm);
      // set parameters 
      rawRsaSignatureEngine.setParameter(params);

      // create the signature
      rawRsaSignatureEngine.update(rawHash);
      rawRsaSig = rawRsaSignatureEngine.sign();

      // verify the signature
      rawRsaSignatureEngine.initVerify(rsa_pub);
      // set parameters 
      rawRsaSignatureEngine.setParameter(params);
      rawRsaSignatureEngine.update(rawHash);
      System.out.println("verify raw RSA (DigestInfo calculated inside): "
          + (rawRsaSignatureEngine.verify(rawRsaSig) ? "OK!" : "NOT OK!"));

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Tests the functionality of RSA PSS signature schemes.
   */
  public void rsaPss() {

    try {
      // 1024 bytes random data to sign
      Random random = new Random();
      byte[] data = new byte[1024];
      random.nextBytes(data);

      Signature md5rsamgf1 = Signature.getInstance("MD5withRSAandMGF1", "IAIK");
      Signature sha1rsamgf1 = Signature.getInstance("SHA1withRSAandMGF1", "IAIK");
      Signature sha224rsamgf1 = Signature.getInstance("SHA224withRSAandMGF1", "IAIK");
      Signature sha256rsamgf1 = Signature.getInstance("SHA256withRSAandMGF1", "IAIK");
      Signature sha384rsamgf1 = Signature.getInstance("SHA384withRSAandMGF1", "IAIK");
      Signature sha512rsamgf1 = Signature.getInstance("SHA512withRSAandMGF1", "IAIK");
      Signature ripemd128rsamgf1 = Signature.getInstance("RIPEMD128withRSAandMGF1",
          "IAIK");
      Signature ripemd160rsamgf1 = Signature.getInstance("RIPEMD160withRSAandMGF1",
          "IAIK");
      Signature whirlpoolrsamgf1 = Signature.getInstance("WHIRLPOOLwithRSAandMGF1",
          "IAIK");

      // init Signature objects with private keys
      md5rsamgf1.initSign(rsa_priv);
      sha1rsamgf1.initSign(rsa_priv);
      sha224rsamgf1.initSign(rsa_priv);
      sha256rsamgf1.initSign(rsa_priv);
      sha384rsamgf1.initSign(rsa_priv);
      sha512rsamgf1.initSign(rsa_priv_2048);
      ripemd128rsamgf1.initSign(rsa_priv);
      ripemd160rsamgf1.initSign(rsa_priv);
      whirlpoolrsamgf1.initSign(rsa_priv_2048);

      // create the signatures
      md5rsamgf1.update(data);
      sha1rsamgf1.update(data);
      sha224rsamgf1.update(data);
      sha256rsamgf1.update(data);
      sha384rsamgf1.update(data);
      sha512rsamgf1.update(data);
      ripemd128rsamgf1.update(data);
      ripemd160rsamgf1.update(data);
      whirlpoolrsamgf1.update(data);

      byte[] md5rsamgf1sig = md5rsamgf1.sign();
      byte[] sha1rsamgf1sig = sha1rsamgf1.sign();
      byte[] sha224rsamgf1sig = sha224rsamgf1.sign();
      byte[] sha256rsamgf1sig = sha256rsamgf1.sign();
      byte[] sha384rsamgf1sig = sha384rsamgf1.sign();
      byte[] sha512rsamgf1sig = sha512rsamgf1.sign();
      byte[] ripemd128rsamgf1sig = ripemd128rsamgf1.sign();
      byte[] ripemd160rsamgf1sig = ripemd160rsamgf1.sign();
      byte[] whirlpoolrsamgf1sig = whirlpoolrsamgf1.sign();

      // verify the signatures
      md5rsamgf1.initVerify(rsa_pub);
      md5rsamgf1.update(data);
      System.out.println("verify MD5withRSAandMGF1: "
          + (md5rsamgf1.verify(md5rsamgf1sig) ? "OK!" : "NOT OK!"));

      sha1rsamgf1.initVerify(rsa_pub);
      sha1rsamgf1.update(data);
      System.out.println("verify SHAwithRSAandMGF1: "
          + (sha1rsamgf1.verify(sha1rsamgf1sig) ? "OK!" : "NOT OK!"));

      sha224rsamgf1.initVerify(rsa_pub);
      sha224rsamgf1.update(data);
      System.out.println("verify SHA224withRSAandMGF1: "
          + (sha224rsamgf1.verify(sha224rsamgf1sig) ? "OK!" : "NOT OK!"));

      sha256rsamgf1.initVerify(rsa_pub);
      sha256rsamgf1.update(data);
      System.out.println("verify SHA256withRSAandMGF1: "
          + (sha256rsamgf1.verify(sha256rsamgf1sig) ? "OK!" : "NOT OK!"));

      sha384rsamgf1.initVerify(rsa_pub);
      sha384rsamgf1.update(data);
      System.out.println("verify SHA384withRSAandMGF1: "
          + (sha384rsamgf1.verify(sha384rsamgf1sig) ? "OK!" : "NOT OK!"));

      sha512rsamgf1.initVerify(rsa_pub_2048);
      sha512rsamgf1.update(data);
      System.out.println("verify SHA512withRSAandMGF1: "
          + (sha512rsamgf1.verify(sha512rsamgf1sig) ? "OK!" : "NOT OK!"));

      ripemd128rsamgf1.initVerify(rsa_pub);
      ripemd128rsamgf1.update(data);
      System.out.println("verify RIPEMD128withRSAandMGF1: "
          + (ripemd128rsamgf1.verify(ripemd128rsamgf1sig) ? "OK!" : "NOT OK!"));

      ripemd160rsamgf1.initVerify(rsa_pub);
      ripemd160rsamgf1.update(data);
      System.out.println("verify RIPEMD160withRSAandMGF1: "
          + (ripemd160rsamgf1.verify(ripemd160rsamgf1sig) ? "OK!" : "NOT OK!"));

      whirlpoolrsamgf1.initVerify(rsa_pub_2048);
      whirlpoolrsamgf1.update(data);
      System.out.println("verify WHIRLPOOLwithRSAandMGF1: "
          + (whirlpoolrsamgf1.verify(whirlpoolrsamgf1sig) ? "OK!" : "NOT OK!"));

      /*
       * test general RSA-PSS engine where parameters are set from outside
       */
      Signature pssSignature = Signature.getInstance("RSASSA-PSS", "IAIK");
      // init Signature object with private key
      pssSignature.initSign(rsa_priv);
      // parameters
      // hash algorithm
      AlgorithmID hashID = (AlgorithmID) AlgorithmID.ripeMd128.clone();
      // mask generation function ID
      AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
      mgfID.setParameter(hashID.toASN1Object());
      // salt length
      int saltLength = 16;
      // create a RSAPssParameterSpec
      RSAPssParameterSpec pssParamSpec = new RSAPssParameterSpec(hashID, mgfID,
          saltLength);
      // optionally set hash and mgf engines
      MessageDigest hashEngine = hashID.getMessageDigestInstance("IAIK");
      pssParamSpec.setHashEngine(hashEngine);
      MaskGenerationAlgorithm mgfEngine = mgfID
          .getMaskGenerationAlgorithmInstance("IAIK");
      MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(hashID);
      mgf1Spec.setHashEngine(hashEngine);
      mgfEngine.setParameters(mgf1Spec);
      pssParamSpec.setMGFEngine(mgfEngine);
      // set parameters 
      pssSignature.setParameter(pssParamSpec);

      // create the signature
      pssSignature.update(data);
      byte[] pssSig = pssSignature.sign();

      pssSignature = Signature.getInstance("RSASSA-PSS", "IAIK");
      // verify the signatures
      pssSignature.initVerify(rsa_pub);
      // set parameters 
      pssSignature.setParameter(pssParamSpec);
      pssSignature.update(data);
      System.out.println("verify RSASSA-PSS siganture: "
          + (pssSignature.verify(pssSig) ? "OK!" : "NOT OK!"));

      /*
       * test raw RSA-PSS engine 
       */
      Signature rawPssSignature = Signature.getInstance("RawRSASSA-PSS", "IAIK");
      // init Signature object with private key
      rawPssSignature.initSign(rsa_priv);
      // set parameters 
      rawPssSignature.setParameter(pssParamSpec);
      // calculate hash outside
      byte[] rawHash = hashEngine.digest(data);
      rawPssSignature.update(rawHash);
      // create the signature
      byte[] rawPssSig = rawPssSignature.sign();

      // verify the signature
      rawPssSignature.initVerify(rsa_pub);
      // set parameters 
      rawPssSignature.setParameter(pssParamSpec);
      rawPssSignature.update(rawHash);
      System.out.println("verify RawRSASSA-PSS siganture: "
          + (rawPssSignature.verify(rawPssSig) ? "OK!" : "NOT OK!"));

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Test of PSS parameter parsing. This method first uses a
   * "SHA1withRSAandMGF1" Signature engine to sign some
   * data and then inits a "RSASSA-PSS" Signature engine with the
   * parameters from the first Signature engine to verify the signature.
   */
  public void rsaPssParameterParse() {

    try {
      // 1024 bytes random data to sign
      Random random = new Random();
      byte[] data = new byte[1024];
      random.nextBytes(data);

      Signature sha1rsamgf1 = Signature.getInstance("SHA1withRSAandMGF1", "IAIK");
      // init Signature object with private key
      sha1rsamgf1.initSign(rsa_priv);
      // create the signature
      sha1rsamgf1.update(data);
      byte[] sha1rsamgf1sig = sha1rsamgf1.sign();

      // get parameters
      AlgorithmParameters params = getParameters(sha1rsamgf1);
      // parameters are encoded and transfered
      byte[] encodedParameters = params.getEncoded();
      // decode parameters
      params = AlgorithmParameters.getInstance("RSASSA-PSS", "IAIK");
      params.init(encodedParameters);
      RSAPssParameterSpec pssParamSpec = (RSAPssParameterSpec) params
          .getParameterSpec(RSAPssParameterSpec.class);

      // verify the signature
      Signature rsaPss = Signature.getInstance("RSASSA-PSS", "IAIK");
      // set parameters 
      rsaPss.setParameter(pssParamSpec);
      rsaPss.initVerify(rsa_pub);
      rsaPss.update(data);
      System.out.println("verify PSS signatures with parameters: "
          + (rsaPss.verify(sha1rsamgf1sig) ? "OK!" : "NOT OK!"));

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Test of PSS SaltLength parameters. This method first uses a
   * "SHA1withRSAandMGF1" Signature engine and inits it with
   * RSAPssSaltParameterSpec parameters to sign some
   * data and then inits a "RSASSA-PSS" Signature engine with the
   * parameters from the first Signature engine to verify the 
   * signature.
   */
  public void rsaPssSaltParameters() {

    try {
      // 1024 bytes random data to sign
      Random random = new Random();
      byte[] data = new byte[1024];
      random.nextBytes(data);

      Signature sha1rsamgf1 = Signature.getInstance("SHA1withRSAandMGF1", "IAIK");
      // init Signature object with private key
      sha1rsamgf1.initSign(rsa_priv);
      // create and set salt length parameters
      int saltLength = 20;
      RSAPssSaltParameterSpec pssSaltParamSpec = new RSAPssSaltParameterSpec(saltLength);
      // create the signature
      sha1rsamgf1.update(data);
      // set parameters 
      sha1rsamgf1.setParameter(pssSaltParamSpec);
      byte[] sha1rsamgf1sig = sha1rsamgf1.sign();

      // get parameters
      AlgorithmParameters params = getParameters(sha1rsamgf1);
      // parameters are encoded and transfered
      byte[] encodedParameters = params.getEncoded();
      // decode parameters
      params = AlgorithmParameters.getInstance("RSASSA-PSS", "IAIK");
      params.init(encodedParameters);
      RSAPssParameterSpec pssParamSpec = (RSAPssParameterSpec) params
          .getParameterSpec(RSAPssParameterSpec.class);

      // verify the signature
      Signature rsaPss = Signature.getInstance("RSASSA-PSS", "IAIK");
      // set parameters 
      rsaPss.setParameter(pssParamSpec);
      rsaPss.initVerify(rsa_pub);
      rsaPss.update(data);
      System.out.println("verify PSS signatures with parameters: "
          + (rsaPss.verify(sha1rsamgf1sig) ? "OK!" : "NOT OK!"));

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Tests the functionality of RSA ISO-9796-2 signature scheme 1.
   */
  public void rsaISO9796P2S1(int dataLength, boolean totalRecovery) {

    try {

      Random random = new Random();
      byte[] data = new byte[dataLength];
      random.nextBytes(data);

      Signature iso9796sharsa = Signature.getInstance("SHA/RSA-ISO9796-2", "IAIK");
      Signature iso9796sha256rsa = Signature.getInstance("SHA256/RSA-ISO9796-2", "IAIK");
      Signature iso9796sha384rsa = Signature.getInstance("SHA384/RSA-ISO9796-2", "IAIK");
      Signature iso9796sha512rsa = Signature.getInstance("SHA512/RSA-ISO9796-2", "IAIK");
      Signature iso9796ripemd128rsa = Signature.getInstance("RIPEMD128/RSA-ISO9796-2",
          "IAIK");
      Signature iso9796ripemd160rsa = Signature.getInstance("RIPEMD160/RSA-ISO9796-2",
          "IAIK");
      Signature iso9796whirlpoolrsa = Signature.getInstance("WHIRLPOOL/RSA-ISO9796-2",
          "IAIK");

      // init Signature objects with private keys
      iso9796sharsa.initSign(rsa_priv);
      iso9796sha256rsa.initSign(rsa_priv);
      iso9796sha384rsa.initSign(rsa_priv);
      iso9796sha512rsa.initSign(rsa_priv);
      iso9796ripemd128rsa.initSign(rsa_priv);
      iso9796ripemd160rsa.initSign(rsa_priv);
      iso9796whirlpoolrsa.initSign(rsa_priv);

      // create the signatures
      iso9796sharsa.update(data);
      iso9796sha256rsa.update(data);
      iso9796sha384rsa.update(data);
      iso9796sha512rsa.update(data);
      iso9796ripemd128rsa.update(data);
      iso9796ripemd160rsa.update(data);
      iso9796whirlpoolrsa.update(data);

      byte[] sharsasig = iso9796sharsa.sign();
      byte[] sha256rsasig = iso9796sha256rsa.sign();
      byte[] sha384rsasig = iso9796sha384rsa.sign();
      byte[] sha512rsasig = iso9796sha512rsa.sign();
      byte[] ripemd128rsasig = iso9796ripemd128rsa.sign();
      byte[] ripemd160rsasig = iso9796ripemd160rsa.sign();
      byte[] whirlpoolrsasig = iso9796whirlpoolrsa.sign();
      // verify the signatures

      iso9796sharsa.initVerify(rsa_pub);
      iso9796sharsa.update(data);
      System.out.println("verify SHA/RSA-ISO9796-2: "
          + (iso9796sharsa.verify(sharsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      AlgorithmParameters recoveredMessage = getParameters(iso9796sharsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      byte[] rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      recoveredMessage = null;
      rm = null;
      iso9796sha256rsa.initVerify(rsa_pub);
      iso9796sha256rsa.update(data);
      System.out.println("verify SHA256/RSA-ISO9796-2: "
          + (iso9796sha256rsa.verify(sha256rsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = getParameters(iso9796sha256rsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      recoveredMessage = null;
      rm = null;
      iso9796sha384rsa.initVerify(rsa_pub);
      iso9796sha384rsa.update(data);
      System.out.println("verify SHA384/RSA-ISO9796-2: "
          + (iso9796sha384rsa.verify(sha384rsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = getParameters(iso9796sha384rsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      recoveredMessage = null;
      rm = null;
      iso9796sha512rsa.initVerify(rsa_pub);
      iso9796sha512rsa.update(data);
      System.out.println("verify SHA512/RSA-ISO9796-2: "
          + (iso9796sha512rsa.verify(sha512rsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = getParameters(iso9796sha512rsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796ripemd128rsa.initVerify(rsa_pub);
      iso9796ripemd128rsa.update(data);
      System.out.println("verify RIPEMD128/RSA-ISO9796-2: "
          + (iso9796ripemd128rsa.verify(ripemd128rsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796ripemd128rsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796ripemd160rsa.initVerify(rsa_pub);
      iso9796ripemd160rsa.update(data);
      System.out.println("verify RIPEMD160/RSA-ISO9796-2: "
          + (iso9796ripemd160rsa.verify(ripemd160rsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796ripemd160rsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796whirlpoolrsa.initVerify(rsa_pub);
      iso9796whirlpoolrsa.update(data);
      System.out.println("verify WHIRLPOOL/RSA-ISO9796-2: "
          + (iso9796whirlpoolrsa.verify(whirlpoolrsasig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796whirlpoolrsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      /*
       * test general RSA-ISO9796 engine where parameters are set from outside
       */
      Signature iso9796Signature = Signature.getInstance("RSA-ISO9796-2", "IAIK");
      // init Signature object with private key
      iso9796Signature.initSign(rsa_priv_2048);
      // parameters
      // length of hash output value
      int hashLength = 64;
      // hash engine
      MessageDigest hashEngine = MessageDigest.getInstance("SHA-512", "IAIK");
      // create a ISO9796P2ParameterSpec
      ISO9796P2ParameterSpec paramSpec = new ISO9796P2ParameterSpec();
      paramSpec.setHashEngine(hashEngine, hashLength);

      // set parameters
      iso9796Signature.setParameter(paramSpec);

      // create the signature
      iso9796Signature.update(data);
      byte[] iso9796Sig = iso9796Signature.sign();

      iso9796Signature = Signature.getInstance("RSA-ISO9796-2", "IAIK");
      // verify the signatures
      iso9796Signature.initVerify(rsa_pub_2048);
      // set parameters 
      iso9796Signature.setParameter(paramSpec);
      iso9796Signature.update(data);
      System.out.println("verify RSA-ISO9796-2 siganture: "
          + (iso9796Signature.verify(iso9796Sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796Signature);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      /*
       * test ISO 9796 Signature engine in raw mode 
       */
      iso9796sharsa = Signature.getInstance("SHA/RSA-ISO9796-2", "IAIK");
      // init Signature object with private key
      iso9796sharsa.initSign(rsa_priv);

      // we have to supply message length and recoverable part of the message as parameter
      int modLen = ((RSAPrivateKey) rsa_priv).getModulus().bitLength();
      hashLength = 20;
      // we do not include hash id (implicit trailer)
      boolean explicit = false;
      // calculate capacity
      int capacity = ISO9796P2Signature.calculateCapacity(modLen, hashLength * 8,
          explicit);
      // create recoverable message part
      int len = Math.min(data.length, capacity / 8);
      byte[] m1 = new byte[len];
      System.arraycopy(data, 0, m1, 0, len);
      // create raw parameters
      paramSpec = new RawISO9796P2ParameterSpec("SHA-1", hashLength, m1, data.length);

      // set parameters     
      iso9796sharsa.setParameter(paramSpec);
      // we are in raw mode and have to calculate hash outside:
      hashEngine = MessageDigest.getInstance("SHA-1", "IAIK");
      byte[] rawHash = hashEngine.digest(data);
      iso9796sharsa.update(rawHash);
      // create the signature
      byte[] rawSig = iso9796sharsa.sign();

      // verify the signature
      iso9796sharsa.initVerify(rsa_pub);
      // set parameters     
      iso9796sharsa.setParameter(paramSpec);
      // update with calculated hash value
      iso9796sharsa.update(rawHash);
      System.out.println("verify raw SHA/RSA-ISO9796-2 signature: "
          + (iso9796sharsa.verify(rawSig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796sharsa);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Tests the functionality of RSA ISO-9796-2 signature schemes 2, 3.
   */
  public void rsaISO9796P2S2S3(int dataLength, boolean totalRecovery) {

    try {

      Random random = new Random();
      byte[] data = new byte[dataLength];
      random.nextBytes(data);

      Signature iso9796sharsamgf1 = Signature.getInstance("SHAandMGF1/RSA-ISO9796-2-2-3",
          "IAIK");
      Signature iso9796sha256rsamgf1 = Signature.getInstance(
          "SHA256andMGF1/RSA-ISO9796-2-2-3", "IAIK");
      Signature iso9796sha384rsamgf1 = Signature.getInstance(
          "SHA384andMGF1/RSA-ISO9796-2-2-3", "IAIK");
      Signature iso9796sha512rsamgf1 = Signature.getInstance(
          "SHA512andMGF1/RSA-ISO9796-2-2-3", "IAIK");
      Signature iso9796ripemd128rsamgf1 = Signature.getInstance(
          "RIPEMD128andMGF1/RSA-ISO9796-2-2-3", "IAIK");
      Signature iso9796ripemd160rsamgf1 = Signature.getInstance(
          "RIPEMD160andMGF1/RSA-ISO9796-2-2-3", "IAIK");
      Signature iso9796whirlpoolrsamgf1 = Signature.getInstance(
          "WHIRLPOOLandMGF1/RSA-ISO9796-2-2-3", "IAIK");

      // init Signature objects with private keys
      iso9796sharsamgf1.initSign(rsa_priv);
      iso9796sha256rsamgf1.initSign(rsa_priv);
      iso9796sha384rsamgf1.initSign(rsa_priv_2048);
      iso9796sha512rsamgf1.initSign(rsa_priv_2048);
      iso9796ripemd128rsamgf1.initSign(rsa_priv);
      iso9796ripemd160rsamgf1.initSign(rsa_priv);
      iso9796whirlpoolrsamgf1.initSign(rsa_priv_2048);

      // create the signatures
      iso9796sharsamgf1.update(data);
      iso9796sha256rsamgf1.update(data);
      iso9796sha384rsamgf1.update(data);
      iso9796sha512rsamgf1.update(data);
      iso9796ripemd128rsamgf1.update(data);
      iso9796ripemd160rsamgf1.update(data);
      iso9796whirlpoolrsamgf1.update(data);

      byte[] sharsamgf1sig = iso9796sharsamgf1.sign();
      byte[] sha256rsamgf1sig = iso9796sha256rsamgf1.sign();
      byte[] sha384rsamgf1sig = iso9796sha384rsamgf1.sign();
      byte[] sha512rsamgf1sig = iso9796sha512rsamgf1.sign();
      byte[] ripemd128rsamgf1sig = iso9796ripemd128rsamgf1.sign();
      byte[] ripemd160rsamgf1sig = iso9796ripemd160rsamgf1.sign();
      byte[] whirlpoolrsamgf1sig = iso9796whirlpoolrsamgf1.sign();

      // verify the signatures

      iso9796sharsamgf1.initVerify(rsa_pub);
      iso9796sharsamgf1.update(data);
      System.out.println("verify SHAandMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796sharsamgf1.verify(sharsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      AlgorithmParameters recoveredMessage = getParameters(iso9796sharsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      byte[] rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796sha256rsamgf1.initVerify(rsa_pub);
      iso9796sha256rsamgf1.update(data);
      System.out.println("verify SHA256andMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796sha256rsamgf1.verify(sha256rsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796sha256rsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796sha384rsamgf1.initVerify(rsa_pub_2048);
      iso9796sha384rsamgf1.update(data);
      System.out.println("verify SHA384andMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796sha384rsamgf1.verify(sha384rsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796sha384rsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796sha512rsamgf1.initVerify(rsa_pub_2048);
      iso9796sha512rsamgf1.update(data);
      System.out.println("verify SHA512andMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796sha512rsamgf1.verify(sha512rsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796sha512rsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796ripemd128rsamgf1.initVerify(rsa_pub);
      iso9796ripemd128rsamgf1.update(data);
      System.out.println("verify RIPEMD128andMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796ripemd128rsamgf1.verify(ripemd128rsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796ripemd128rsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796ripemd160rsamgf1.initVerify(rsa_pub);
      iso9796ripemd160rsamgf1.update(data);
      System.out.println("verify RIPEMD160andMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796ripemd160rsamgf1.verify(ripemd160rsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796ripemd160rsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      iso9796whirlpoolrsamgf1.initVerify(rsa_pub_2048);
      iso9796whirlpoolrsamgf1.update(data);
      System.out.println("verify WHIRLPOOLandMGF1/RSA-ISO9796-2-2-3: "
          + (iso9796whirlpoolrsamgf1.verify(whirlpoolrsamgf1sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796whirlpoolrsamgf1);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      /*
       * test general RSA-ISO9796 engine where parameters are set from outside
       */
      Signature iso9796Signature = Signature.getInstance("RSA-ISO9796-2-2-3", "IAIK");
      // init Signature object with private key
      iso9796Signature.initSign(rsa_priv_2048);
      // parameters
      // hash algorithm
      AlgorithmID hashID = (AlgorithmID) AlgorithmID.sha512.clone();
      // mask generation function ID
      AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
      mgfID.setParameter(hashID.toASN1Object());
      // salt length
      int saltLength = 64;
      // length of hash output value
      int hashLength = 64;
      // create a ISO9796P2S2S3ParameterSpec
      ISO9796P2S2S3ParameterSpec paramSpec = new ISO9796P2S2S3ParameterSpec();
      paramSpec.setSaltLength(saltLength);
      // optionally set hash and mgf engines
      MessageDigest hashEngine = hashID.getMessageDigestInstance("IAIK");
      paramSpec.setHashEngine(hashEngine, hashLength);
      MaskGenerationAlgorithm mgfEngine = mgfID
          .getMaskGenerationAlgorithmInstance("IAIK");
      MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(hashID);
      mgf1Spec.setHashEngine(hashEngine);
      mgfEngine.setParameters(mgf1Spec);
      paramSpec.setMGFEngine(mgfEngine);
      // set parameters  
      iso9796Signature.setParameter(paramSpec);

      // create the signature
      iso9796Signature.update(data);
      byte[] iso9796Sig = iso9796Signature.sign();

      iso9796Signature = Signature.getInstance("RSA-ISO9796-2-2-3", "IAIK");
      // verify the signatures
      iso9796Signature.initVerify(rsa_pub_2048);
      // set parameters 
      iso9796Signature.setParameter(paramSpec);
      iso9796Signature.update(data);
      System.out.println("verify RSA-ISO9796-2-2-3 siganture: "
          + (iso9796Signature.verify(iso9796Sig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796Signature);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

      /*
       * test ISO 9796 Signature engine in raw mode 
       */
      iso9796sharsamgf1 = Signature.getInstance("SHAandMGF1/RSA-ISO9796-2-2-3", "IAIK");
      // init Signature object with private key
      iso9796sharsamgf1.initSign(rsa_priv);

      // we have to supply message length and recoverable part of the message as parameter
      int modLen = ((RSAPrivateKey) rsa_priv).getModulus().bitLength();
      hashLength = 20;
      saltLength = 20;
      // we do not include hash id (implicit trailer)
      boolean explicit = false;
      // calculate capacity
      int capacity = ISO9796P2S2S3Signature.calculateCapacity(modLen, hashLength * 8,
          saltLength * 8, explicit);
      // create recoverable message part
      int len = Math.min(data.length, capacity / 8);
      byte[] m1 = new byte[len];
      System.arraycopy(data, 0, m1, 0, len);
      // create raw parameters
      paramSpec = new RawISO9796P2S2S3ParameterSpec("SHA-1", hashLength, m1, data.length);

      // set parameters     
      iso9796sharsamgf1.setParameter(paramSpec);
      // we are in raw mode and have to calculate hash outside:
      // for signature scheme 2,3 the hash has to be calculated on the
      // non-recoverable part only!
      len = data.length - m1.length;
      byte[] m2 = new byte[len];
      System.arraycopy(data, m1.length, m2, 0, len);
      hashEngine = MessageDigest.getInstance("SHA-1", "IAIK");
      byte[] rawHash = hashEngine.digest(m2);
      iso9796sharsamgf1.update(rawHash);
      // create the signature
      byte[] rawSig = iso9796sharsamgf1.sign();

      // verify the signature
      iso9796sharsamgf1.initVerify(rsa_pub);
      // set parameters      
      iso9796sharsamgf1.setParameter(paramSpec);
      // update with calculated hash value
      iso9796sharsamgf1.update(rawHash);
      System.out.println("verify raw SHAandMGF1/RSA-ISO9796-2-2-3 signature: "
          + (iso9796sharsamgf1.verify(rawSig) ? "OK!" : "NOT OK!"));
      // get recovered message
      recoveredMessage = null;
      rm = null;
      recoveredMessage = getParameters(iso9796Signature);
      if (recoveredMessage == null) {
        throw new Exception("Recovered message must not be null!");
      }
      rm = recoveredMessage.getEncoded();
      if (totalRecovery) {
        if ((rm == null) || (CryptoUtils.equalsBlock(rm, data) == false)) {
          throw new Exception(
              "Recovered message must be equal to original data for total recovery!");
        }
      }

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Tests the functionality of the DSA signature algorithm.
   */
  public void dsa() {

    try {
      // 1024 bytes random data to sign
      Random random = new Random();
      byte[] data = new byte[1024];
      random.nextBytes(data);

      Signature dsa = Signature.getInstance("SHA1withDSA", "IAIK");
      // init Signature object with private key
      dsa.initSign(dsa_priv);
      // create the signature
      dsa.update(data);
      byte[] dsasig = dsa.sign();

      // verify the signature
      dsa.initVerify(dsa_pub);
      dsa.update(data);
      System.out.println("verify SHA1withDSA: "
          + (dsa.verify(dsasig) ? "OK!" : "NOT OK!"));

      // test raw signature 
      MessageDigest hashEngine = MessageDigest.getInstance("SHA-1", "IAIK");
      byte[] rawHash = hashEngine.digest(data);

      Signature rawDsaSignatureEngine = Signature.getInstance("RawDSA", "IAIK");

      // init Signature object with private key
      rawDsaSignatureEngine.initSign(dsa_priv);

      // create the signature
      rawDsaSignatureEngine.update(rawHash);
      byte[] rawDsaSig = rawDsaSignatureEngine.sign();

      // verify the signatures
      rawDsaSignatureEngine.initVerify(dsa_pub);
      rawDsaSignatureEngine.update(rawHash);
      System.out.println("verify raw DSA: "
          + (rawDsaSignatureEngine.verify(rawDsaSig) ? "OK!" : "NOT OK!"));

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException();
    }
  }

  /**
   * Tests the functionality of DSA and RSA based signature algorithms.
   */
  public void start() {

    System.out.println("Testing DSA signature algorithm...");
    dsa();
    System.out.println("Testing RSA PKCS#1v1.5 based signature schemes...");
    rsaPKCS1v15();
    System.out.println("Testing RSA PSS signature schemes...");
    rsaPss();
    System.out.println("Testing RSA PSS parameter parsing.");
    rsaPssParameterParse();
    System.out.println("Testing RSA PSS SaltLength parameters.");
    rsaPssSaltParameters();
    System.out.println("Testing RSA ISO-9796-2 signature scheme...");
    // total recovery
    rsaISO9796P2S1(40, true);
    // partial recovery 
    rsaISO9796P2S1(320, false);
    System.out.println("Testing RSA ISO-9796-2-2-3 signature schemes...");
    // total recovery
    rsaISO9796P2S2S3(40, true);
    // partial recovery 
    rsaISO9796P2S2S3(320, false);

  }

  /**
   * Gets the parametes from a Signature engine.
   * This method uses <code>Signature.getParameter(String param)</code>
   * to get the parameters because method <code>Signature.getParameters()</code>
   * is not available for JDK versions < 1.4.
   * 
   * @param signature the Signature engine from which to get the parametes
   * 
   * @return the algorithm parameters
   */
  private static AlgorithmParameters getParameters(Signature signature) {
    return Util.getSignatureParameters(signature);
  }

  /**
   * Performs a test for the implemented signature algorithms.
   */
  public static void main(String arg[]) {

    DemoUtil.initDemos();
    try {
      (new TestSignature()).start();
    } catch (Exception ex) {
      // ignore
    }
    iaik.utils.Util.waitKey();
  }
}
