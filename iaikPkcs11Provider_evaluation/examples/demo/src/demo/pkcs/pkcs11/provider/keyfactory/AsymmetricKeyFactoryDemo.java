// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2015 Stiftung Secure Information and
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

package demo.pkcs.pkcs11.provider.keyfactory;

//class and interface imports
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.keyfactories.PKCS11KeySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

/**
 * This class shows a short demonstration of how to use this provider's implementation of a key
 * factory for key pairs.
 */
public class AsymmetricKeyFactoryDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The new key-pair.
   */
  protected KeyPair keyPair_;

  /**
   * The new key spec of the public key.
   */
  protected KeySpec softwarePublicKeySpec_;

  /**
   * The new key spec of the private key.
   */
  protected KeySpec softwarePrivateKeySpec_;

  /**
   * The new PKCS#11 public key.
   */
  protected PublicKey pkcs11PublicKey_;

  /**
   * The new PKCS#11 private key.
   */
  protected PrivateKey pkcs11PrivateKey_;

  /**
   * The key spec of the public key gained back from the PKCS#11 key.
   */
  protected KeySpec pkcs11PublicKeySpec_;

  /**
   * The key spec of the private key gained back from the PKCS#11 key.
   */
  protected KeySpec pkcs11PrivateKeySpec_;

  /**
   * The encoded key spec of the public key gained back from the PKCS#11 key.
   */
  protected X509EncodedKeySpec pkcs11PublicKeyEncodedSpec_;

  /**
   * The encoded key spec of the private key gained back from the PKCS#11 key.
   */
  protected PKCS8EncodedKeySpec pkcs11PrivateKeyEncodedSpec_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public AsymmetricKeyFactoryDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException,
      ClassNotFoundException {
    AsymmetricKeyFactoryDemo demo = new AsymmetricKeyFactoryDemo();

    String algorithm = "RSA";
    int keyLength = 1024;
    Class publicKeySpecClass = RSAPublicKeySpec.class;
    Class privateKeySpecClass = RSAPrivateCrtKeySpec.class;
    String softwareProviderName = "IAIK";
    if (args.length > 4) {
      algorithm = args[0];
      keyLength = Integer.parseInt(args[1]);
      publicKeySpecClass = Class.forName(args[2]);
      privateKeySpecClass = Class.forName(args[3]);
      softwareProviderName = args[4];
    }

    // if algorithm is not supported, this demo would not work
    KeyPairGenerator.getInstance(algorithm, demo.pkcs11Provider_.getName());

    demo.getKeyPair(algorithm, keyLength, softwareProviderName);
    demo.printSoftwareKeyPair();
    demo.translateKeyPairToSpecs(algorithm, softwareProviderName, publicKeySpecClass,
        privateKeySpecClass);
    demo.translateSpecsToPkcs11KeyPair(algorithm);
    demo.printPkcs11KeyPair();
    demo.translatePkcs11KeyPairToSpecs(algorithm, publicKeySpecClass, privateKeySpecClass);
    demo.translatePkcs11KeyPairToEncodedSpecs(algorithm);
    demo.getPkcs11KeyPairEncoded();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a key-pair in software. It stores the key-pair in the member variable
   * <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void getKeyPair(String algorithm, int keyLength, String softwareProviderName)
      throws GeneralSecurityException, IOException {

    System.out.print("Generating a key-pair in software...");

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
        softwareProviderName);

    SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", "IAIK");
    keyPairGenerator.initialize(keyLength, random);

    keyPair_ = keyPairGenerator.generateKeyPair();

    System.out.println(" finished");

  }

  /**
   * Translate the software keys into key specs using a factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translateKeyPairToSpecs(String algorithm, String softwareProviderName,
      Class publicKeySpecClass, Class privateKeySpecClass)
      throws GeneralSecurityException {
    System.out.print("Translating the key-pair into key specs...");

    KeyFactory softwareKeyFactory = KeyFactory.getInstance(algorithm,
        softwareProviderName);

    softwarePublicKeySpec_ = softwareKeyFactory.getKeySpec(keyPair_.getPublic(),
        publicKeySpecClass);

    softwarePrivateKeySpec_ = softwareKeyFactory.getKeySpec(keyPair_.getPrivate(),
        privateKeySpecClass);

    System.out.println(" finished");
  }

  /**
   * Translate the software keys into PKCS#11 keys using a key factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translateSpecsToPkcs11KeyPair(String algorithm)
      throws GeneralSecurityException {
    KeyFactory pkcs11KeyFactory = KeyFactory.getInstance(algorithm,
        pkcs11Provider_.getName());

    System.out.print("Translating public key...");

    iaik.pkcs.pkcs11.objects.PublicKey pkcs11PublicKeyTemplate = new iaik.pkcs.pkcs11.objects.PublicKey();
    pkcs11PublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    pkcs11PublicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    PKCS11KeySpec pkcs11PublicKeySpec = (PKCS11KeySpec) new PKCS11KeySpec(
        softwarePublicKeySpec_, pkcs11PublicKeyTemplate).setUseUserRole(false);

    pkcs11PublicKey_ = pkcs11KeyFactory.generatePublic(pkcs11PublicKeySpec);

    System.out.println(" finished");

    System.out.print("Translating private key...");

    iaik.pkcs.pkcs11.objects.PrivateKey pkcs11PrivateKeyTemplate = new iaik.pkcs.pkcs11.objects.PrivateKey();
    pkcs11PrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    pkcs11PrivateKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    // set key extractable to get key specs later
    // this is only for demo purposes - actually a private or secret key should never leave the
    // token!
    pkcs11PrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
    pkcs11PrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    pkcs11PrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);

    PKCS11KeySpec pkcs11PrivateKeySpec = (PKCS11KeySpec) new PKCS11KeySpec(
        softwarePrivateKeySpec_, pkcs11PrivateKeyTemplate).setUseUserRole(false);

    pkcs11PrivateKey_ = pkcs11KeyFactory.generatePrivate(pkcs11PrivateKeySpec);

    System.out.println(" finished");
  }

  /**
   * Translate back the PKCS#11 keys into key specs using a key factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translatePkcs11KeyPairToSpecs(String algorithm, Class publicKeySpecClass,
      Class privateKeySpecClass) throws GeneralSecurityException {
    KeyFactory pkcs11KeyFactory = KeyFactory.getInstance(algorithm,
        pkcs11Provider_.getName());

    System.out.print("Translating public key into spec...");

    pkcs11PublicKeySpec_ = pkcs11KeyFactory.getKeySpec(pkcs11PublicKey_,
        publicKeySpecClass);

    System.out.println(" finished");

    System.out.print("Translating private key into spec...");

    pkcs11PrivateKeySpec_ = pkcs11KeyFactory.getKeySpec(pkcs11PrivateKey_,
        privateKeySpecClass);

    System.out.println(" finished");
  }

  /**
   * This method prints the generated software key-pair (<code>keyPair_</code>).
   */
  public void printSoftwareKeyPair() {
    System.out
        .println("################################################################################");
    System.out.println("The generated software key-pair is:");
    if (keyPair_ == null) {
      System.out.println("null");
    } else {
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Public key:");
      System.out.println(keyPair_.getPublic());
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Private key:");
      System.out.println(keyPair_.getPrivate());
    }
    System.out
        .println("################################################################################");
  }

  /**
   * This method prints the generated pkcs#11 key-pair (<code>keyPair_</code>).
   */
  public void printPkcs11KeyPair() {
    System.out
        .println("################################################################################");
    System.out.println("The generated PKCS#11 key-pair is:");
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Public key:");
    System.out.println((pkcs11PublicKey_ != null) ? pkcs11PublicKey_.toString() : "null");
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Private key:");
    System.out.println((pkcs11PrivateKey_ != null) ? pkcs11PrivateKey_.toString()
        : "null");
    System.out
        .println("################################################################################");
  }

  /**
   * Translate back the PKCS#11 keys into encoded key specs using a key factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translatePkcs11KeyPairToEncodedSpecs(String algorithm)
      throws GeneralSecurityException {
    KeyFactory pkcs11KeyFactory = KeyFactory.getInstance(algorithm,
        pkcs11Provider_.getName());

    System.out.print("Translating public key into encoded spec...");

    pkcs11PublicKeyEncodedSpec_ = (X509EncodedKeySpec) pkcs11KeyFactory.getKeySpec(
        pkcs11PublicKey_, X509EncodedKeySpec.class);

    System.out.println(" finished");

    System.out.print("Translating private key into encoded spec...");

    pkcs11PrivateKeyEncodedSpec_ = (PKCS8EncodedKeySpec) pkcs11KeyFactory.getKeySpec(
        pkcs11PrivateKey_, PKCS8EncodedKeySpec.class);

    System.out.println(" finished");
  }

  /**
   * Get the encoding of the PKCS#11 keys.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void getPkcs11KeyPairEncoded() throws GeneralSecurityException {
    System.out.print("Getting X.509 encoded public key...");

    byte[] publicKeyEncoding = pkcs11PublicKey_.getEncoded();

    // same key factory of pkcs11 provider - must be equal
    if (Arrays.equals(publicKeyEncoding, pkcs11PublicKeyEncodedSpec_.getEncoded())) {
      System.out.println(" finished");
    } else {
      System.out.println(" ERROR");
      throw new IAIKPkcs11Exception(
          "keyfactory error - public key encodings do not match.");
    }

    System.out.print("Getting PKCS#8 encoded private key...");

    byte[] privateKeyEncoding = pkcs11PrivateKey_.getEncoded();

    if (Arrays.equals(privateKeyEncoding, pkcs11PrivateKeyEncodedSpec_.getEncoded())) {
      System.out.println(" finished");
    } else {
      System.out.println(" ERROR");
      throw new IAIKPkcs11Exception(
          "keyfactory error - private key encodings do not match.");
    }
  }

}
