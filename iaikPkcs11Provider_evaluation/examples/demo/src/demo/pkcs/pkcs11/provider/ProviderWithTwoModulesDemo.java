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

package demo.pkcs.pkcs11.provider;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.pkcs.pkcs11.provider.keyfactories.PKCS11KeySpec;
import iaik.security.provider.IAIK;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

import demo.pkcs.pkcs11.provider.utils.KeyFinder;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This demo shows how to use two instances of the IAIK PKCS#11 Provider in order to use two
 * different modules.
 * 
 */
public class ProviderWithTwoModulesDemo {

  /**
   * The PKCS#11 provider used to generate the key-pair.
   */
  protected IAIKPkcs11 keyPairGenerationProvider_;

  /**
   * The PKCS#11 provider used to store the key-pair.
   */
  protected IAIKPkcs11 keyPairStoreProvider_;

  /**
   * The new key-pair.
   */
  protected KeyPair keyPair_;

  /**
   * The new key spec of the public key.
   */
  protected KeySpec publicKeySpec_;

  /**
   * The new key spec of the private key.
   */
  protected KeySpec privateCrtKeySpec_;

  /**
   * The new PKCS#11 public key.
   */
  protected java.security.PublicKey publicKey_;

  /**
   * The new PKCS#11 private key.
   */
  protected java.security.PrivateKey privateKey_;

  public ProviderWithTwoModulesDemo() {
    URL propertyURL = IAIKPkcs11.class.getClassLoader().getResource(
        Constants.PROVIDER_PROPERTIES_NAME);
    Properties generationProperties;
    Properties storeProperties;
    try {
      if (propertyURL != null) {
        InputStream propertyInputStream = propertyURL.openStream();
        Properties instanceProperties = new Properties(); // fall back to defaults
        instanceProperties.load(propertyInputStream);
        propertyInputStream.close();
        // use default properties for demo, typically different modules would be used
        generationProperties = instanceProperties;
        storeProperties = instanceProperties;
      } else {
        throw new IAIKPkcs11Exception(
            "No properties file in classpath. Add to classpath or specify properties manually.");
      }
    } catch (IOException ioe) {
      throw new IAIKPkcs11Exception(ioe.getMessage());
    }
    keyPairGenerationProvider_ = new IAIKPkcs11(generationProperties);
    keyPairStoreProvider_ = new IAIKPkcs11(storeProperties);
    Security.addProvider(new IAIK());
    Security.addProvider(keyPairGenerationProvider_);
    Security.addProvider(keyPairStoreProvider_);

  }

  public static void main(String[] args) throws GeneralSecurityException, TokenException {
    ProviderWithTwoModulesDemo demo = new ProviderWithTwoModulesDemo();

    String algorithm = (args.length > 0) ? args[0] : "DSA";

    // generate key-pair
    demo.generateKeyPair(algorithm);
    // dump info about the key-pair to standard out
    demo.printGeneratedKeyPair();
    // translate the key-pair to JCE key specs
    demo.translateKeyPairToSpecs(algorithm);
    // translate the key specs of the key-pair to keys of the store provider and store the keys in a
    // token of the store provider
    demo.storeKeyPair(algorithm);
    // dump info about the stored key-pair to standard out
    demo.printStoredKeyPair();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a key-pair on the "generationProvider". It stores the key-pair in the
   * member variable <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception TokenException
   *              If anything with the token access fails.
   */
  public void generateKeyPair(String algorithm) throws GeneralSecurityException,
      TokenException {
    PrivateKey privateKeyTemplate = KeyTemplateDemo
        .getSignaturePrivateKeyTemplate(algorithm);
    // set the private key extractable and not sensitive to enable extraction of the private values
    privateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
    privateKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);
    PublicKey publicKeyTemplate = KeyTemplateDemo
        .getSignaturePublicKeyTemplate(algorithm);
    keyPair_ = KeyFinder.generateKeyPair(keyPairGenerationProvider_, algorithm,
        privateKeyTemplate, publicKeyTemplate);
  }

  /**
   * This method prints the generated key-pair (<code>keyPair_</code>).
   */
  public void printGeneratedKeyPair() {
    System.out
        .println("################################################################################");
    System.out.println("The generated key-pair is:");
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
   * Translate the keys into key specs using a factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the generation provider fails.
   */
  public void translateKeyPairToSpecs(String algorithm) throws GeneralSecurityException {
    System.out.print("Translating the key-pair into key specs...");

    KeyFactory pkcs11KeyFactory = KeyFactory.getInstance(algorithm,
        keyPairGenerationProvider_.getName());

    publicKeySpec_ = pkcs11KeyFactory.getKeySpec(keyPair_.getPublic(),
        X509EncodedKeySpec.class);

    privateCrtKeySpec_ = pkcs11KeyFactory.getKeySpec(keyPair_.getPrivate(),
        PKCS8EncodedKeySpec.class);

    System.out.println(" finished");
  }

  /**
   * This method store the generated key-pair (<code>keyPair_</code>) on the token of the second
   * PKCS#11 provider.
   * 
   * @exception GeneralSecurityException
   *              If anything with the store provider fails.
   */
  public void storeKeyPair(String algorithm) throws GeneralSecurityException {
    System.out.print("Storing generated key-pair using provider \"");
    System.out.print(keyPairStoreProvider_.getName());
    System.out.println("\":");

    System.out.println("Translating key-pair using a key factory");

    TokenManager tokenManager = keyPairStoreProvider_.getTokenManager();

    KeyFactory pkcs11KeyFactory = KeyFactory.getInstance(algorithm,
        keyPairStoreProvider_.getName());

    // only the algorithm specific values were extracted in the key specs - get pkcs#11 key
    // templates again
    PublicKey pkcs11PublicKeyTemplate = KeyTemplateDemo
        .getSignaturePublicKeyTemplate(algorithm);
    PrivateKey pkcs11PrivateKeyTemplate = KeyTemplateDemo
        .getSignaturePrivateKeyTemplate(algorithm);

    // generate a key pair on the 2nd token with the key values generated on the 1st token

    System.out.print("Translating public key...");
    PKCS11KeySpec pkcs11PublicKeySpec = (PKCS11KeySpec) new PKCS11KeySpec(publicKeySpec_,
        pkcs11PublicKeyTemplate).setUseUserRole(false).setTokenManager(tokenManager);
    publicKey_ = pkcs11KeyFactory.generatePublic(pkcs11PublicKeySpec);

    System.out.print("Translating private key...");
    PKCS11KeySpec pkcs11PrivateKeySpec = (PKCS11KeySpec) new PKCS11KeySpec(
        privateCrtKeySpec_, pkcs11PrivateKeyTemplate).setUseAnonymousRole(false)
        .setTokenManager(tokenManager);
    privateKey_ = pkcs11KeyFactory.generatePrivate(pkcs11PrivateKeySpec);

    System.out.println(" finished");
  }

  /**
   * This method prints the generated key-pair (<code>keyPair_</code>).
   */
  public void printStoredKeyPair() {
    System.out
        .println("################################################################################");
    System.out.println("The stored key-pair is:");
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Public key:");
    System.out.println(publicKey_);
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Private key:");
    System.out.println(privateKey_);
    System.out
        .println("################################################################################");
  }

}
